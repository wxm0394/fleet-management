package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"text/template"
	"time"

	"fleet-panel/internal/acme"
	"fleet-panel/internal/store"
	"fleet-panel/pkg/protocol"
	"fleet-panel/pkg/tunnel"

	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
)

//go:embed web/*
var webFS embed.FS

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type ControlPlane struct {
	store    *store.Store
	sessions sync.Map
}

func generateRandomPassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func adminAuthMiddleware(adminPassword string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Public agent endpoints and install script do not require admin auth
		if strings.HasPrefix(r.URL.Path, "/api/v1/agent/") || r.URL.Path == "/install.sh" {
			next.ServeHTTP(w, r)
			return
		}

		// Allow unauthenticated access ONLY to static web root UI assets (index.html, js, css, etc.)
		if !strings.HasPrefix(r.URL.Path, "/api/v1/") {
			next.ServeHTTP(w, r)
			return
		}

		// Verify API requests via HTTP Basic Auth or Authorization: Bearer <adminPassword> or X-Admin-Key
		user, pass, ok := r.BasicAuth()
		if ok && (subtle.ConstantTimeCompare([]byte(pass), []byte(adminPassword)) == 1 || subtle.ConstantTimeCompare([]byte(user), []byte(adminPassword)) == 1) {
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			if subtle.ConstantTimeCompare([]byte(token), []byte(adminPassword)) == 1 {
				next.ServeHTTP(w, r)
				return
			}
		}

		adminKeyHeader := r.Header.Get("X-Admin-Key")
		if adminKeyHeader != "" && subtle.ConstantTimeCompare([]byte(adminKeyHeader), []byte(adminPassword)) == 1 {
			next.ServeHTTP(w, r)
			return
		}

		w.Header().Set("WWW-Authenticate", `Basic realm="Fleet Management Admin"`)
		http.Error(w, "Unauthorized: Admin Authentication Required", http.StatusUnauthorized)
	})
}

func main() {
	addr := flag.String("listen", ":8080", "listen addr")
	dbPath := flag.String("db", "fleet.db", "sqlite path")
	adminPass := flag.String("admin-pass", os.Getenv("FLEET_ADMIN_PASS"), "admin authentication password")
	flag.Parse()

	if *adminPass == "" {
		*adminPass = generateRandomPassword(16)
	}

	db, err := store.NewSQLiteStore(*dbPath)
	if err != nil {
		log.Fatalf("sqlite err: %v", err)
	}

	cp := &ControlPlane{store: db}
	bootToken, err := db.CreateBootstrapToken(24 * time.Hour)
	if err != nil {
		log.Fatalf("token err: %v", err)
	}

	go startFailoverInspector(cp)

	log.Println("====================================================")
	log.Printf("Control Plane listening on %s", *addr)
	log.Printf("Admin Password: %s", *adminPass)
	log.Printf("Bootstrap Token: %s", bootToken)
	log.Printf("Run Agent:\ngo run ./cmd/agent -server http://127.0.0.1%s -bootstrap %s", *addr, bootToken)
	log.Println("====================================================")

	subFS, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatalf("fs sub err: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(subFS)))
	mux.HandleFunc("GET /install.sh", cp.handleInstallScript)
	mux.HandleFunc("POST /api/v1/agent/register", cp.handleRegister)
	mux.HandleFunc("GET /api/v1/agent/tunnel", cp.handleTunnel)
	mux.HandleFunc("POST /api/v1/tokens", cp.handleCreateToken)
	mux.HandleFunc("GET /api/v1/nodes", cp.handleListNodes)
	mux.HandleFunc("GET /api/v1/nodes/{id}/metrics", cp.handleNodeMetrics)
	mux.HandleFunc("POST /api/v1/nodes/{id}/exec", cp.handleNodeExec)
	mux.HandleFunc("GET /api/v1/nodes/{id}/pty", cp.handleNodePTY)
	mux.HandleFunc("/api/v1/dns-providers", cp.handleDNSProviders)
	mux.HandleFunc("/api/v1/certificates", cp.handleCertificates)
	mux.HandleFunc("/api/v1/routes", cp.handleProxyRoutes)
	mux.HandleFunc("PUT /api/v1/nodes/{id}/tags", cp.handleNodeTags)
	mux.HandleFunc("GET /api/v1/stacks", cp.handleListStacks)
	mux.HandleFunc("POST /api/v1/stacks", cp.handleCreateStack)
	mux.HandleFunc("POST /api/v1/nodes/{id}/keepalive", cp.handleNodeKeepalive)

	handler := adminAuthMiddleware(*adminPass, mux)
	log.Fatal(http.ListenAndServe(*addr, handler))
}

func (cp *ControlPlane) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Missing token parameter", http.StatusBadRequest)
		return
	}

	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	serverURL := fmt.Sprintf("%s://%s", scheme, r.Host)

	scriptTmpl := `#!/bin/sh
set -e

echo "[+] Installing Fleet Agent..."

ARCH=$(uname -m)

case "$ARCH" in
    x86_64|amd64)
        AGENT_ARCH="amd64"
        ;;
    aarch64|arm64)
        AGENT_ARCH="arm64"
        ;;
    *)
        echo "[-] Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

DOWNLOAD_URL="https://github.com/wxm0394/fleet-management/releases/latest/download/fleet-agent-linux-${AGENT_ARCH}"

echo "[+] Downloading fleet-agent (${AGENT_ARCH}) from ${DOWNLOAD_URL}..."
curl -fsSL "$DOWNLOAD_URL" -o /usr/local/bin/fleet-agent
chmod +x /usr/local/bin/fleet-agent

mkdir -p /etc/systemd/system

cat <<EOF > /etc/systemd/system/fleet-agent.service
[Unit]
Description=Fleet Management Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/fleet-agent -server {{.ServerURL}} -bootstrap {{.Token}}
Restart=always
RestartSec=5
WorkDir=/var/lib/fleet-agent

[Install]
WantedBy=multi-user.target
EOF

mkdir -p /var/lib/fleet-agent

echo "[+] Enabling and starting fleet-agent service..."
systemctl daemon-reload
systemctl enable --now fleet-agent

echo "[+] Fleet Agent installation complete!"
`

	tmpl, err := template.New("install").Parse(scriptTmpl)
	if err != nil {
		http.Error(w, "Failed to generate script", http.StatusInternalServerError)
		return
	}

	data := map[string]string{
		"ServerURL": serverURL,
		"Token":     token,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		http.Error(w, "Failed to generate script", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="install.sh"`)
	_, _ = w.Write(buf.Bytes())
}

func (cp *ControlPlane) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req protocol.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	id, sec, err := cp.store.ExchangeBootstrapToken(
		req.BootstrapToken, req.Hostname, req.OS, req.Arch, r.RemoteAddr,
	)
	if err != nil {
		http.Error(w, err.Error(), 401)
		return
	}
	log.Printf("[+] Node registered (UUIDv7): %s (%s)", id, req.Hostname)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(protocol.RegisterResponse{
		NodeID:     id,
		NodeSecret: sec,
	})
}

func (cp *ControlPlane) handleTunnel(w http.ResponseWriter, r *http.Request) {
	nodeID := r.Header.Get("X-Node-ID")
	secret := r.Header.Get("X-Node-Secret")
	if !cp.store.AuthenticateNode(nodeID, secret, r.RemoteAddr) {
		http.Error(w, "unauthorized", 401)
		return
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	cfg := yamux.DefaultConfig()
	cfg.KeepAliveInterval = 20 * time.Second
	session, err := yamux.Client(tunnel.NewWSConn(ws), cfg)
	if err != nil {
		_ = ws.Close()
		return
	}

	cp.sessions.Store(nodeID, session)
	log.Printf("[+] Tunnel connected (reversed): %s", nodeID)

	<-session.CloseChan()
	cp.sessions.CompareAndDelete(nodeID, session)
	log.Printf("[-] Tunnel disconnected: %s", nodeID)
}

func (cp *ControlPlane) newAgentClient(nodeID string) (*http.Client, error) {
	val, ok := cp.sessions.Load(nodeID)
	if !ok {
		return nil, io.EOF
	}
	session := val.(*yamux.Session)
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return session.Open()
			},
		},
	}, nil
}

func (cp *ControlPlane) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	tok, err := cp.store.CreateBootstrapToken(time.Hour)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"bootstrap_token": tok})
}

func (cp *ControlPlane) handleListNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := cp.store.ListNodes()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	for i := range nodes {
		if s, ok := cp.sessions.Load(nodes[i].ID); ok && !s.(*yamux.Session).IsClosed() {
			nodes[i].Online = true
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(nodes)
}

func (cp *ControlPlane) handleNodeMetrics(w http.ResponseWriter, r *http.Request) {
	c, err := cp.newAgentClient(r.PathValue("id"))
	if err != nil {
		http.Error(w, "node offline", 503)
		return
	}
	resp, err := c.Get("http://agent/rpc/metrics")
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.Copy(w, resp.Body)
}

func (cp *ControlPlane) handleNodeExec(w http.ResponseWriter, r *http.Request) {
	c, err := cp.newAgentClient(r.PathValue("id"))
	if err != nil {
		http.Error(w, "node offline", 503)
		return
	}
	body, _ := io.ReadAll(r.Body)
	resp, err := c.Post("http://agent/rpc/exec", "application/json", bytes.NewReader(body))
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.Copy(w, resp.Body)
}

func (cp *ControlPlane) handleNodePTY(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("id")
	val, ok := cp.sessions.Load(nodeID)
	if !ok {
		http.Error(w, "node offline", 503)
		return
	}
	session := val.(*yamux.Session)

	targetURL, _ := url.Parse("http://agent/rpc/pty")
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Transport = &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return session.Open()
		},
	}
	proxy.ServeHTTP(w, r)
}

func (cp *ControlPlane) handleDNSProviders(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		providers, err := cp.store.ListDNSProviders()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(providers)
	case http.MethodPost:
		var req struct {
			Name            string `json:"name"`
			ProviderType    string `json:"provider_type"`
			CredentialsJSON string `json:"credentials_json"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		id, err := cp.store.CreateDNSProvider(req.Name, req.ProviderType, req.CredentialsJSON)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"id": id})
	}
}

func (cp *ControlPlane) handleCertificates(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		certs, err := cp.store.ListCertificates()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(certs)
	case http.MethodPost:
		var req struct {
			Domain        string `json:"domain"`
			DNSProviderID string `json:"dns_provider_id"`
			ACMEEnv       string `json:"acme_env"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		dnsProvider, err := cp.store.GetDNSProvider(req.DNSProviderID)
		if err != nil {
			http.Error(w, "DNS provider not found", 404)
			return
		}
		issuer := acme.NewDefaultIssuer()
		result, err := issuer.IssueCertificate(req.Domain, dnsProvider.ProviderType, dnsProvider.CredentialsJSON)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		id, err := cp.store.CreateCertificate(req.Domain, req.DNSProviderID, req.ACMEEnv, result.CertPEM, result.KeyPEM)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"id": id})
	}
}

func (cp *ControlPlane) handleProxyRoutes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		routes, err := cp.store.ListProxyRoutes()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(routes)
	case http.MethodPost:
		var req struct {
			NodeID   string `json:"node_id"`
			Domain   string `json:"domain"`
			Upstream string `json:"upstream"`
			CertID   string `json:"cert_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		routeID, err := cp.store.CreateProxyRoute(req.NodeID, req.Domain, req.Upstream, &req.CertID)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if s, ok := cp.sessions.Load(req.NodeID); ok {
			session := s.(*yamux.Session)
			cert, _ := cp.store.GetCertificate(req.CertID)
			routes, _ := cp.store.ListProxyRoutes()
			var routeRules []protocol.RouteRule
			for _, r := range routes {
				if r.NodeID == req.NodeID {
					routeRules = append(routeRules, protocol.RouteRule{
						ID:       r.ID,
						Domain:   r.Domain,
						Upstream: r.Upstream,
					})
				}
			}
			var certs []protocol.CertPair
			if cert != nil {
				certs = []protocol.CertPair{
					{CertPEM: cert.CertPEM, KeyPEM: cert.KeyPEM},
				}
			}
			payload := protocol.CaddySyncPayload{
				Routes:       routeRules,
				Certificates: certs,
				DryRun:       false,
			}
			payloadJSON, _ := json.Marshal(payload)
			client := &http.Client{
				Timeout: 5 * time.Second,
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
						return session.Open()
					},
				},
			}
			resp, err := client.Post("http://agent/rpc/caddy/sync", "application/json", bytes.NewReader(payloadJSON))
			if err != nil {
				log.Printf("[!] Failed to sync caddy to agent %s: %v", req.NodeID, err)
			} else {
				resp.Body.Close()
				log.Printf("[+] Caddy sync sent to agent %s", req.NodeID)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"id": routeID})
	}
}

func (cp *ControlPlane) handleNodeTags(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("id")
	var req struct {
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	tagsStr, _ := json.Marshal(req.Tags)
	err := cp.store.UpdateNodeTags(nodeID, string(tagsStr))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	nodes, _ := cp.store.ListNodes()
	for i := range nodes {
		if s, ok := cp.sessions.Load(nodes[i].ID); ok && !s.(*yamux.Session).IsClosed() {
			nodes[i].Online = true
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(nodes)
}

func (cp *ControlPlane) handleListStacks(w http.ResponseWriter, r *http.Request) {
	stacks, err := cp.store.ListComposeStacks()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stacks)
}

func (cp *ControlPlane) handleCreateStack(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		TargetTag   string `json:"target_tag"`
		YAMLContent string `json:"yaml_content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	id, err := cp.store.CreateComposeStack(req.Name, req.TargetTag, req.YAMLContent)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"id": id})
}

func (cp *ControlPlane) handleNodeKeepalive(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("id")
	val, ok := cp.sessions.Load(nodeID)
	if !ok {
		http.Error(w, "node offline", 503)
		return
	}
	session := val.(*yamux.Session)
	targetURL, _ := url.Parse("http://agent/rpc/keepalive/config")
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Transport = &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return session.Open()
		},
	}
	proxy.ServeHTTP(w, r)
}

func startFailoverInspector(cp *ControlPlane) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		cp.handleFailoverCheck()
	}
}

func (cp *ControlPlane) handleFailoverCheck() {
	nodes, err := cp.store.ListNodes()
	if err != nil {
		log.Printf("[!] Failover check error: %v", err)
		return
	}
	for _, node := range nodes {
		if s, ok := cp.sessions.Load(node.ID); ok && !s.(*yamux.Session).IsClosed() {
			continue
		}
		log.Printf("[!] Node %s detected offline in background inspector", node.ID)
	}
}
