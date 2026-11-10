package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
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

var configuredServerURL string

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type ControlPlane struct {
	store         *store.Store
	issuer        acme.Issuer
	renewingCerts sync.Map
	sessions      sync.Map
	authAttempts  sync.Map // key: client IP (string), value: *authAttempt
}

type authAttempt struct {
	mu          sync.Mutex
	failCount   int
	lastFail    time.Time
	lockedUntil time.Time
}

func generateRandomPassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		for i := range b {
			b[i] = charset[i%len(charset)]
		}
	} else {
		for i := range b {
			b[i] = charset[b[i]%byte(len(charset))]
		}
	}
	return string(b)
}

func (cp *ControlPlane) extractClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			firstIP := strings.TrimSpace(parts[0])
			if net.ParseIP(firstIP) != nil {
				return firstIP
			}
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			ipStr := strings.TrimSpace(xri)
			if net.ParseIP(ipStr) != nil {
				return ipStr
			}
		}
	}
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || clientIP == "" {
		return r.RemoteAddr
	}
	return clientIP
}

func adminAuthMiddleware(cp *ControlPlane, adminPassword string, trustProxy bool, next http.Handler) http.Handler {
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

		clientIP := cp.extractClientIP(r, trustProxy)

		// Check IP-based rate limiting / lockout
		if locked, retryAfter := cp.checkAuthLockout(clientIP); locked {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		// Verify API requests via HTTP Basic Auth or Authorization: Bearer <adminPassword> or X-Admin-Key
		authenticated := false
		user, pass, ok := r.BasicAuth()
		if ok && (subtle.ConstantTimeCompare([]byte(pass), []byte(adminPassword)) == 1 || subtle.ConstantTimeCompare([]byte(user), []byte(adminPassword)) == 1) {
			authenticated = true
		}

		if !authenticated {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token := strings.TrimPrefix(authHeader, "Bearer ")
				if subtle.ConstantTimeCompare([]byte(token), []byte(adminPassword)) == 1 {
					authenticated = true
				}
			}
		}

		if !authenticated {
			adminKeyHeader := r.Header.Get("X-Admin-Key")
			if adminKeyHeader != "" && subtle.ConstantTimeCompare([]byte(adminKeyHeader), []byte(adminPassword)) == 1 {
				authenticated = true
			}
		}

		if authenticated {
			cp.resetAuthAttempt(clientIP)
			next.ServeHTTP(w, r)
			return
		}

		cp.recordAuthFailure(clientIP)
		w.Header().Set("WWW-Authenticate", `Basic realm="Fleet Management Admin"`)
		http.Error(w, "Unauthorized: Admin Authentication Required", http.StatusUnauthorized)
	})
}

func (cp *ControlPlane) checkAuthLockout(ip string) (bool, int) {
	val, ok := cp.authAttempts.Load(ip)
	if !ok {
		return false, 0
	}
	attempt := val.(*authAttempt)
	attempt.mu.Lock()
	defer attempt.mu.Unlock()

	now := time.Now()
	if !attempt.lockedUntil.IsZero() && now.Before(attempt.lockedUntil) {
		retryAfter := int(time.Until(attempt.lockedUntil).Seconds()) + 1
		if retryAfter < 1 {
			retryAfter = 1
		}
		return true, retryAfter
	}
	// Lockout expired, reset attempt count
	attempt.failCount = 0
	attempt.lockedUntil = time.Time{}
	return false, 0
}

func (cp *ControlPlane) recordAuthFailure(ip string) {
	now := time.Now()
	val, _ := cp.authAttempts.LoadOrStore(ip, &authAttempt{})
	attempt := val.(*authAttempt)

	attempt.mu.Lock()
	defer attempt.mu.Unlock()

	// If 15 minutes have passed since last failure, reset fail count
	if !attempt.lastFail.IsZero() && now.Sub(attempt.lastFail) > 15*time.Minute {
		attempt.failCount = 0
	}

	attempt.failCount++
	attempt.lastFail = now

	if attempt.failCount >= 5 {
		attempt.lockedUntil = now.Add(15 * time.Minute)
	}
}

func (cp *ControlPlane) resetAuthAttempt(ip string) {
	cp.authAttempts.Delete(ip)
}

func startAuthAttemptCleaner(cp *ControlPlane) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		cp.authAttempts.Range(func(key, value any) bool {
			attempt := value.(*authAttempt)
			attempt.mu.Lock()
			lastFail := attempt.lastFail
			attempt.mu.Unlock()

			if !lastFail.IsZero() && now.Sub(lastFail) > 1*time.Hour {
				cp.authAttempts.Delete(key)
			}
			return true
		})
	}
}

func main() {
	addr := flag.String("listen", ":8080", "listen addr")
	dbPath := flag.String("db", "fleet.db", "sqlite path")
	tlsCert := flag.String("tls-cert", os.Getenv("FLEET_TLS_CERT"), "TLS certificate file path")
	tlsKey := flag.String("tls-key", os.Getenv("FLEET_TLS_KEY"), "TLS key file path")
	trustProxyFlag := flag.Bool("trust-proxy-headers", false, "trust X-Forwarded-For and X-Real-IP headers from reverse proxy (default false)")
	agentAMD64 := flag.String("agent-amd64", "/opt/fleet-management/fleet-agent-linux-amd64", "Linux amd64 Agent binary path")
	agentARM64 := flag.String("agent-arm64", "/opt/fleet-management/fleet-agent-linux-arm64", "Linux arm64 Agent binary path")
	flag.Parse()

	configuredServerURL = strings.TrimRight(strings.TrimSpace(os.Getenv("FLEET_SERVER_URL")), "/")
	trustProxy := *trustProxyFlag
	if envVal := os.Getenv("FLEET_TRUST_PROXY_HEADERS"); envVal != "" {
		if b, err := strconv.ParseBool(envVal); err == nil {
			trustProxy = b
		}
	}

	// Admin password: only from environment variable, no command-line flag
	adminPass := os.Getenv("FLEET_ADMIN_PASS")
	if adminPass == "" {
		adminPass = generateRandomPassword(16)
		log.Println("[INFO] No FLEET_ADMIN_PASS set, auto-generated random admin password. Keep it safe!")
	}

	db, err := store.NewSQLiteStore(*dbPath)
	if err != nil {
		log.Fatalf("sqlite err: %v", err)
	}

	cp := &ControlPlane{
		store:  db,
		issuer: acme.NewDefaultIssuer(),
	}
	bootToken, err := db.CreateBootstrapToken(24 * time.Hour)
	if err != nil {
		log.Fatalf("token err: %v", err)
	}

	go startFailoverInspector(cp)
	go startCertRenewalInspector(cp)
	go startAuthAttemptCleaner(cp)

	log.Println("====================================================")
	log.Printf("Admin Password: %s", adminPass)
	log.Printf("Bootstrap Token: %s", bootToken)
	log.Printf("Control Plane listening on %s", *addr)

	// TLS configuration
	tlsCertPath := *tlsCert
	tlsKeyPath := *tlsKey

	if tlsCertPath != "" && tlsKeyPath != "" {
		// Both cert and key provided - use TLS
		log.Println("Starting Control Plane with TLS (HTTPS)")
		log.Println("====================================================")
	} else if tlsCertPath != "" || tlsKeyPath != "" {
		// Only one provided - warn and fall back to HTTP
		log.Println("[WARNING] Only one of -tls-cert or -tls-key provided. Falling back to HTTP.")
		log.Println("[WARNING] For production use, configure both -tls-cert and -tls-key,")
		log.Println("[WARNING] or use Caddy/Nginx as TLS termination proxy in front of this server.")
		log.Println("[WARNING] If using Caddy/Nginx, bind this server to 127.0.0.1 only!")
		log.Println("====================================================")
	} else {
		// No TLS configured - print prominent warning
		log.Println("====================================================")
		log.Println("[WARNING] Running Control Plane with raw HTTP (no TLS)!")
		log.Println("[WARNING] This is fine for development, but NOT for production!")
		log.Println("[WARNING] Generate a self-signed cert or use a real cert:")
		log.Printf("[WARNING]   -tls-cert /path/to/cert.pem -tls-key /path/to/key.pem")
		log.Println("[WARNING] Or use Caddy/Nginx as TLS termination proxy in front of this server!")
		log.Println("[WARNING] If using Caddy/Nginx, bind this server to 127.0.0.1 only!")
		log.Println("====================================================")
	}

	subFS, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatalf("fs sub err: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(subFS)))
	mux.HandleFunc("GET /fleet-agent-linux-amd64", func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, *agentAMD64) })
	mux.HandleFunc("GET /fleet-agent-linux-arm64", func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, *agentARM64) })
	mux.HandleFunc("GET /install.sh", cp.handleInstallScript)
	mux.HandleFunc("GET /api/v1/server-info", cp.handleServerInfo)
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

	handler := adminAuthMiddleware(cp, adminPass, trustProxy, mux)

	// Start HTTP server in goroutine
	go func() {
		if tlsCertPath != "" && tlsKeyPath != "" {
			log.Fatal(http.ListenAndServeTLS(*addr, tlsCertPath, tlsKeyPath, handler))
		}
		log.Fatal(http.ListenAndServe(*addr, handler))
	}()

	// Wait for interrupt signal
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	<-stop
	log.Println("[INFO] Shutting down Control Plane...")
}

func (cp *ControlPlane) handleServerInfo(w http.ResponseWriter, r *http.Request) {
	serverURL := configuredServerURL
	if serverURL == "" {
		scheme := "http"
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			scheme = "https"
		}
		serverURL = fmt.Sprintf("%s://%s", scheme, r.Host)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"server_url": serverURL})
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
	serverURL := configuredServerURL
	if serverURL == "" {
		serverURL = fmt.Sprintf("%s://%s", scheme, r.Host)
	}

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

DOWNLOAD_URL="{{.ServerURL}}/fleet-agent-linux-${AGENT_ARCH}"

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

func (cp *ControlPlane) syncCaddyToNode(nodeID string) error {
	val, ok := cp.sessions.Load(nodeID)
	if !ok {
		return fmt.Errorf("node %s not connected", nodeID)
	}
	session := val.(*yamux.Session)

	routes, err := cp.store.ListProxyRoutes()
	if err != nil {
		return fmt.Errorf("failed to list proxy routes: %w", err)
	}

	var routeRules []protocol.RouteRule
	var certs []protocol.CertPair
	certMap := make(map[string]bool)

	for _, r := range routes {
		if r.NodeID == nodeID {
			routeRules = append(routeRules, protocol.RouteRule{
				ID:       r.ID,
				Domain:   r.Domain,
				Upstream: r.Upstream,
			})
			if r.CertID != "" && !certMap[r.CertID] {
				certMap[r.CertID] = true
				cert, _ := cp.store.GetCertificate(r.CertID)
				if cert != nil {
					certs = append(certs, protocol.CertPair{
						CertPEM: cert.CertPEM,
						KeyPEM:  cert.KeyPEM,
					})
				}
			}
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
		return fmt.Errorf("failed to sync caddy to agent %s: %w", nodeID, err)
	}
	resp.Body.Close()
	log.Printf("[+] Caddy sync sent to agent %s", nodeID)
	return nil
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
		result, err := cp.issuer.IssueCertificate(req.Domain, dnsProvider.ProviderType, dnsProvider.CredentialsJSON, req.ACMEEnv)
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
		if err := cp.syncCaddyToNode(req.NodeID); err != nil {
			log.Printf("[!] Failed to sync caddy to agent %s: %v", req.NodeID, err)
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

func startCertRenewalInspector(cp *ControlPlane) {
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		// Get certificates expiring within 20 days
		expiringCerts, err := cp.store.ListExpiringCertificates(20 * 24 * time.Hour)
		if err != nil {
			log.Printf("[!] Failed to list expiring certificates: %v", err)
			continue
		}

		for _, cert := range expiringCerts {
			// Skip if already renewing this domain
			if _, renewing := cp.renewingCerts.Load(cert.Domain); renewing {
				continue
			}

			// Mark as renewing
			cp.renewingCerts.Store(cert.Domain, true)

			// Renew the certificate in background
			go func(certRecord store.CertificateRecord) {
				defer cp.renewingCerts.Delete(certRecord.Domain)

				dnsProvider, err := cp.store.GetDNSProvider(certRecord.DNSProviderID)
				if err != nil {
					log.Printf("[!] Failed to get DNS provider %s for domain %s: %v", certRecord.DNSProviderID, certRecord.Domain, err)
					return
				}

				result, err := cp.issuer.IssueCertificate(certRecord.Domain, dnsProvider.ProviderType, dnsProvider.CredentialsJSON, certRecord.ACMEEnv)
				if err != nil {
					log.Printf("[!] Failed to auto-renew certificate for domain %s: %v", certRecord.Domain, err)
					return
				}

				if err := cp.store.UpdateCertificate(certRecord.ID, certRecord.Domain, certRecord.DNSProviderID, certRecord.ACMEEnv, result.CertPEM, result.KeyPEM); err != nil {
					log.Printf("[!] Failed to update renewed certificate for domain %s: %v", certRecord.Domain, err)
					return
				}

				routes, err := cp.store.ListProxyRoutes()
				if err != nil {
					log.Printf("[!] Failed to list routes during cert renewal for domain %s: %v", certRecord.Domain, err)
					return
				}

				syncedNodes := make(map[string]bool)
				for _, route := range routes {
					if route.CertID == certRecord.ID && !syncedNodes[route.NodeID] {
						syncedNodes[route.NodeID] = true
						if err := cp.syncCaddyToNode(route.NodeID); err != nil {
							log.Printf("[!] Failed to sync renewed cert to node %s: %v", route.NodeID, err)
						}
					}
				}
				log.Printf("[+] Certificate auto-renewed successfully for domain %s", certRecord.Domain)
			}(cert)
		}
	}
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
