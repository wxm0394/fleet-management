package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"flag"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
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

func main() {
	addr := flag.String("listen", ":8080", "listen addr")
	dbPath := flag.String("db", "fleet.db", "sqlite path")
	flag.Parse()

	db, err := store.NewSQLiteStore(*dbPath)
	if err != nil {
		log.Fatalf("sqlite err: %v", err)
	}

	cp := &ControlPlane{store: db}
	bootToken, err := db.CreateBootstrapToken(24 * time.Hour)
	if err != nil {
		log.Fatalf("token err: %v", err)
	}

	log.Println("====================================================")
	log.Printf("Control Plane listening on %s", *addr)
	log.Printf("Bootstrap Token: %s", bootToken)
	log.Printf("Run Agent:\ngo run ./cmd/agent -server http://127.0.0.1%s -bootstrap %s", *addr, bootToken)
	log.Println("====================================================")

	subFS, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatalf("fs sub err: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(subFS)))
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

	log.Fatal(http.ListenAndServe(*addr, mux))
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
	cp.sessions.Delete(nodeID)
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

// DNS Providers CRUD

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

// Certificates CRUD

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
		// Use acme issuer to generate cert/key in memory
		issuer := acme.NewDefaultIssuer()
		result, err := issuer.IssueCertificate(req.Domain, req.ACMEEnv, "")
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

// Proxy Routes CRUD

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
		// Create route
		routeID, err := cp.store.CreateProxyRoute(req.NodeID, req.Domain, req.Upstream, &req.CertID)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		// Sync to Agent via yamux tunnel
		// Find the node session and POST /rpc/caddy/sync
		if s, ok := cp.sessions.Load(req.NodeID); ok {
			session := s.(*yamux.Session)
			// Build sync payload from stored cert
			cert, _ := cp.store.GetCertificate(req.CertID)
			// Get routes for this node
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
			// Get cert pair
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
			// Use session to open HTTP connection to agent
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
