package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"fleet-panel/pkg/protocol"
	"fleet-panel/pkg/tunnel"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
)

type AgentIdentity struct {
	NodeID     string `json:"node_id"`
	NodeSecret string `json:"node_secret"`
}

func main() {
	srv := flag.String("server", "http://127.0.0.1:8080", "server url")
	boot := flag.String("bootstrap", "", "bootstrap token")
	state := flag.String("state", "agent_identity.json", "state file")
	requireTLS := flag.Bool("require-tls", false, "require TLS (wss://) for connection")
	flag.Parse()

	if strings.HasPrefix(*srv, "http://") {
		if *requireTLS {
			log.Fatalf("[FATAL] Plain HTTP/WS connections rejected due to -require-tls flag. Provide an https:// server URL.")
		}
		log.Printf("[WARNING] Agent is connecting via unencrypted HTTP/WS (%s). Pass https:// server URL in production for WSS encryption!", *srv)
	}

	id, err := loadOrRegister(*srv, *boot, *state)
	if err != nil {
		log.Fatalf("Auth failed: %v", err)
	}
	log.Printf("[+] Authenticated NodeID: %s", id.NodeID)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /rpc/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(collectMetrics(id.NodeID))
	})
	mux.HandleFunc("POST /rpc/exec", handleExec)
	mux.HandleFunc("GET /rpc/pty", handlePTY)
	mux.HandleFunc("POST /rpc/caddy/sync", handleCaddySync)
	mux.HandleFunc("POST /rpc/compose/deploy", handleComposeDeploy)
	mux.HandleFunc("POST /rpc/keepalive/config", handleKeepaliveConfig)

	wsURL := strings.Replace(*srv, "http://", "ws://", 1)
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	wsURL += "/api/v1/agent/tunnel"

	for {
		if err := runTunnel(wsURL, id, mux); err != nil {
			log.Printf("[!] Tunnel lost: %v, retry in 5s...", err)
			time.Sleep(5 * time.Second)
		}
	}
}

func runTunnel(wsURL string, id *AgentIdentity, h http.Handler) error {
	hdr := http.Header{
		"X-Node-ID":     []string{id.NodeID},
		"X-Node-Secret": []string{id.NodeSecret},
	}
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, hdr)
	if err != nil {
		return err
	}
	cfg := yamux.DefaultConfig()
	cfg.KeepAliveInterval = 20 * time.Second
	session, err := yamux.Server(tunnel.NewWSConn(ws), cfg)
	if err != nil {
		_ = ws.Close()
		return err
	}
	log.Printf("[+] Outbound tunnel established to %s", wsURL)
	return http.Serve(session, h)
}

func loadOrRegister(srv, boot, state string) (*AgentIdentity, error) {
	if b, err := os.ReadFile(state); err == nil {
		var id AgentIdentity
		if json.Unmarshal(b, &id) == nil && id.NodeID != "" {
			return &id, nil
		}
	}
	if boot == "" {
		return nil, errors.New("missing -bootstrap token")
	}
	hn, _ := os.Hostname()
	body, _ := json.Marshal(protocol.RegisterRequest{
		BootstrapToken: boot,
		Hostname:       hn,
		OS:             runtime.GOOS,
		Arch:           runtime.GOARCH,
	})
	resp, err := http.Post(srv+"/api/v1/agent/register", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		msg, _ := io.ReadAll(resp.Body)
		return nil, errors.New(string(msg))
	}
	var reg protocol.RegisterResponse
	if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
		return nil, err
	}
	id := &AgentIdentity{NodeID: reg.NodeID, NodeSecret: reg.NodeSecret}
	saved, _ := json.MarshalIndent(id, "", "  ")
	_ = os.WriteFile(state, saved, 0600)
	return id, nil
}

func collectMetrics(nodeID string) protocol.NodeMetrics {
	hn, _ := os.Hostname()
	pct, _ := cpu.Percent(0, false)
	var c float64
	if len(pct) > 0 {
		c = pct[0]
	}
	vm, _ := mem.VirtualMemory()
	du, _ := disk.Usage("/")
	up, _ := host.Uptime()

	var mUsed, mTotal, dUsed, dTotal uint64
	var mPct float64
	if vm != nil {
		mUsed = vm.Used / 1024 / 1024
		mTotal = vm.Total / 1024 / 1024
		mPct = vm.UsedPercent
	}
	if du != nil {
		dUsed = du.Used / 1024 / 1024 / 1024
		dTotal = du.Total / 1024 / 1024 / 1024
	}
	return protocol.NodeMetrics{
		NodeID:      nodeID,
		Hostname:    hn,
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		CPUPercent:  c,
		MemUsedMB:   mUsed,
		MemTotalMB:  mTotal,
		MemPercent:  mPct,
		DiskUsedGB:  dUsed,
		DiskTotalGB: dTotal,
		UptimeSec:   up,
		Timestamp:   time.Now().Unix(),
	}
}

func handleExec(w http.ResponseWriter, r *http.Request) {
	var req protocol.ExecRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	t := time.Duration(req.Timeout) * time.Second
	if t <= 0 {
		t = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), t)
	defer cancel()

	out, err := exec.CommandContext(ctx, "sh", "-c", req.Command).CombinedOutput()
	res := protocol.ExecResponse{ExitCode: 0, Output: string(out)}
	if err != nil {
		res.Error = err.Error()
		res.ExitCode = 1
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

var ptyUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func handlePTY(w http.ResponseWriter, r *http.Request) {
	ws, err := ptyUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()

	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}

	cmd := exec.Command(shell)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")

	ptmx, err := pty.Start(cmd)
	if err != nil {
		return
	}
	defer func() {
		_ = ptmx.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	// PTY -> WebSocket
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := ptmx.Read(buf)
			if err != nil {
				_ = ws.Close()
				return
			}
			if err := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
				return
			}
		}
	}()

	// WebSocket -> PTY
	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			break
		}
		if _, err := ptmx.Write(msg); err != nil {
			break
		}
	}
}

func handleCaddySync(w http.ResponseWriter, r *http.Request) {
	var payload protocol.CaddySyncPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	caddyConfig := buildCaddyConfig(payload)
	configJSON, err := json.Marshal(caddyConfig)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if payload.DryRun {
		_ = json.NewEncoder(w).Encode(protocol.CaddySyncResponse{
			Success: true,
			Message: "Dry-run mode, Caddy configuration generated successfully",
			Config:  caddyConfig,
		})
		return
	}

	// POST to Caddy Admin API
	caddyAdminURL := "http://127.0.0.1:2019/load"
	req, err := http.NewRequest("POST", caddyAdminURL, bytes.NewBuffer(configJSON))
	if err != nil {
		_ = json.NewEncoder(w).Encode(protocol.CaddySyncResponse{
			Success: false,
			Message: "Failed to create Caddy Admin API request: " + err.Error(),
			Config:  caddyConfig,
		})
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		_ = json.NewEncoder(w).Encode(protocol.CaddySyncResponse{
			Success: false,
			Message: "Caddy Admin API unreachable (127.0.0.1:2019): " + err.Error() + ". Check if Caddy is running on host.",
			Config:  caddyConfig,
		})
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		_ = json.NewEncoder(w).Encode(protocol.CaddySyncResponse{
			Success: false,
			Message: "Caddy Admin API error: " + string(respBody),
			Config:  caddyConfig,
		})
		return
	}

	_ = json.NewEncoder(w).Encode(protocol.CaddySyncResponse{
		Success: true,
		Message: "Caddy configuration updated successfully in memory",
		Config:  caddyConfig,
	})
}

func buildCaddyConfig(payload protocol.CaddySyncPayload) map[string]interface{} {
	// Build Caddy JSON v2 configuration with zero-disk cert loading via tls.certificates.load_pem
	var tlsCerts []map[string]interface{}
	for _, c := range payload.Certificates {
		if c.CertPEM != "" && c.KeyPEM != "" {
			tlsCerts = append(tlsCerts, map[string]interface{}{
				"certificate": c.CertPEM,
				"key":         c.KeyPEM,
			})
		}
	}

	var routes []map[string]interface{}
	for _, r := range payload.Routes {
		routes = append(routes, map[string]interface{}{
			"match": []map[string]interface{}{
				{
					"host": []string{r.Domain},
				},
			},
			"handle": []map[string]interface{}{
				{
					"handler": "reverse_proxy",
					"upstreams": []map[string]interface{}{
						{
							"dial": r.Upstream,
						},
					},
				},
			},
		})
	}

	apps := map[string]interface{}{}
	if len(routes) > 0 {
		apps["http"] = map[string]interface{}{
			"servers": map[string]interface{}{
				"srv0": map[string]interface{}{
					"listen": []string{":443", ":80"},
					"routes": routes,
				},
			},
		}
	}

	if len(tlsCerts) > 0 {
		apps["tls"] = map[string]interface{}{
			"certificates": map[string]interface{}{
				"load_pem": tlsCerts,
			},
		}
	}

	return map[string]interface{}{
		"apps": apps,
	}
}

func isValidStackName(name string) bool {
	// Only allow alphanumeric, underscore, and hyphen characters
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, name)
	return matched
}

func handleComposeDeploy(w http.ResponseWriter, r *http.Request) {
	var req protocol.ComposeDeployRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	if !isValidStackName(req.Name) {
		http.Error(w, "Invalid stack name: only alphanumeric characters, underscore, and hyphen are allowed", 400)
		return
	}

	dir := "stacks/" + req.Name
	_ = os.MkdirAll(dir, 0755)
	composePath := dir + "/docker-compose.yml"
	if err := os.WriteFile(composePath, []byte(req.YAMLContent), 0644); err != nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(protocol.ComposeDeployResponse{
			Success: false,
			Error:   "Failed to save docker-compose.yml: " + err.Error(),
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", composePath, "up", "-d")
	out, err := cmd.CombinedOutput()
	if err != nil {
		cmdLegacy := exec.CommandContext(ctx, "docker-compose", "-f", composePath, "up", "-d")
		outLegacy, errLegacy := cmdLegacy.CombinedOutput()
		if errLegacy != nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(protocol.ComposeDeployResponse{
				Success: false,
				Output:  string(out) + "\n" + string(outLegacy),
				Error:   errLegacy.Error(),
			})
			return
		}
		out = outLegacy
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(protocol.ComposeDeployResponse{
		Success: true,
		Output:  string(out),
	})
}

var (
	keepaliveMu     sync.Mutex
	keepaliveCancel context.CancelFunc
)

func handleKeepaliveConfig(w http.ResponseWriter, r *http.Request) {
	var req protocol.KeepaliveConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	keepaliveMu.Lock()
	if keepaliveCancel != nil {
		keepaliveCancel()
		keepaliveCancel = nil
	}
	if req.Enabled && req.TargetCPUPercent > 0 {
		ctx, cancel := context.WithCancel(context.Background())
		keepaliveCancel = cancel
		go startKeepaliveLoop(ctx, req.TargetCPUPercent)
	}
	keepaliveMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(protocol.KeepaliveConfigResponse{
		Success: true,
		Message: "Keepalive configuration updated",
	})
}

func startKeepaliveLoop(ctx context.Context, targetPercent float64) {
	if targetPercent > 95 {
		targetPercent = 95
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pct, err := cpu.Percent(0, false)
			if err == nil && len(pct) > 0 {
				currentCPU := pct[0]
				if currentCPU < targetPercent {
					busyDuration := time.Duration(float64(time.Millisecond*100) * ((targetPercent - currentCPU) / 100.0))
					start := time.Now()
					for time.Since(start) < busyDuration {
						_ = 1 + 1
					}
				}
			}
		}
	}
}
