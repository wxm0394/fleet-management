package protocol

type RegisterRequest struct {
	BootstrapToken string `json:"bootstrap_token"`
	Hostname       string `json:"hostname"`
	OS             string `json:"os"`
	Arch           string `json:"arch"`
}

type RegisterResponse struct {
	NodeID     string `json:"node_id"`
	NodeSecret string `json:"node_secret"`
}

type NodeMetrics struct {
	NodeID      string  `json:"node_id"`
	Hostname    string  `json:"hostname"`
	OS          string  `json:"os"`
	Arch        string  `json:"arch"`
	CPUPercent  float64 `json:"cpu_percent"`
	MemUsedMB   uint64  `json:"mem_used_mb"`
	MemTotalMB  uint64  `json:"mem_total_mb"`
	MemPercent  float64 `json:"mem_percent"`
	DiskUsedGB  uint64  `json:"disk_used_gb"`
	DiskTotalGB uint64  `json:"disk_total_gb"`
	UptimeSec   uint64  `json:"uptime_sec"`
	Timestamp   int64   `json:"timestamp"`
}

type ExecRequest struct {
	Command string `json:"command"`
	Timeout int    `json:"timeout_sec"`
}

type ExecResponse struct {
	ExitCode int    `json:"exit_code"`
	Output   string `json:"output"`
	Error    string `json:"error,omitempty"`
}

type RouteRule struct {
	ID       string `json:"id"`
	Domain   string `json:"domain"`
	Upstream string `json:"upstream"`
}

type CertPair struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

type CaddySyncPayload struct {
	Routes       []RouteRule `json:"routes"`
	Certificates []CertPair  `json:"certificates"`
	DryRun       bool        `json:"dry_run,omitempty"`
}

type CaddySyncResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Config  any    `json:"config,omitempty"`
}

type ComposeDeployRequest struct {
	Name        string `json:"name"`
	YAMLContent string `json:"yaml_content"`
}

type ComposeDeployResponse struct {
	Success bool   `json:"success"`
	Output  string `json:"output"`
	Error   string `json:"error,omitempty"`
}

type KeepaliveConfigRequest struct {
	Enabled          bool    `json:"enabled"`
	TargetCPUPercent float64 `json:"target_cpu_percent"`
}

type KeepaliveConfigResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}
