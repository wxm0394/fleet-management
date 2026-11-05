package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

type NodeRecord struct {
	ID        string `json:"id"`
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	RemoteIP  string `json:"remote_ip"`
	Tags      string `json:"tags"`
	CreatedAt int64  `json:"created_at"`
	LastSeen  int64  `json:"last_seen"`
	Online    bool   `json:"online"`
}

type DNSProviderRecord struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	ProviderType    string `json:"provider_type"`
	CredentialsJSON string `json:"credentials_json"`
	CreatedAt       int64  `json:"created_at"`
}

type CertificateRecord struct {
	ID            string `json:"id"`
	Domain        string `json:"domain"`
	DNSProviderID string `json:"dns_provider_id"`
	ACMEEnv       string `json:"acme_env"`
	CertPEM       string `json:"cert_pem"`
	KeyPEM        string `json:"key_pem"`
	ExpiresAt     int64  `json:"expires_at"`
	CreatedAt     int64  `json:"created_at"`
}

type ProxyRouteRecord struct {
	ID         string `json:"id"`
	NodeID     string `json:"node_id"`
	Domain     string `json:"domain"`
	Upstream   string `json:"upstream"`
	CertID     string `json:"cert_id"`
	SyncStatus string `json:"sync_status"`
	UpdatedAt  int64  `json:"updated_at"`
}

type ComposeStackRecord struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	TargetTag   string `json:"target_tag"`
	YAMLContent string `json:"yaml_content"`
	Status      string `json:"status"`
	UpdatedAt   int64  `json:"updated_at"`
}

func NewSQLiteStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	// 开启 WAL 模式提升并发写入性能
	pragmas := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=NORMAL;",
		"PRAGMA busy_timeout=5000;",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			return nil, err
		}
	}

	schema := `
	CREATE TABLE IF NOT EXISTS bootstrap_tokens (
		token TEXT PRIMARY KEY NOT NULL,
		expires_at INTEGER NOT NULL,
		used INTEGER DEFAULT 0
	) WITHOUT ROWID;

	CREATE TABLE IF NOT EXISTS nodes (
		id TEXT PRIMARY KEY NOT NULL,
		secret_hash TEXT NOT NULL,
		hostname TEXT NOT NULL,
		os TEXT NOT NULL,
		arch TEXT NOT NULL,
		remote_ip TEXT NOT NULL,
		tags TEXT DEFAULT '{}',
		created_at INTEGER NOT NULL,
		last_seen INTEGER NOT NULL
	) WITHOUT ROWID;

	CREATE TABLE IF NOT EXISTS dns_providers (
		id TEXT PRIMARY KEY NOT NULL,
		name TEXT NOT NULL,
		provider_type TEXT NOT NULL,
		credentials_json TEXT NOT NULL,
		created_at INTEGER NOT NULL
	) WITHOUT ROWID;

	CREATE TABLE IF NOT EXISTS certificates (
		id TEXT PRIMARY KEY NOT NULL,
		domain TEXT NOT NULL,
		dns_provider_id TEXT NOT NULL,
		acme_env TEXT NOT NULL,
		cert_pem TEXT,
		key_pem TEXT,
		expires_at INTEGER NOT NULL,
		created_at INTEGER NOT NULL,
		FOREIGN KEY (dns_provider_id) REFERENCES dns_providers(id)
	) WITHOUT ROWID;

	CREATE TABLE IF NOT EXISTS proxy_routes (
		id TEXT PRIMARY KEY NOT NULL,
		node_id TEXT NOT NULL,
		domain TEXT NOT NULL,
		upstream TEXT NOT NULL,
		cert_id TEXT,
		sync_status TEXT DEFAULT 'pending',
		updated_at INTEGER NOT NULL,
		FOREIGN KEY (cert_id) REFERENCES certificates(id),
		FOREIGN KEY (node_id) REFERENCES nodes(id)
	) WITHOUT ROWID;

	CREATE TABLE IF NOT EXISTS compose_stacks (
		id TEXT PRIMARY KEY NOT NULL,
		name TEXT NOT NULL,
		target_tag TEXT,
		yaml_content TEXT,
		status TEXT DEFAULT 'pending',
		updated_at INTEGER NOT NULL
	) WITHOUT ROWID;
	`
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

// CreateBootstrapToken 生成一次性节点注册 Token（基于 UUIDv7）
func (s *Store) CreateBootstrapToken(ttl time.Duration) (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	token := "boot_" + id.String()
	expires := time.Now().Add(ttl).Unix()
	_, err = s.db.Exec(`INSERT INTO bootstrap_tokens (token, expires_at, used) VALUES (?, ?, 0)`, token, expires)
	return token, err
}

// ExchangeBootstrapToken 验证一次性 Token 并签发持久化 UUIDv7 节点身份
func (s *Store) ExchangeBootstrapToken(token, hostname, osName, arch, remoteIP string) (string, string, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback()

	var expiresAt int64
	var used int
	err = tx.QueryRow(`SELECT expires_at, used FROM bootstrap_tokens WHERE token = ?`, token).Scan(&expiresAt, &used)
	if err != nil {
		return "", "", errors.New("invalid bootstrap token")
	}
	if used == 1 || time.Now().Unix() > expiresAt {
		return "", "", errors.New("bootstrap token expired or already used")
	}

	if _, err := tx.Exec(`UPDATE bootstrap_tokens SET used = 1 WHERE token = ?`, token); err != nil {
		return "", "", err
	}

	nodeUUID, err := uuid.NewV7()
	if err != nil {
		return "", "", err
	}
	nodeID := nodeUUID.String()

	secretBytes := make([]byte, 24)
	_, _ = rand.Read(secretBytes)
	nodeSecret := hex.EncodeToString(secretBytes)

	hashBytes := sha256.Sum256([]byte(nodeSecret))
	secretHash := hex.EncodeToString(hashBytes[:])

	now := time.Now().Unix()
	_, err = tx.Exec(
		`INSERT INTO nodes (id, secret_hash, hostname, os, arch, remote_ip, created_at, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		nodeID, secretHash, hostname, osName, arch, remoteIP, now, now,
	)
	if err != nil {
		return "", "", err
	}

	return nodeID, nodeSecret, tx.Commit()
}

func (s *Store) AuthenticateNode(nodeID, secret, remoteIP string) bool {
	var storedHash string
	err := s.db.QueryRow(`SELECT secret_hash FROM nodes WHERE id = ?`, nodeID).Scan(&storedHash)
	if err != nil {
		return false
	}
	hashBytes := sha256.Sum256([]byte(secret))
	computedHash := hex.EncodeToString(hashBytes[:])

	if subtle.ConstantTimeCompare([]byte(storedHash), []byte(computedHash)) != 1 {
		return false
	}
	_, _ = s.db.Exec(`UPDATE nodes SET last_seen = ?, remote_ip = ? WHERE id = ?`, time.Now().Unix(), remoteIP, nodeID)
	return true
}

func (s *Store) ListNodes() ([]NodeRecord, error) {
	rows, err := s.db.Query(`SELECT id, hostname, os, arch, remote_ip, tags, created_at, last_seen FROM nodes ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []NodeRecord
	for rows.Next() {
		var n NodeRecord
		if err := rows.Scan(&n.ID, &n.Hostname, &n.OS, &n.Arch, &n.RemoteIP, &n.Tags, &n.CreatedAt, &n.LastSeen); err != nil {
			return nil, err
		}
		list = append(list, n)
	}
	return list, nil
}

// DNS Provider CRUD

func (s *Store) CreateDNSProvider(name, providerType, credentialsJSON string) (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	now := time.Now().Unix()
	_, err = s.db.Exec(
		`INSERT INTO dns_providers (id, name, provider_type, credentials_json, created_at) VALUES (?, ?, ?, ?, ?)`,
		id.String(), name, providerType, credentialsJSON, now,
	)
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

func (s *Store) GetDNSProvider(id string) (*DNSProviderRecord, error) {
	row := s.db.QueryRow(`SELECT id, name, provider_type, credentials_json, created_at FROM dns_providers WHERE id = ?`, id)
	var r DNSProviderRecord
	err := row.Scan(&r.ID, &r.Name, &r.ProviderType, &r.CredentialsJSON, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) ListDNSProviders() ([]DNSProviderRecord, error) {
	rows, err := s.db.Query(`SELECT id, name, provider_type, credentials_json, created_at FROM dns_providers ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []DNSProviderRecord
	for rows.Next() {
		var r DNSProviderRecord
		if err := rows.Scan(&r.ID, &r.Name, &r.ProviderType, &r.CredentialsJSON, &r.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, nil
}

func (s *Store) UpdateDNSProvider(id, name, providerType, credentialsJSON string) error {
	_, err := s.db.Exec(
		`UPDATE dns_providers SET name = ?, provider_type = ?, credentials_json = ? WHERE id = ?`,
		name, providerType, credentialsJSON, id,
	)
	return err
}

func (s *Store) DeleteDNSProvider(id string) error {
	_, err := s.db.Exec(`DELETE FROM dns_providers WHERE id = ?`, id)
	return err
}

// Certificate CRUD

func (s *Store) CreateCertificate(domain, dnsProviderID, acmeEnv, certPEM, keyPEM string) (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", err
	}

	// Parse x509 certificate to get real expiration time
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	expiresAt := cert.NotAfter.Unix()
	now := time.Now().Unix()
	_, err = s.db.Exec(
		`INSERT INTO certificates (id, domain, dns_provider_id, acme_env, cert_pem, key_pem, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id.String(), domain, dnsProviderID, acmeEnv, certPEM, keyPEM, expiresAt, now,
	)
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

func (s *Store) GetCertificate(id string) (*CertificateRecord, error) {
	row := s.db.QueryRow(`SELECT id, domain, dns_provider_id, acme_env, cert_pem, key_pem, expires_at, created_at FROM certificates WHERE id = ?`, id)
	var r CertificateRecord
	err := row.Scan(&r.ID, &r.Domain, &r.DNSProviderID, &r.ACMEEnv, &r.CertPEM, &r.KeyPEM, &r.ExpiresAt, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) ListCertificates() ([]CertificateRecord, error) {
	rows, err := s.db.Query(`SELECT id, domain, dns_provider_id, acme_env, cert_pem, key_pem, expires_at, created_at FROM certificates ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []CertificateRecord
	for rows.Next() {
		var r CertificateRecord
		if err := rows.Scan(&r.ID, &r.Domain, &r.DNSProviderID, &r.ACMEEnv, &r.CertPEM, &r.KeyPEM, &r.ExpiresAt, &r.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, nil
}

// ListExpiringCertificates returns certificates expiring within the given threshold
func (s *Store) ListExpiringCertificates(threshold time.Duration) ([]CertificateRecord, error) {
	cutoff := time.Now().Add(threshold).Unix()
	rows, err := s.db.Query(
		`SELECT id, domain, dns_provider_id, acme_env, cert_pem, key_pem, expires_at, created_at FROM certificates WHERE expires_at < ? ORDER BY expires_at ASC`, cutoff,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []CertificateRecord
	for rows.Next() {
		var r CertificateRecord
		if err := rows.Scan(&r.ID, &r.Domain, &r.DNSProviderID, &r.ACMEEnv, &r.CertPEM, &r.KeyPEM, &r.ExpiresAt, &r.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, nil
}

func (s *Store) UpdateCertificate(id, domain, dnsProviderID, acmeEnv, certPEM, keyPEM string) error {
	// Parse x509 certificate to get real expiration time
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	expiresAt := cert.NotAfter.Unix()

	_, err = s.db.Exec(
		`UPDATE certificates SET domain = ?, dns_provider_id = ?, acme_env = ?, cert_pem = ?, key_pem = ?, expires_at = ? WHERE id = ?`,
		domain, dnsProviderID, acmeEnv, certPEM, keyPEM, expiresAt, id,
	)
	return err
}

func (s *Store) DeleteCertificate(id string) error {
	_, err := s.db.Exec(`DELETE FROM certificates WHERE id = ?`, id)
	return err
}

// Proxy Route CRUD

func (s *Store) CreateProxyRoute(nodeID, domain, upstream string, certID *string) (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	now := time.Now().Unix()
	var certIDVal interface{}
	if certID != nil {
		certIDVal = *certID
	}
	_, err = s.db.Exec(
		`INSERT INTO proxy_routes (id, node_id, domain, upstream, cert_id, sync_status, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id.String(), nodeID, domain, upstream, certIDVal, "pending", now,
	)
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

func (s *Store) GetProxyRoute(id string) (*ProxyRouteRecord, error) {
	row := s.db.QueryRow(`SELECT id, node_id, domain, upstream, cert_id, sync_status, updated_at FROM proxy_routes WHERE id = ?`, id)
	var r ProxyRouteRecord
	err := row.Scan(&r.ID, &r.NodeID, &r.Domain, &r.Upstream, &r.CertID, &r.SyncStatus, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) ListProxyRoutes() ([]ProxyRouteRecord, error) {
	rows, err := s.db.Query(`SELECT id, node_id, domain, upstream, cert_id, sync_status, updated_at FROM proxy_routes ORDER BY updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []ProxyRouteRecord
	for rows.Next() {
		var r ProxyRouteRecord
		if err := rows.Scan(&r.ID, &r.NodeID, &r.Domain, &r.Upstream, &r.CertID, &r.SyncStatus, &r.UpdatedAt); err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, nil
}

func (s *Store) UpdateProxyRoute(id, nodeID, domain, upstream, syncStatus string, certID *string) error {
	_, err := s.db.Exec(
		`UPDATE proxy_routes SET node_id = ?, domain = ?, upstream = ?, sync_status = ?,
		 cert_id = CASE WHEN ? IS NOT NULL THEN ? ELSE cert_id END,
		 updated_at = ? WHERE id = ?`,
		nodeID, domain, upstream, syncStatus, certID, certID, time.Now().Unix(), id,
	)
	return err
}

func (s *Store) DeleteProxyRoute(id string) error {
	_, err := s.db.Exec(`DELETE FROM proxy_routes WHERE id = ?`, id)
	return err
}

// Node Tags Update

func (s *Store) UpdateNodeTags(nodeID string, tags string) error {
	_, err := s.db.Exec(`UPDATE nodes SET tags = ? WHERE id = ?`, tags, nodeID)
	return err
}

// Compose Stack CRUD

func (s *Store) CreateComposeStack(name, targetTag, yamlContent string) (string, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	now := time.Now().Unix()
	_, err = s.db.Exec(
		`INSERT INTO compose_stacks (id, name, target_tag, yaml_content, status, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		id.String(), name, targetTag, yamlContent, "pending", now,
	)
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

func (s *Store) GetComposeStack(id string) (*ComposeStackRecord, error) {
	row := s.db.QueryRow(`SELECT id, name, target_tag, yaml_content, status, updated_at FROM compose_stacks WHERE id = ?`, id)
	var r ComposeStackRecord
	err := row.Scan(&r.ID, &r.Name, &r.TargetTag, &r.YAMLContent, &r.Status, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) ListComposeStacks() ([]ComposeStackRecord, error) {
	rows, err := s.db.Query(`SELECT id, name, target_tag, yaml_content, status, updated_at FROM compose_stacks ORDER BY updated_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []ComposeStackRecord
	for rows.Next() {
		var r ComposeStackRecord
		if err := rows.Scan(&r.ID, &r.Name, &r.TargetTag, &r.YAMLContent, &r.Status, &r.UpdatedAt); err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, nil
}

func (s *Store) UpdateComposeStackStatus(id string, status string) error {
	_, err := s.db.Exec(`UPDATE compose_stacks SET status = ?, updated_at = ? WHERE id = ?`, status, time.Now().Unix(), id)
	return err
}

func (s *Store) DeleteComposeStack(id string) error {
	_, err := s.db.Exec(`DELETE FROM compose_stacks WHERE id = ?`, id)
	return err
}
