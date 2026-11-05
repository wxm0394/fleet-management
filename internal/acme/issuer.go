package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
)

type IssueResult struct {
	CertPEM string
	KeyPEM  string
}

type Issuer interface {
	IssueCertificate(domain string, providerType string, credentialsJSON string, acmeEnv string) (*IssueResult, error)
}

type DefaultIssuer struct {
	mu           sync.Mutex
	userAccounts map[string]*acmeUser
}

func NewDefaultIssuer() Issuer {
	return &DefaultIssuer{
		userAccounts: make(map[string]*acmeUser),
	}
}

type acmeUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string {
	return u.Email
}

func (u *acmeUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *acmeUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func (i *DefaultIssuer) IssueCertificate(domain string, providerType string, credentialsJSON string, acmeEnv string) (*IssueResult, error) {
	if providerType == "local_self_signed" || providerType == "mock" || providerType == "" {
		return generateSelfSignedCert(domain)
	}

	// Protect env var modification and provider challenge setup from concurrent race condition
	i.mu.Lock()
	defer i.mu.Unlock()

	// Parse JSON credentials and set as env vars for lego provider with deferred cleanup
	if credentialsJSON != "" {
		var creds map[string]string
		if err := json.Unmarshal([]byte(credentialsJSON), &creds); err == nil {
			for k, v := range creds {
				os.Setenv(k, v)
				defer os.Unsetenv(k)
			}
		}
	}

	caDirURL := lego.LEDirectoryProduction
	if acmeEnv == "staging" {
		caDirURL = lego.LEDirectoryStaging
	}

	userKey := caDirURL
	user, exists := i.userAccounts[userKey]
	if !exists {
		// Create private key for ACME user
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key: %w", err)
		}

		user = &acmeUser{
			Email: "admin@" + domain,
			key:   privateKey,
		}
	}

	config := lego.NewConfig(user)
	config.CADirURL = caDirURL
	config.Certificate.KeyType = "p256"

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create lego client: %w", err)
	}

	provider, err := dns.NewDNSChallengeProviderByName(providerType)
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS provider '%s': %w", providerType, err)
	}

	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		return nil, fmt.Errorf("failed to set DNS01 provider: %w", err)
	}

	if user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("ACME registration failed: %w", err)
		}
		user.Registration = reg
		i.userAccounts[userKey] = user
	}

	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain certificate via ACME: %w", err)
	}

	return &IssueResult{
		CertPEM: string(certificates.Certificate),
		KeyPEM:  string(certificates.PrivateKey),
	}, nil
}

func generateSelfSignedCert(domain string) (*IssueResult, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Fleet Management Local CA"},
			CommonName:   domain,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	certPemBlock := &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
	certPem := pem.EncodeToMemory(certPemBlock)

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	keyPemBlock := &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}
	keyPem := pem.EncodeToMemory(keyPemBlock)

	return &IssueResult{
		CertPEM: string(certPem),
		KeyPEM:  string(keyPem),
	}, nil
}
