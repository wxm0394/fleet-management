package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

type IssueResult struct {
	CertPEM string
	KeyPEM  string
}

type Issuer interface {
	IssueCertificate(domain string, providerType string, credentialsJSON string) (*IssueResult, error)
}

type DefaultIssuer struct{}

func NewDefaultIssuer() Issuer {
	return &DefaultIssuer{}
}

func (i *DefaultIssuer) IssueCertificate(domain string, providerType string, credentialsJSON string) (*IssueResult, error) {
	if providerType == "local_self_signed" || providerType == "mock" || providerType == "" {
		return generateSelfSignedCert(domain)
	}

	return generateSelfSignedCert(domain)
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
