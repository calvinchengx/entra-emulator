// Package tlscert generates and persists the emulator's self-signed TLS
// certificate so its fingerprint stays stable across restarts.
package tlscert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	certFile = "cert.pem"
	keyFile  = "key.pem"
)

// Material holds the loaded or generated certificate pair.
type Material struct {
	CertPEM  []byte
	KeyPEM   []byte
	CertPath string
	KeyPath  string
}

// Fingerprint returns the SHA-256 fingerprint of the leaf certificate,
// formatted as uppercase colon-separated hex.
func (m *Material) Fingerprint() (string, error) {
	block, _ := pem.Decode(m.CertPEM)
	if block == nil {
		return "", fmt.Errorf("tlscert: invalid certificate PEM")
	}
	sum := sha256.Sum256(block.Bytes)
	hexed := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(hexed)/2)
	for i := 0; i < len(hexed); i += 2 {
		parts = append(parts, hexed[i:i+2])
	}
	return strings.Join(parts, ":"), nil
}

// Certificate parses the pair for use with a TLS listener.
func (m *Material) Certificate() (tls.Certificate, error) {
	return tls.X509KeyPair(m.CertPEM, m.KeyPEM)
}

// LoadOrCreate returns the persisted certificate from dir, generating a new
// self-signed wildcard certificate on first run. baseDomain is the apex the
// wildcard covers (e.g. "entra.localhost"); extraDomains each contribute the
// apex plus a wildcard entry.
func LoadOrCreate(dir, baseDomain string, extraDomains []string) (*Material, error) {
	certPath := filepath.Join(dir, certFile)
	keyPath := filepath.Join(dir, keyFile)

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		if _, err := tls.X509KeyPair(certPEM, keyPEM); err == nil {
			return &Material{CertPEM: certPEM, KeyPEM: keyPEM, CertPath: certPath, KeyPath: keyPath}, nil
		}
	}

	certPEM, keyPEM, err := generate(baseDomain, extraDomains)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("tlscert: create dir: %w", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("tlscert: write cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("tlscert: write key: %w", err)
	}
	return &Material{CertPEM: certPEM, KeyPEM: keyPEM, CertPath: certPath, KeyPath: keyPath}, nil
}

// LoadCustom loads a user-supplied certificate pair.
func LoadCustom(certPath, keyPath string) (*Material, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("tlscert: read TLS_CERT: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("tlscert: read TLS_KEY: %w", err)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return nil, fmt.Errorf("tlscert: invalid custom cert/key pair: %w", err)
	}
	return &Material{CertPEM: certPEM, KeyPEM: keyPEM, CertPath: certPath, KeyPath: keyPath}, nil
}

func generate(baseDomain string, extraDomains []string) (certPEM, keyPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("tlscert: generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("tlscert: serial: %w", err)
	}

	dnsNames := []string{baseDomain, "*." + baseDomain, "localhost"}
	for _, d := range extraDomains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		dnsNames = append(dnsNames, d, "*."+d)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         baseDomain,
			OrganizationalUnit: []string{"Entra Emulator"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(2, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              dnsNames,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("tlscert: create certificate: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalPKCS8(key)})
	return certPEM, keyPEM, nil
}

func mustMarshalPKCS8(key *rsa.PrivateKey) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	return der
}
