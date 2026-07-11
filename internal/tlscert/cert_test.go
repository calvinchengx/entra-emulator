package tlscert

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadOrCreateGeneratesStablePair(t *testing.T) {
	dir := t.TempDir()

	m, err := LoadOrCreate(dir, "entra.localhost", []string{"login.entra.localhost"})
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	// The pair parses as a usable TLS certificate.
	if _, err := m.Certificate(); err != nil {
		t.Fatalf("Certificate: %v", err)
	}

	// Fingerprint is colon-separated uppercase hex over the leaf DER.
	fp, err := m.Fingerprint()
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if strings.Count(fp, ":") != 31 || strings.ToUpper(fp) != fp {
		t.Fatalf("unexpected fingerprint format: %q", fp)
	}

	// The generated leaf covers the base domain, its wildcard, and localhost.
	block, _ := pem.Decode(m.CertPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	for _, want := range []string{"entra.localhost", "*.entra.localhost", "localhost", "login.entra.localhost"} {
		if !contains(leaf.DNSNames, want) {
			t.Fatalf("cert missing SAN %q: %v", want, leaf.DNSNames)
		}
	}

	// A second load reuses the persisted files (fingerprint stays stable).
	m2, err := LoadOrCreate(dir, "entra.localhost", nil)
	if err != nil {
		t.Fatalf("second LoadOrCreate: %v", err)
	}
	fp2, _ := m2.Fingerprint()
	if fp2 != fp {
		t.Fatalf("fingerprint changed across reloads: %q vs %q", fp, fp2)
	}
	if _, err := os.Stat(filepath.Join(dir, certFile)); err != nil {
		t.Fatalf("cert file not persisted: %v", err)
	}
}

func TestLoadCustomRoundTrip(t *testing.T) {
	dir := t.TempDir()
	// Produce a valid pair via LoadOrCreate, then load it as "custom".
	gen, err := LoadOrCreate(dir, "custom.localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	m, err := LoadCustom(gen.CertPath, gen.KeyPath)
	if err != nil {
		t.Fatalf("LoadCustom: %v", err)
	}
	if _, err := m.Certificate(); err != nil {
		t.Fatalf("custom Certificate: %v", err)
	}

	// Missing files and mismatched pairs are rejected.
	if _, err := LoadCustom(filepath.Join(dir, "nope.pem"), gen.KeyPath); err == nil {
		t.Fatal("LoadCustom should fail on a missing cert file")
	}
	bad := filepath.Join(dir, "bad.pem")
	_ = os.WriteFile(bad, []byte("-----BEGIN CERTIFICATE-----\nnotpem\n-----END CERTIFICATE-----"), 0o644)
	if _, err := LoadCustom(bad, gen.KeyPath); err == nil {
		t.Fatal("LoadCustom should fail on an invalid pair")
	}
}

func TestFingerprintInvalidPEM(t *testing.T) {
	m := &Material{CertPEM: []byte("not pem")}
	if _, err := m.Fingerprint(); err == nil {
		t.Fatal("Fingerprint should error on invalid PEM")
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
