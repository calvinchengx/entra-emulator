package tlscert

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// TestLoadOrCreateExtraDomainsTrimAndSkip covers the extraDomains loop's
// trim/skip branch (blank and whitespace entries are ignored) and verifies
// that real extra domains land in the generated cert's DNSNames.
func TestLoadOrCreateExtraDomainsTrimAndSkip(t *testing.T) {
	dir := t.TempDir()

	m, err := LoadOrCreate(dir, "entra.localhost", []string{"", "   ", "extra.local", "  padded.local  "})
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	block, _ := pem.Decode(m.CertPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	// Trimmed real domains present with their wildcards.
	for _, want := range []string{
		"entra.localhost", "*.entra.localhost", "localhost",
		"extra.local", "*.extra.local",
		"padded.local", "*.padded.local",
	} {
		if !contains(leaf.DNSNames, want) {
			t.Fatalf("cert missing SAN %q: %v", want, leaf.DNSNames)
		}
	}

	// Blank/whitespace-only entries were skipped, not added as empty SANs.
	for _, bad := range []string{"", "   ", "*.", "*.   "} {
		if contains(leaf.DNSNames, bad) {
			t.Fatalf("cert unexpectedly contains blank SAN %q: %v", bad, leaf.DNSNames)
		}
	}
}

// TestLoadOrCreateReusesExistingPair covers the "existing valid pair is
// reused" branch: a second call must return byte-identical material without
// regenerating.
func TestLoadOrCreateReusesExistingPair(t *testing.T) {
	dir := t.TempDir()

	first, err := LoadOrCreate(dir, "reuse.localhost", nil)
	if err != nil {
		t.Fatalf("first LoadOrCreate: %v", err)
	}
	second, err := LoadOrCreate(dir, "reuse.localhost", nil)
	if err != nil {
		t.Fatalf("second LoadOrCreate: %v", err)
	}
	if string(first.CertPEM) != string(second.CertPEM) || string(first.KeyPEM) != string(second.KeyPEM) {
		t.Fatal("expected existing pair to be reused byte-for-byte")
	}
}

// TestLoadOrCreateRegeneratesInvalidPair covers the branch where cert.pem and
// key.pem exist but do not form a valid pair: LoadOrCreate must regenerate.
func TestLoadOrCreateRegeneratesInvalidPair(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, certFile), []byte("garbage cert"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, keyFile), []byte("garbage key"), 0o600); err != nil {
		t.Fatal(err)
	}

	m, err := LoadOrCreate(dir, "regen.localhost", nil)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	// The regenerated pair is valid and was written over the garbage.
	if _, err := m.Certificate(); err != nil {
		t.Fatalf("regenerated Certificate invalid: %v", err)
	}
	onDisk, err := os.ReadFile(filepath.Join(dir, certFile))
	if err != nil {
		t.Fatal(err)
	}
	if string(onDisk) == "garbage cert" {
		t.Fatal("expected cert.pem to be overwritten with a valid cert")
	}
}

// TestLoadCustomMissingKey covers LoadCustom's key-read error branch: the
// cert file exists and reads fine, but the key path is missing.
func TestLoadCustomMissingKey(t *testing.T) {
	dir := t.TempDir()
	gen, err := LoadOrCreate(dir, "customkey.localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCustom(gen.CertPath, filepath.Join(dir, "missing-key.pem")); err == nil {
		t.Fatal("LoadCustom should fail when the key file is missing")
	}
}

// TestLoadOrCreateMkdirAllFails covers the MkdirAll error branch by pointing
// dir at a path whose parent is a regular file.
func TestLoadOrCreateMkdirAllFails(t *testing.T) {
	base := t.TempDir()
	parentFile := filepath.Join(base, "iamafile")
	if err := os.WriteFile(parentFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parentFile, "sub") // parent is a file -> MkdirAll fails

	if _, err := LoadOrCreate(dir, "mkdir.localhost", nil); err == nil {
		t.Fatal("expected MkdirAll to fail when parent is a regular file")
	}
}

// TestLoadOrCreateWriteCertFails covers the WriteFile(certPath) error branch:
// cert.pem already exists as a directory, so writing to it fails.
func TestLoadOrCreateWriteCertFails(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, certFile), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadOrCreate(dir, "writecert.localhost", nil); err == nil {
		t.Fatal("expected WriteFile(cert) to fail when cert.pem is a directory")
	}
}

// TestLoadOrCreateWriteKeyFails covers the WriteFile(keyPath) error branch:
// cert.pem writes fine but key.pem exists as a directory, so its write fails.
func TestLoadOrCreateWriteKeyFails(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, keyFile), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadOrCreate(dir, "writekey.localhost", nil); err == nil {
		t.Fatal("expected WriteFile(key) to fail when key.pem is a directory")
	}
	// cert.pem should have been written successfully before the key write failed.
	if _, err := os.Stat(filepath.Join(dir, certFile)); err != nil {
		t.Fatalf("expected cert.pem to be written before key failure: %v", err)
	}
}
