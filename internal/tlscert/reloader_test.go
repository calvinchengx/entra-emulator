package tlscert

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// writePair generates a fresh self-signed pair and writes it to dir.
func writePair(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	certPEM, keyPEM, err := generate("entra.localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestReloaderSwapsOnChange(t *testing.T) {
	dir := t.TempDir()
	cp, kp := writePair(t, dir)
	m, err := LoadCustom(cp, kp)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewReloader(m)
	if err != nil {
		t.Fatal(err)
	}
	if !r.CanReload() {
		t.Fatal("CanReload should be true for an on-disk pair")
	}

	first, _ := r.GetCertificate(nil)
	firstLeaf := first.Certificate[0]

	// Identical content → no-op reload.
	if changed, err := r.Reload(); err != nil || changed {
		t.Fatalf("unchanged reload: changed=%v err=%v", changed, err)
	}

	// Re-issue a different pair to the same paths → reload swaps it in.
	certPEM2, keyPEM2, err := generate("entra.localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cp, certPEM2, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, keyPEM2, 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := r.Reload(); err != nil || !changed {
		t.Fatalf("changed reload: changed=%v err=%v", changed, err)
	}
	second, _ := r.GetCertificate(nil)
	if bytes.Equal(second.Certificate[0], firstLeaf) {
		t.Fatal("certificate did not change after reload")
	}
}

func TestReloaderKeepsCurrentOnBadReload(t *testing.T) {
	dir := t.TempDir()
	cp, kp := writePair(t, dir)
	m, _ := LoadCustom(cp, kp)
	r, _ := NewReloader(m)
	before, _ := r.GetCertificate(nil)

	// Corrupt cert → reload errors, current pair retained.
	if err := os.WriteFile(cp, []byte("not a cert"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reload(); err == nil {
		t.Fatal("expected error reloading an invalid cert")
	}
	if after, _ := r.GetCertificate(nil); !bytes.Equal(after.Certificate[0], before.Certificate[0]) {
		t.Fatal("current certificate should survive a failed reload")
	}

	// Missing file → error.
	if err := os.Remove(cp); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reload(); err == nil {
		t.Fatal("expected error reloading a missing cert")
	}
}

func TestReloaderInMemoryNotReloadable(t *testing.T) {
	certPEM, keyPEM, err := generate("entra.localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewReloader(&Material{CertPEM: certPEM, KeyPEM: keyPEM}) // no paths
	if err != nil {
		t.Fatal(err)
	}
	if r.CanReload() {
		t.Fatal("in-memory material must not be reloadable")
	}
	if _, err := r.Reload(); err == nil {
		t.Fatal("reload without paths should error")
	}
	if c, _ := r.GetCertificate(nil); c == nil {
		t.Fatal("static certificate should still be served")
	}
}

func TestNewReloaderRejectsInvalidPair(t *testing.T) {
	if _, err := NewReloader(&Material{CertPEM: []byte("x"), KeyPEM: []byte("y")}); err == nil {
		t.Fatal("expected error for an invalid initial pair")
	}
}
