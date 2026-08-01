package server

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/calvinchengx/entra-emulator/internal/tlscert"
)

// freeTCPPort returns an unused localhost TCP port.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// servedLeafDER completes a TLS handshake and returns the served leaf cert DER.
func servedLeafDER(addr string) ([]byte, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // inspecting the served cert on purpose
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no peer certificates")
	}
	return certs[0].Raw, nil
}

func leafDER(t *testing.T, certPEM []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("bad cert PEM")
	}
	return block.Bytes
}

// TestCertReloadEndToEnd starts a real TLS listener, re-issues the on-disk cert
// pair while it is serving, and asserts the server presents the NEW leaf on a
// fresh connection — without a restart — through the mtime-poll reload path.
func TestCertReloadEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cert-reload e2e (waits on the reload poll) in -short mode")
	}
	dir := t.TempDir()
	cert, err := tlscert.LoadOrCreate(dir, "entra.localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	srv, cfg := buildServer(t, cert)
	cfg.Host, cfg.Port, cfg.TLSEnabled = "127.0.0.1", freeTCPPort(t), true
	addr := fmt.Sprintf("127.0.0.1:%d", cfg.Port)

	go func() { _ = srv.Listen() }()

	// Wait for the listener to accept TLS, then capture the initial leaf.
	var leaf1 []byte
	deadline := time.Now().Add(5 * time.Second)
	for {
		leaf1, err = servedLeafDER(addr)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("TLS server never came up: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !bytes.Equal(leaf1, leafDER(t, cert.CertPEM)) {
		t.Fatal("served leaf does not match the initial certificate")
	}

	// Re-issue a different pair to the SAME paths (simulating `step ca renew`).
	fresh, err := tlscert.LoadOrCreate(t.TempDir(), "entra.localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(leafDER(t, fresh.CertPEM), leaf1) {
		t.Fatal("freshly generated cert is unexpectedly identical to the first")
	}
	if err := os.WriteFile(cert.CertPath, fresh.CertPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cert.KeyPath, fresh.KeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	// Push the mtime clearly forward so the poll detects the change regardless
	// of filesystem timestamp granularity.
	future := time.Now().Add(10 * time.Second)
	if err := os.Chtimes(cert.CertPath, future, future); err != nil {
		t.Fatal(err)
	}

	// The poll ticks every 5s; wait for the served leaf to flip to the new cert.
	wantLeaf := leafDER(t, fresh.CertPEM)
	deadline = time.Now().Add(12 * time.Second)
	for {
		if got, err := servedLeafDER(addr); err == nil && bytes.Equal(got, wantLeaf) {
			return // served the reloaded certificate without a restart
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not serve the reloaded certificate within 12s")
		}
		time.Sleep(250 * time.Millisecond)
	}
}
