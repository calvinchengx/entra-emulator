package server

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/config"
	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tlscert"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// buildServer constructs a *Server the same way the harness does, for tests
// that call methods directly instead of going through httptest.
func buildServer(t *testing.T, cert *tlscert.Material) (*Server, *config.Config) {
	t.Helper()
	cfg, err := config.Load(func(k string) string {
		switch k {
		case "DB_PATH":
			return filepath.Join(t.TempDir(), "l.db")
		case "TLS_ENABLED":
			return "false"
		case "ORIGIN_MODE":
			return "compat"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.EnsureTenant(cfg.TenantID, cfg.Issuer); err != nil {
		t.Fatal(err)
	}
	signer, err := tokens.EnsureActiveKey(st, cfg.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	ts := &tokens.Service{Store: st, Signer: signer, Cfg: cfg}
	return New(cfg, st, ts, cert, "test"), cfg
}

// TestListenErrors covers Server.Listen's error branches (the success paths
// block on ListenAndServe/ServeTLS, so only errors are unit-testable). Each
// case fails fast without binding a lasting listener.
func TestListenErrors(t *testing.T) {
	// Hold an ephemeral port so every Listen below collides with it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	// Non-TLS on a taken port → ListenAndServe error.
	srv, cfg := buildServer(t, nil)
	cfg.Host, cfg.Port, cfg.TLSEnabled = "127.0.0.1", port, false
	if err := srv.Listen(); err == nil {
		t.Fatal("non-TLS Listen on a taken port should error")
	}

	// TLS with an invalid certificate → Certificate() error (no bind).
	badCert := &tlscert.Material{CertPEM: []byte("not a cert"), KeyPEM: []byte("not a key")}
	srv2, cfg2 := buildServer(t, badCert)
	cfg2.Host, cfg2.Port, cfg2.TLSEnabled = "127.0.0.1", port, true
	if err := srv2.Listen(); err == nil {
		t.Fatal("TLS Listen with an invalid cert should error")
	}

	// TLS with a valid cert but a taken port → net.Listen error.
	goodCert, err := tlscert.LoadOrCreate(t.TempDir(), "entra.localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	srv3, cfg3 := buildServer(t, goodCert)
	cfg3.Host, cfg3.Port, cfg3.TLSEnabled = "127.0.0.1", port, true
	if err := srv3.Listen(); err == nil {
		t.Fatal("TLS Listen on a taken port should error")
	}
}
