package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/tlscert"
)

// TestPrintHelpOutput exercises printHelp and asserts the usage text is emitted.
func TestPrintHelpOutput(t *testing.T) {
	out := captureStdout(t, printHelp)
	for _, want := range []string{"entra-emulator", "hosts", "trust", "healthcheck", "version"} {
		if !strings.Contains(out, want) {
			t.Fatalf("help output missing %q: %s", want, out)
		}
	}
}

// TestPrintTrustCommandOutput calls printTrustCommand and confirms the cert path
// and the Node hint are present. The runtime.GOOS switch covers the current-OS
// branch.
func TestPrintTrustCommandOutput(t *testing.T) {
	out := captureStdout(t, func() { printTrustCommand("/tmp/cert.pem") })
	if !strings.Contains(out, "/tmp/cert.pem") {
		t.Fatalf("trust output missing cert path: %s", out)
	}
	if !strings.Contains(out, "NODE_EXTRA_CA_CERTS=/tmp/cert.pem") {
		t.Fatalf("trust output missing Node hint: %s", out)
	}
}

// TestHostsFilePath confirms the OS-appropriate default path.
func TestHostsFilePath(t *testing.T) {
	p := hostsFilePath()
	if p == "" {
		t.Fatal("hostsFilePath returned empty")
	}
}

// TestRunHostsPrintRemove covers the print-mode (no --apply) + --remove branch,
// which prints the "re-run to remove" hint rather than mutating the file.
func TestRunHostsPrintRemove(t *testing.T) {
	cfg := testConfig(t)
	out := captureStdout(t, func() {
		if err := runHosts(cfg, []string{"--remove"}); err != nil {
			t.Fatalf("print remove: %v", err)
		}
	})
	if !strings.Contains(out, "remove the block") {
		t.Fatalf("print-remove missing hint: %s", out)
	}
	if !strings.Contains(out, hostsMarkerBegin) {
		t.Fatalf("print-remove should still show the block: %s", out)
	}
}

// TestRunHostsApplyReadError points hostsFilePathFn at a nonexistent file so the
// os.ReadFile error path is exercised.
func TestRunHostsApplyReadError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does", "not", "exist", "hosts")
	orig := hostsFilePathFn
	hostsFilePathFn = func() string { return missing }
	t.Cleanup(func() { hostsFilePathFn = orig })

	cfg := testConfig(t)
	err := runHosts(cfg, []string{"--apply"})
	if err == nil {
		t.Fatal("apply against a missing hosts file should error")
	}
	if !strings.Contains(err.Error(), "read") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestRunSubcommandHostsAndHealthcheck drives the runSubcommand branches for
// "hosts" (delegates to runHosts print mode) and "healthcheck".
func TestRunSubcommandHostsAndHealthcheck(t *testing.T) {
	cfg := testConfig(t)

	// hosts (print mode) via the dispatcher.
	if err := runSubcommand(cfg, []string{"hosts"}); err != nil {
		t.Fatalf("subcommand hosts: %v", err)
	}

	// healthcheck against a live /health handler through the dispatcher.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	cfg.TLSEnabled = false
	cfg.Port = portOf(t, srv.URL)
	if err := runSubcommand(cfg, []string{"healthcheck"}); err != nil {
		t.Fatalf("subcommand healthcheck: %v", err)
	}
}

// TestRunSubcommandUnknownPrintsHelp confirms the default branch prints help and
// returns an error naming the bad verb.
func TestRunSubcommandUnknownPrintsHelp(t *testing.T) {
	cfg := testConfig(t)
	var err error
	out := captureStdout(t, func() { err = runSubcommand(cfg, []string{"nope"}) })
	if err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("expected unknown-subcommand error, got %v", err)
	}
	if !strings.Contains(out, "Usage") {
		t.Fatalf("default branch should print help: %s", out)
	}
}

// TestCertPathAndShowCertOutput verifies the cert-path and show-cert output goes
// through captureStdout with a fingerprint line for show-cert.
func TestCertPathAndShowCertOutput(t *testing.T) {
	cfg := testConfig(t)

	certOut := captureStdout(t, func() {
		if err := runSubcommand(cfg, []string{"cert-path"}); err != nil {
			t.Fatalf("cert-path: %v", err)
		}
	})
	if !strings.Contains(certOut, "cert.pem") {
		t.Fatalf("cert-path output missing cert.pem: %s", certOut)
	}

	showOut := captureStdout(t, func() {
		if err := runSubcommand(cfg, []string{"show-cert"}); err != nil {
			t.Fatalf("show-cert: %v", err)
		}
	})
	if !strings.Contains(showOut, "SHA-256:") {
		t.Fatalf("show-cert output missing fingerprint: %s", showOut)
	}
}

// TestTrustSubcommandOutput drives the "trust" verb end-to-end and confirms it
// prints a trust command referencing the generated cert path.
func TestTrustSubcommandOutput(t *testing.T) {
	cfg := testConfig(t)
	out := captureStdout(t, func() {
		if err := runSubcommand(cfg, []string{"trust"}); err != nil {
			t.Fatalf("trust: %v", err)
		}
	})
	if !strings.Contains(out, "Trust the emulator certificate") {
		t.Fatalf("trust output unexpected: %s", out)
	}
}

// TestRunHealthcheckTLSAndBadStatus covers the https scheme branch (TLS-enabled)
// against an httptest TLS server, and the non-200 status error path.
func TestRunHealthcheckTLSAndBadStatus(t *testing.T) {
	// TLS server: the InsecureSkipVerify client must accept the self-signed cert.
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer tlsSrv.Close()

	cfg := testConfig(t)
	cfg.TLSEnabled = true
	cfg.Port = portOf(t, tlsSrv.URL)
	if err := runHealthcheck(cfg); err != nil {
		t.Fatalf("TLS healthcheck should pass: %v", err)
	}

	// Non-200 response → error.
	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer badSrv.Close()
	cfg.TLSEnabled = false
	cfg.Port = portOf(t, badSrv.URL)
	if err := runHealthcheck(cfg); err == nil {
		t.Fatal("non-200 health should error")
	}
}

// TestBootTLSEnabled covers boot()'s TLS-enabled branch using the auto-generated
// cert (LoadOrCreate) and, separately, a custom cert/key pair (LoadCustom).
func TestBootTLSEnabled(t *testing.T) {
	// Auto cert via LoadOrCreate.
	cfg := testConfig(t)
	cfg.TLSEnabled = true
	srv, st, err := boot(cfg)
	if err != nil {
		t.Fatalf("boot with auto TLS: %v", err)
	}
	st.Close()
	if srv == nil {
		t.Fatal("boot returned nil server")
	}

	// Custom cert pair via LoadCustom: generate a pair, then point config at it.
	gen, err := tlscert.LoadOrCreate(filepath.Join(t.TempDir(), "gen"), cfg.BaseDomain, cfg.LocalDomains)
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	cfg2 := testConfig(t)
	cfg2.TLSEnabled = true
	cfg2.TLSCertPath = gen.CertPath
	cfg2.TLSKeyPath = gen.KeyPath
	srv2, st2, err := boot(cfg2)
	if err != nil {
		t.Fatalf("boot with custom TLS: %v", err)
	}
	st2.Close()
	if srv2 == nil {
		t.Fatal("boot returned nil server (custom)")
	}
}

// TestBootStoreOpenError makes store.Open fail by pointing DB_PATH at a path
// whose parent directory can't be created (a component is a regular file).
func TestBootStoreOpenError(t *testing.T) {
	dir := t.TempDir()
	fileAsDir := filepath.Join(dir, "afile")
	if err := os.WriteFile(fileAsDir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(t)
	cfg.DBPath = filepath.Join(fileAsDir, "sub", "db.sqlite")
	if _, _, err := boot(cfg); err == nil {
		t.Fatal("boot should fail when the data dir cannot be created")
	}
}

// TestBootTLSCustomLoadError exercises boot()'s error return when the custom TLS
// material cannot be loaded (nonexistent cert path).
func TestBootTLSCustomLoadError(t *testing.T) {
	cfg := testConfig(t)
	cfg.TLSEnabled = true
	cfg.TLSCertPath = filepath.Join(t.TempDir(), "missing-cert.pem")
	cfg.TLSKeyPath = filepath.Join(t.TempDir(), "missing-key.pem")
	if _, _, err := boot(cfg); err == nil {
		t.Fatal("boot should fail when the custom cert is missing")
	}
}

// TestRunConfigError drives run()'s early config.Load error path via an invalid
// TENANT_ID, with no subcommand args.
func TestRunConfigError(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"entra-emulator"}
	t.Cleanup(func() { os.Args = oldArgs })
	t.Setenv("ORIGIN_MODE", "compat")
	t.Setenv("TLS_ENABLED", "false")
	t.Setenv("TENANT_ID", "not-a-guid")
	if err := run(); err == nil {
		t.Fatal("run with an invalid TENANT_ID should error")
	}
}
