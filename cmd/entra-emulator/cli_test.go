package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/config"
)

// captureStdout runs fn with os.Stdout redirected to a pipe and returns what
// it wrote.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = orig }()
	fn()
	_ = w.Close()
	var sb strings.Builder
	buf := make([]byte, 1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	return sb.String()
}

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Load(func(k string) string {
		switch k {
		case "ORIGIN_MODE":
			return "compat"
		case "TLS_ENABLED":
			return "false"
		case "TLS_CERT_DIR":
			return filepath.Join(t.TempDir(), "tls")
		case "DB_PATH":
			return filepath.Join(t.TempDir(), "cli.db")
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestHostsEntries(t *testing.T) {
	cfg := testConfig(t)
	cfg.BaseDomain = "entra.localhost"
	cfg.LocalDomains = []string{"corp.test"}
	lines := hostsEntries(cfg)
	// login/portal/graph for each of 2 domains = 6 lines.
	if len(lines) != 6 {
		t.Fatalf("want 6 host lines, got %d: %v", len(lines), lines)
	}
	for _, want := range []string{"127.0.0.1  login.entra.localhost", "127.0.0.1  graph.corp.test"} {
		found := false
		for _, l := range lines {
			if l == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing host line %q in %v", want, lines)
		}
	}
}

func TestMergeHostsBlock(t *testing.T) {
	block := hostsMarkerBegin + "\n127.0.0.1  login.x\n" + hostsMarkerEnd
	base := "127.0.0.1 localhost\n"

	// Add.
	added := mergeHostsBlock(base, block, false)
	if !strings.Contains(added, "login.x") || !strings.Contains(added, hostsMarkerBegin) {
		t.Fatalf("block not added: %q", added)
	}
	// Idempotent re-add: exactly one managed block.
	twice := mergeHostsBlock(added, block, false)
	if strings.Count(twice, hostsMarkerBegin) != 1 {
		t.Fatalf("re-add duplicated block: %q", twice)
	}
	// Remove strips the block but keeps other content.
	removed := mergeHostsBlock(twice, block, true)
	if strings.Contains(removed, hostsMarkerBegin) || !strings.Contains(removed, "localhost") {
		t.Fatalf("remove failed: %q", removed)
	}
}

func TestRunHostsApplyAndRemove(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "hosts")
	if err := os.WriteFile(fake, []byte("127.0.0.1 localhost\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := hostsFilePathFn
	hostsFilePathFn = func() string { return fake }
	t.Cleanup(func() { hostsFilePathFn = orig })

	cfg := testConfig(t)
	if err := runHosts(cfg, []string{"--apply"}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	raw, _ := os.ReadFile(fake)
	if !strings.Contains(string(raw), hostsMarkerBegin) {
		t.Fatalf("apply did not write block: %s", raw)
	}
	if err := runHosts(cfg, []string{"--apply", "--remove"}); err != nil {
		t.Fatalf("remove: %v", err)
	}
	raw, _ = os.ReadFile(fake)
	if strings.Contains(string(raw), hostsMarkerBegin) {
		t.Fatalf("remove did not strip block: %s", raw)
	}

	// Print mode (no --apply) must not error and must not touch the file.
	if err := runHosts(cfg, nil); err != nil {
		t.Fatalf("print mode: %v", err)
	}
}

func TestRunSubcommandDispatch(t *testing.T) {
	cfg := testConfig(t)

	// help / cert-path / show-cert / trust / version all succeed.
	for _, verb := range []string{"help", "--help", "cert-path", "show-cert", "trust", "version", "--version", "-v"} {
		if err := runSubcommand(cfg, []string{verb}); err != nil {
			t.Fatalf("subcommand %q: %v", verb, err)
		}
	}
	// Unknown → error.
	if err := runSubcommand(cfg, []string{"bogus"}); err == nil {
		t.Fatal("unknown subcommand should error")
	}
}

func TestVersionSubcommandPrints(t *testing.T) {
	cfg := testConfig(t)
	// Stamp a recognizable version and confirm `version` prints exactly it.
	orig := version
	version = "v9.9.9-test"
	t.Cleanup(func() { version = orig })

	out := captureStdout(t, func() {
		if err := runSubcommand(cfg, []string{"version"}); err != nil {
			t.Fatalf("version: %v", err)
		}
	})
	if strings.TrimSpace(out) != "v9.9.9-test" {
		t.Fatalf("version output = %q, want %q", strings.TrimSpace(out), "v9.9.9-test")
	}
}

func TestRunHealthcheck(t *testing.T) {
	// Healthy server on the configured port.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	port := portOf(t, srv.URL)
	cfg := testConfig(t)
	cfg.TLSEnabled = false
	cfg.Port = port
	if err := runHealthcheck(cfg); err != nil {
		t.Fatalf("healthy probe should pass: %v", err)
	}

	// Unhealthy: nothing listening on a free port → error.
	cfg.Port = 1 // privileged/closed; connection fails fast
	if err := runHealthcheck(cfg); err == nil {
		t.Fatal("healthcheck against a dead port should error")
	}
}

func TestBootAndSubcommandRun(t *testing.T) {
	// boot() wires the full stack without binding a listener.
	cfg := testConfig(t)
	srv, st, err := boot(cfg)
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	defer st.Close()
	if srv == nil {
		t.Fatal("boot returned nil server")
	}
	// The seeded directory is present.
	if u, err := st.GetUserByUPN("alice@entraemulator.dev"); err != nil || u == nil {
		t.Fatalf("boot did not seed: %v", err)
	}

	// run() dispatches to the subcommand path when args are present.
	oldArgs := os.Args
	os.Args = []string{"entra-emulator", "help"}
	t.Cleanup(func() { os.Args = oldArgs })
	// Point CONFIG at the compat/no-TLS env so run()'s config.Load succeeds
	// without generating certs or binding.
	t.Setenv("ORIGIN_MODE", "compat")
	t.Setenv("TLS_ENABLED", "false")
	if err := run(); err != nil {
		t.Fatalf("run help: %v", err)
	}
}

func portOf(t *testing.T, url string) int {
	t.Helper()
	i := strings.LastIndex(url, ":")
	p, err := strconv.Atoi(url[i+1:])
	if err != nil {
		t.Fatalf("parse port from %q: %v", url, err)
	}
	return p
}
