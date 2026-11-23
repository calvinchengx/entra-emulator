package main

import (
	"path/filepath"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/config"
)

// TestBootLoadsManifest: boot() loads the manifest's directory instead of
// the deterministic seed.
func TestBootLoadsManifest(t *testing.T) {
	dir := t.TempDir()
	cfg, err := config.Load(func(k string) string {
		return map[string]string{
			"CONFIG_FILE":   filepath.Join(dir, "absent.json"),
			"MANIFEST_FILE": "../../samples/manifest/entra-emulator.manifest.json",
			"ORIGIN_MODE":   "compat",
			"TLS_ENABLED":   "false",
			"DB_PATH":       filepath.Join(dir, "boot.db"),
		}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, st, err := boot(cfg)
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	defer func() { _ = st.Close() }()
	if srv == nil {
		t.Fatal("boot returned nil server")
	}
	if _, err := st.GetUserByUPN("alice@contoso.local"); err != nil {
		t.Fatalf("manifest user missing: %v", err)
	}
	if _, err := st.GetUserByUPN("alice@entraemulator.dev"); err == nil {
		t.Fatal("the seed ran despite the manifest")
	}
}
