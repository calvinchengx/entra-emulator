package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const exampleManifest = "../../samples/manifest/entra-emulator.manifest.json"

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// TestManifestReplacesDirectorySettings: with a manifest, its tenant and token
// lifetimes win over TENANT_ID and TOKEN_LIFETIME_*, and the seed is off.
// Server settings still come from the environment.
func TestManifestReplacesDirectorySettings(t *testing.T) {
	c, err := Load(envOf(map[string]string{
		"CONFIG_FILE":                   filepath.Join(t.TempDir(), "absent.json"),
		"MANIFEST_FILE":                 exampleManifest,
		"TENANT_ID":                     "11111111-2222-4333-8444-555555555555",
		"TOKEN_LIFETIME_ACCESS_SECONDS": "60",
		"TOKEN_LIFETIME_ID_SECONDS":     "60",
		"SEED_ON_START":                 "true",
		"PORT":                          "9443",
		"ORIGIN_MODE":                   "compat",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Manifest == nil || c.ManifestPath != exampleManifest {
		t.Fatalf("manifest not loaded: %q %v", c.ManifestPath, c.Manifest)
	}
	if c.TenantID != "3c8f2a91-6d4e-4b7a-9e15-0a2b7c4d8e6f" || !strings.Contains(c.Issuer, c.TenantID) {
		t.Fatalf("tenant: %s issuer %s", c.TenantID, c.Issuer)
	}
	// accessToken comes from the manifest; idToken, which the manifest leaves
	// out, is the default rather than the ignored environment value.
	if c.Lifetimes.AccessToken != 3600 || c.Lifetimes.IDToken != 3600 || c.Lifetimes.AuthCode != 300 {
		t.Fatalf("lifetimes: %+v", c.Lifetimes)
	}
	if c.SeedOnStart {
		t.Fatal("seed must be off with a manifest")
	}
	if c.Port != 9443 || c.Origins.Login != "https://localhost:9443" {
		t.Fatalf("server settings must still come from the environment: port %d login %s", c.Port, c.Origins.Login)
	}
}

func TestManifestFromConfigFile(t *testing.T) {
	abs, _ := filepath.Abs(exampleManifest)
	cfgFile := filepath.Join(t.TempDir(), "entra-emulator.config.json")
	if err := os.WriteFile(cfgFile, []byte(`{"manifestFile": `+quote(abs)+`}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(envOf(map[string]string{"CONFIG_FILE": cfgFile}))
	if err != nil || c.Manifest == nil {
		t.Fatalf("manifestFile in the config file: %v %v", err, c)
	}
}

func TestManifestErrorsNameTheKey(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`{"tenantId": "contoso"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		bad: "tenantId: must be a lowercase GUID",
		filepath.Join(t.TempDir(), "missing.json"): "MANIFEST_FILE",
	} {
		_, err := Load(envOf(map[string]string{"CONFIG_FILE": filepath.Join(t.TempDir(), "absent.json"), "MANIFEST_FILE": path}))
		if err == nil || !strings.Contains(err.Error(), "MANIFEST_FILE") || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want an error naming MANIFEST_FILE and %q, got %v", path, want, err)
		}
	}
}

func quote(s string) string { return `"` + strings.ReplaceAll(s, `\`, `\\`) + `"` }
