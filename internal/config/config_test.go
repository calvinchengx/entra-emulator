package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// envFunc builds a getenv closure from a map.
func envFunc(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(envFunc(nil))
	if err != nil {
		t.Fatalf("defaults should load: %v", err)
	}
	if cfg.TenantID != DefaultTenantID {
		t.Fatalf("default tenant = %q", cfg.TenantID)
	}
	if cfg.OriginMode != "subdomains" || cfg.Port != 8443 || !cfg.TLSEnabled {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	// Subdomains + TLS → https://login.<base>:<port> and a GUID-form issuer.
	if !strings.HasPrefix(cfg.Origins.Login, "https://login.") {
		t.Fatalf("login origin = %q", cfg.Origins.Login)
	}
	if !strings.HasSuffix(cfg.Issuer, "/"+DefaultTenantID+"/v2.0") {
		t.Fatalf("issuer = %q", cfg.Issuer)
	}
}

func TestCompatOriginDerivation(t *testing.T) {
	cfg, err := Load(envFunc(map[string]string{"ORIGIN_MODE": "compat", "TLS_ENABLED": "false", "PORT": "9000"}))
	if err != nil {
		t.Fatal(err)
	}
	// Compat collapses every surface onto one http origin.
	want := "http://localhost:9000"
	if cfg.Origins.Login != want || cfg.Origins.Graph != want || cfg.Origins.Portal != want {
		t.Fatalf("compat origins not collapsed: %+v", cfg.Origins)
	}
}

func TestEnvOverridesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"host":"filehost","port":7000,"logLevel":"debug"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// File provides port 7000 + host; env overrides host and adds tenant.
	cfg, err := Load(envFunc(map[string]string{
		"CONFIG_FILE": path,
		"HOST":        "envhost",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "envhost" {
		t.Fatalf("env should win over file: host = %q", cfg.Host)
	}
	if cfg.Port != 7000 {
		t.Fatalf("file value should apply when env absent: port = %d", cfg.Port)
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("file logLevel not applied: %q", cfg.LogLevel)
	}
}

func TestValidationErrors(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"bad tenant", map[string]string{"TENANT_ID": "not-a-guid"}, "TENANT_ID"},
		{"bad port", map[string]string{"PORT": "70000"}, "PORT"},
		{"bad origin mode", map[string]string{"ORIGIN_MODE": "weird"}, "ORIGIN_MODE"},
		{"tls half pair", map[string]string{"TLS_CERT": "/x/cert.pem"}, "TLS_CERT/TLS_KEY"},
		{"nonpositive lifetime", map[string]string{"TOKEN_LIFETIME_ACCESS_SECONDS": "0"}, "TOKEN_LIFETIME_ACCESS_SECONDS"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(envFunc(tc.env))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error mentioning %q, got %v", tc.want, err)
			}
		})
	}
}

func TestBadConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(path, []byte("{not json"), 0o644)
	if _, err := Load(envFunc(map[string]string{"CONFIG_FILE": path})); err == nil {
		t.Fatal("invalid JSON config should error")
	}
	// A missing config file is not an error (defaults apply).
	if _, err := Load(envFunc(map[string]string{"CONFIG_FILE": filepath.Join(dir, "absent.json")})); err != nil {
		t.Fatalf("missing config file should be tolerated: %v", err)
	}
}
