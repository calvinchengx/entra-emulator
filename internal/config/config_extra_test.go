package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPublicOriginCollapse: PUBLIC_ORIGIN collapses every surface onto one
// origin and drives the derived issuer.
func TestPublicOriginCollapse(t *testing.T) {
	cfg, err := Load(envFunc(map[string]string{"PUBLIC_ORIGIN": "https://auth.example.test"}))
	if err != nil {
		t.Fatal(err)
	}
	want := "https://auth.example.test"
	if cfg.Origins.Login != want || cfg.Origins.Portal != want || cfg.Origins.Graph != want {
		t.Fatalf("PUBLIC_ORIGIN not collapsed onto all surfaces: %+v", cfg.Origins)
	}
	if !strings.HasPrefix(cfg.Issuer, want+"/") {
		t.Fatalf("issuer should derive from PUBLIC_ORIGIN: %q", cfg.Issuer)
	}
}

// TestPerSurfaceOriginOverrides: each LOGIN/PORTAL/GRAPH_ORIGIN wins over the
// derived default independently.
func TestPerSurfaceOriginOverrides(t *testing.T) {
	cfg, err := Load(envFunc(map[string]string{
		"LOGIN_ORIGIN":  "https://login.acme.test",
		"PORTAL_ORIGIN": "https://portal.acme.test",
		"GRAPH_ORIGIN":  "https://graph.acme.test",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Origins.Login != "https://login.acme.test" {
		t.Fatalf("login override: %q", cfg.Origins.Login)
	}
	if cfg.Origins.Portal != "https://portal.acme.test" {
		t.Fatalf("portal override: %q", cfg.Origins.Portal)
	}
	if cfg.Origins.Graph != "https://graph.acme.test" {
		t.Fatalf("graph override: %q", cfg.Origins.Graph)
	}
	// Issuer still derives from the (overridden) login origin.
	if !strings.HasPrefix(cfg.Issuer, "https://login.acme.test/") {
		t.Fatalf("issuer should follow login override: %q", cfg.Issuer)
	}
}

// TestIssuerOverride: explicit ISSUER wins over derivation.
func TestIssuerOverride(t *testing.T) {
	cfg, err := Load(envFunc(map[string]string{"ISSUER": "https://issuer.acme.test/tenant/v2.0"}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Issuer != "https://issuer.acme.test/tenant/v2.0" {
		t.Fatalf("ISSUER override not applied: %q", cfg.Issuer)
	}
}

// TestLocalDomainsParsing: comma list is split, trimmed, lowercased; blanks
// dropped.
func TestLocalDomainsParsing(t *testing.T) {
	cfg, err := Load(envFunc(map[string]string{"LOCAL_DOMAINS": " Foo.test , ,BAR.test "}))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"foo.test", "bar.test"}
	if len(cfg.LocalDomains) != len(want) {
		t.Fatalf("LocalDomains = %v", cfg.LocalDomains)
	}
	for i, d := range want {
		if cfg.LocalDomains[i] != d {
			t.Fatalf("LocalDomains[%d] = %q, want %q", i, cfg.LocalDomains[i], d)
		}
	}
}

// TestTLSEnvOverrides exercises TLS_CERT/TLS_KEY (both set = valid) and
// TLS_CERT_DIR overriding the default.
func TestTLSEnvOverrides(t *testing.T) {
	cfg, err := Load(envFunc(map[string]string{
		"TLS_CERT":     "/etc/certs/cert.pem",
		"TLS_KEY":      "/etc/certs/key.pem",
		"TLS_CERT_DIR": "/custom/tls",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLSCertPath != "/etc/certs/cert.pem" || cfg.TLSKeyPath != "/etc/certs/key.pem" {
		t.Fatalf("TLS cert/key env not applied: %+v", cfg)
	}
	if cfg.TLSCertDir != "/custom/tls" {
		t.Fatalf("TLS_CERT_DIR not applied: %q", cfg.TLSCertDir)
	}
}

// TestFileTLSAndLifetimes drives the file-based tls block, token lifetimes,
// and other pointer-backed fields (fileTLS, fileTLifetimes, boolFrom, ltp).
func TestFileTLSAndLifetimes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	body := `{
	  "tls": {"enabled": false, "certPath": "/f/cert.pem", "keyPath": "/f/key.pem", "certDir": "/f/tls"},
	  "tokenLifetimes": {"authCode": 111, "idToken": 222, "accessToken": 333, "refreshToken": 444, "deviceCode": 555},
	  "deviceCodeInterval": 7,
	  "requirePassword": true,
	  "requireConsent": true,
	  "seedOnStart": false,
	  "localDomains": "a.test,b.test",
	  "graphResourceId": "https://graph.file.test"
	}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(envFunc(map[string]string{"CONFIG_FILE": path}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLSEnabled {
		t.Fatal("file tls.enabled=false should disable TLS")
	}
	if cfg.TLSCertPath != "/f/cert.pem" || cfg.TLSKeyPath != "/f/key.pem" || cfg.TLSCertDir != "/f/tls" {
		t.Fatalf("file TLS paths not applied: %+v", cfg)
	}
	if cfg.Lifetimes.AuthCode != 111 || cfg.Lifetimes.IDToken != 222 || cfg.Lifetimes.AccessToken != 333 ||
		cfg.Lifetimes.RefreshToken != 444 || cfg.Lifetimes.DeviceCode != 555 {
		t.Fatalf("file token lifetimes not applied: %+v", cfg.Lifetimes)
	}
	if cfg.DeviceInterval != 7 {
		t.Fatalf("file deviceCodeInterval not applied: %d", cfg.DeviceInterval)
	}
	if !cfg.RequirePassword || !cfg.RequireConsent || cfg.SeedOnStart {
		t.Fatalf("file bool fields not applied: %+v", cfg)
	}
	if len(cfg.LocalDomains) != 2 || cfg.LocalDomains[0] != "a.test" {
		t.Fatalf("file localDomains not applied: %v", cfg.LocalDomains)
	}
	if cfg.GraphResourceID != "https://graph.file.test" {
		t.Fatalf("file graphResourceId not applied: %q", cfg.GraphResourceID)
	}
	// TLS disabled => http scheme in derived subdomain origins.
	if !strings.HasPrefix(cfg.Origins.Login, "http://login.") {
		t.Fatalf("scheme should be http with tls disabled: %q", cfg.Origins.Login)
	}
}

// TestResolveBoolVariants covers each accepted literal plus the invalid case.
func TestResolveBoolVariants(t *testing.T) {
	truthy := []string{"true", "1", "yes", "TRUE", "Yes"}
	for _, v := range truthy {
		cfg, err := Load(envFunc(map[string]string{"REQUIRE_CONSENT": v}))
		if err != nil {
			t.Fatalf("%q should parse: %v", v, err)
		}
		if !cfg.RequireConsent {
			t.Fatalf("%q should be truthy", v)
		}
	}
	falsy := []string{"false", "0", "no", "NO"}
	for _, v := range falsy {
		cfg, err := Load(envFunc(map[string]string{"SEED_ON_START": v}))
		if err != nil {
			t.Fatalf("%q should parse: %v", v, err)
		}
		if cfg.SeedOnStart {
			t.Fatalf("%q should be falsy", v)
		}
	}
	if _, err := Load(envFunc(map[string]string{"TLS_ENABLED": "maybe"})); err == nil ||
		!strings.Contains(err.Error(), "TLS_ENABLED") {
		t.Fatalf("invalid boolean should fail on TLS_ENABLED: %v", err)
	}
}

// TestResolveIntInvalid covers the non-integer env failure path.
func TestResolveIntInvalid(t *testing.T) {
	_, err := Load(envFunc(map[string]string{"PORT": "notanint"}))
	if err == nil || !strings.Contains(err.Error(), "PORT") {
		t.Fatalf("non-integer PORT should fail: %v", err)
	}
	_, err = Load(envFunc(map[string]string{"DEVICE_CODE_INTERVAL_SECONDS": "abc"}))
	if err == nil || !strings.Contains(err.Error(), "DEVICE_CODE_INTERVAL_SECONDS") {
		t.Fatalf("non-integer interval should fail: %v", err)
	}
}

// TestInvalidOriginURL exercises the absolute-URL validation on origins/issuer.
func TestInvalidOriginURL(t *testing.T) {
	_, err := Load(envFunc(map[string]string{"LOGIN_ORIGIN": "not a url"}))
	if err == nil || !strings.Contains(err.Error(), "LOGIN_ORIGIN") {
		t.Fatalf("invalid LOGIN_ORIGIN should fail: %v", err)
	}
	_, err = Load(envFunc(map[string]string{"ISSUER": "://missing-scheme"}))
	if err == nil || !strings.Contains(err.Error(), "ISSUER") {
		t.Fatalf("invalid ISSUER should fail: %v", err)
	}
}

// TestReadFileGenericError: a CONFIG_FILE that points at a directory triggers
// the non-IsNotExist read error branch.
func TestReadFileGenericError(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(envFunc(map[string]string{"CONFIG_FILE": dir})); err == nil ||
		!strings.Contains(err.Error(), "CONFIG_FILE") {
		t.Fatalf("reading a directory as CONFIG_FILE should error: %v", err)
	}
}

// TestManagedIdentityAndConsentDefaults locks the managed-identity defaults
// and overrides.
func TestManagedIdentityOverrides(t *testing.T) {
	cfg, err := Load(envFunc(map[string]string{
		"MANAGED_IDENTITY_SECRET":    "custom-secret",
		"MANAGED_IDENTITY_CLIENT_ID": "AAAAAAAA-0000-0000-0000-000000000009",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ManagedIdentitySecret != "custom-secret" {
		t.Fatalf("managed identity secret override: %q", cfg.ManagedIdentitySecret)
	}
	// Client id is lowercased.
	if cfg.ManagedIdentityClientID != "aaaaaaaa-0000-0000-0000-000000000009" {
		t.Fatalf("managed identity client id not lowercased: %q", cfg.ManagedIdentityClientID)
	}
}

// TestMultipleValidationErrorsAggregated verifies several failures surface in
// one error string.
func TestMultipleValidationErrorsAggregated(t *testing.T) {
	_, err := Load(envFunc(map[string]string{
		"TENANT_ID":   "bad",
		"PORT":        "0",
		"ORIGIN_MODE": "nope",
	}))
	if err == nil {
		t.Fatal("expected aggregated errors")
	}
	for _, want := range []string{"TENANT_ID", "PORT", "ORIGIN_MODE"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("aggregated error missing %q: %v", want, err)
		}
	}
}
