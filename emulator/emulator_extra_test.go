package emulator_test

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/calvinchengx/entra-emulator/emulator"
)

// TestWithTenantIDOption verifies the tenant override flows into every
// advertised URL and the health/discovery documents.
func TestWithTenantIDOption(t *testing.T) {
	custom := "22222222-2222-2222-2222-222222222222"
	emu := emulator.StartT(t, emulator.WithTenantID(custom))

	if emu.TenantID != custom {
		t.Fatalf("TenantID override not applied: %q", emu.TenantID)
	}
	if !strings.Contains(emu.Authority(), custom) {
		t.Fatalf("Authority should embed custom tenant: %q", emu.Authority())
	}
	if !strings.Contains(emu.Issuer, custom) {
		t.Fatalf("Issuer should embed custom tenant: %q", emu.Issuer)
	}
	if !strings.Contains(emu.JWKSURL(), custom) || !strings.Contains(emu.DiscoveryURL(), custom) {
		t.Fatalf("JWKS/Discovery should embed custom tenant")
	}

	resp, err := emu.HTTPClient().Get(emu.Origin + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("health under custom tenant: want 200, got %d", resp.StatusCode)
	}
	var health map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&health)
	if health["tenantId"] != custom {
		t.Fatalf("health tenantId mismatch: %v", health["tenantId"])
	}
}

// TestWithRequirePasswordOption exercises the password-form construction
// branch. The instance must still boot and serve discovery.
func TestWithRequirePasswordOption(t *testing.T) {
	emu := emulator.StartT(t, emulator.WithRequirePassword())

	resp, err := emu.HTTPClient().Get(emu.DiscoveryURL())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("discovery: want 200, got %d", resp.StatusCode)
	}
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	if doc["issuer"] != emu.Issuer {
		t.Fatalf("issuer mismatch under RequirePassword: %v", doc["issuer"])
	}
}

// TestSeedConstantsExposed asserts every re-exported seed identifier is
// non-empty and internally consistent so callers can rely on them.
func TestSeedConstantsExposed(t *testing.T) {
	consts := map[string]string{
		"TenantID":       emulator.TenantID,
		"SPAClientID":    emulator.SPAClientID,
		"DaemonClientID": emulator.DaemonClientID,
		"DaemonSecret":   emulator.DaemonSecret,
		"AliceOID":       emulator.AliceOID,
		"BobOID":         emulator.BobOID,
		"Password":       emulator.Password,
		"AliceUPN":       emulator.AliceUPN,
		"BobUPN":         emulator.BobUPN,
	}
	for name, v := range consts {
		if v == "" {
			t.Errorf("seed constant %s is empty", name)
		}
	}
	if !strings.HasSuffix(emulator.AliceUPN, "@entraemulator.dev") {
		t.Fatalf("AliceUPN unexpected: %q", emulator.AliceUPN)
	}
}

// TestAccessorsWellFormed checks Authority/Issuer/JWKSURL/DiscoveryURL are
// absolute URLs rooted at Origin.
func TestAccessorsWellFormed(t *testing.T) {
	emu := emulator.StartT(t)

	for name, raw := range map[string]string{
		"Authority":    emu.Authority(),
		"Issuer":       emu.Issuer,
		"JWKSURL":      emu.JWKSURL(),
		"DiscoveryURL": emu.DiscoveryURL(),
	} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			t.Fatalf("%s is not a well-formed absolute URL: %q (%v)", name, raw, err)
		}
		if !strings.HasPrefix(raw, emu.Origin) {
			t.Fatalf("%s should be rooted at Origin %q: %q", name, emu.Origin, raw)
		}
	}
}

// TestBobSeeded confirms the second seed user is reachable via Store.
func TestBobSeeded(t *testing.T) {
	emu := emulator.StartT(t)
	u, err := emu.Store().GetUser(emulator.BobOID)
	if err != nil {
		t.Fatal(err)
	}
	if u.UserPrincipalName != emulator.BobUPN {
		t.Fatalf("Bob UPN mismatch: %q", u.UserPrincipalName)
	}
}

// TestCloseIsIdempotent ensures Close can run without panicking beyond the
// automatic t.Cleanup registration.
func TestCloseIsIdempotent(t *testing.T) {
	emu, err := emulator.Start()
	if err != nil {
		t.Fatal(err)
	}
	emu.Close()
	// A second Close must not panic (srv/store already released).
	emu.Close()
}

// TestStartWithoutHelper exercises the plain Start (no *testing.T) path and
// its accessors, closing manually.
func TestStartWithoutHelper(t *testing.T) {
	emu, err := emulator.Start(emulator.WithTenantID("33333333-3333-3333-3333-333333333333"))
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer emu.Close()

	if emu.HTTPClient() == nil {
		t.Fatal("HTTPClient must not be nil")
	}
	resp, err := emu.HTTPClient().Get(emu.Origin + "/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("health: want 200, got %d", resp.StatusCode)
	}
}

// fakeTB captures the testing.TB surface StartT relies on so we can assert on
// its failure path without failing the real test.
type fakeTB struct {
	fatal    bool
	cleanups []func()
}

func (f *fakeTB) Helper()               {}
func (f *fakeTB) Fatalf(string, ...any) { f.fatal = true; panic("fatal") }
func (f *fakeTB) Cleanup(fn func())     { f.cleanups = append(f.cleanups, fn) }

// TestStartInvalidTenantErrors drives Start's config.Load error branch: an
// invalid tenant GUID fails validation, and the temp dir is cleaned up.
func TestStartInvalidTenantErrors(t *testing.T) {
	emu, err := emulator.Start(emulator.WithTenantID("not-a-guid"))
	if err == nil {
		emu.Close()
		t.Fatal("invalid tenant should make Start fail")
	}
	if !strings.Contains(err.Error(), "TENANT_ID") {
		t.Fatalf("error should mention TENANT_ID: %v", err)
	}
}

// TestStartTFatalOnError verifies StartT calls Fatalf (not return) when Start
// errors, using a fake TB to catch the fatal.
func TestStartTFatalOnError(t *testing.T) {
	f := &fakeTB{}
	defer func() {
		_ = recover() // Fatalf panics in our fake; swallow it.
		if !f.fatal {
			t.Fatal("StartT should have called Fatalf on Start error")
		}
	}()
	emulator.StartT(f, emulator.WithTenantID("also-not-a-guid"))
	t.Fatal("StartT should not return on error")
}

// TestStartTRegistersCleanup confirms the happy path registers exactly one
// cleanup (Close) on the TB.
func TestStartTRegistersCleanup(t *testing.T) {
	f := &fakeTB{}
	emu := emulator.StartT(f)
	if f.fatal {
		t.Fatal("StartT should not fail on the happy path")
	}
	if len(f.cleanups) != 1 {
		t.Fatalf("StartT should register one cleanup, got %d", len(f.cleanups))
	}
	// Run the registered cleanup (Close) ourselves since our fake TB won't.
	for _, fn := range f.cleanups {
		fn()
	}
	_ = emu
}

// TestTLSWithoutSeedCombination covers the TLS construction branch combined
// with an empty directory (both option branches at once).
func TestTLSWithoutSeedCombination(t *testing.T) {
	emu := emulator.StartT(t, emulator.WithTLS(), emulator.WithoutSeed())

	if !strings.HasPrefix(emu.Origin, "https://") {
		t.Fatalf("expected https origin: %q", emu.Origin)
	}
	seeded, err := emu.Store().IsSeeded()
	if err != nil {
		t.Fatal(err)
	}
	if seeded {
		t.Fatal("WithoutSeed under TLS should leave directory empty")
	}
	resp, err := emu.HTTPClient().Get(emu.JWKSURL())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("jwks over TLS: want 200, got %d", resp.StatusCode)
	}
}
