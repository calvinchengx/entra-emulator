// Package emulator embeds the Entra Emulator in-process so Go tests can run
// real OIDC/OAuth flows against it with zero external processes.
//
//	emu, err := emulator.Start()
//	defer emu.Close()
//	// point MSAL Go / azidentity at emu.Authority() with emu.HTTPClient()
//
// or, in a test, with automatic cleanup:
//
//	emu := emulator.StartT(t)
//	resp, _ := emu.HTTPClient().Get(emu.Origin + "/health")
//
// The returned Emulator exposes the advertised issuer/authority, a *http.Client
// that trusts the instance (and reaches its listener), and the seeded client
// IDs/secrets so tests need no hard-coded fixtures.
package emulator

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	"github.com/calvinchengx/entra-emulator/internal/config"
	"github.com/calvinchengx/entra-emulator/internal/server"
	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tlscert"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// Seed identifiers — the deterministic directory every instance boots with
// (docs/06-data-model-and-seed.md). Re-exported so callers avoid magic strings.
const (
	TenantID = config.DefaultTenantID

	SPAClientID    = store.SeedAppSPAID    // public SPA (PKCE, device code)
	DaemonClientID = store.SeedAppDaemonID // confidential daemon (client credentials)
	DaemonSecret   = store.SeedDaemonSecret

	AliceOID = store.SeedUserAliceID
	BobOID   = store.SeedUserBobID
	Password = store.SeedPassword

	AliceUPN = "alice@entraemulator.dev"
	BobUPN   = "bob@entraemulator.dev"
)

// Emulator is a running in-process instance.
type Emulator struct {
	// Origin is the base URL of the instance (scheme://host:port).
	Origin string
	// Issuer is the token/discovery issuer (GUID-form).
	Issuer string
	// TenantID is the fixed tenant GUID.
	TenantID string

	srv     *httptest.Server
	st      *store.Store
	dataDir string
	cleanup []func()
}

// Options configures Start. The zero value is the default: an HTTP listener,
// seeded directory, compat origin.
type Options struct {
	// TLS serves HTTPS with a self-signed cert (HTTPClient trusts it).
	TLS bool
	// NoSeed skips the deterministic seed (empty directory).
	NoSeed bool
	// RequirePassword enables the password sign-in form instead of the picker.
	RequirePassword bool
	// TenantID overrides the default tenant GUID.
	TenantID string
}

// Option mutates Options.
type Option func(*Options)

// WithTLS serves over HTTPS.
func WithTLS() Option { return func(o *Options) { o.TLS = true } }

// WithoutSeed boots an empty directory.
func WithoutSeed() Option { return func(o *Options) { o.NoSeed = true } }

// WithRequirePassword enables password sign-in.
func WithRequirePassword() Option { return func(o *Options) { o.RequirePassword = true } }

// WithTenantID overrides the tenant GUID.
func WithTenantID(id string) Option { return func(o *Options) { o.TenantID = id } }

// Start boots an instance. Call Close to release it.
func Start(opts ...Option) (*Emulator, error) {
	o := Options{}
	for _, fn := range opts {
		fn(&o)
	}

	dataDir, err := os.MkdirTemp("", "entra-emulator-*")
	if err != nil {
		return nil, err
	}

	scheme := "http"
	if o.TLS {
		scheme = "https"
	}
	tenantID := o.TenantID
	if tenantID == "" {
		tenantID = config.DefaultTenantID
	}

	getenv := func(k string) string {
		switch k {
		case "DB_PATH":
			return filepath.Join(dataDir, "emulator.db")
		case "TLS_CERT_DIR":
			return filepath.Join(dataDir, "tls")
		case "TLS_ENABLED":
			if o.TLS {
				return "true"
			}
			return "false"
		case "ORIGIN_MODE":
			return "compat"
		case "TENANT_ID":
			return tenantID
		case "REQUIRE_PASSWORD":
			if o.RequirePassword {
				return "true"
			}
			return "false"
		case "SEED_ON_START":
			return "false" // we seed explicitly below for a clear error path
		}
		return ""
	}

	cfg, err := config.Load(getenv)
	if err != nil {
		os.RemoveAll(dataDir)
		return nil, err
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		os.RemoveAll(dataDir)
		return nil, err
	}
	// The tenant is infrastructure the signing key depends on; ensure it even
	// when the directory seed is skipped.
	if err := st.EnsureTenant(cfg.TenantID, cfg.Issuer); err != nil {
		st.Close()
		os.RemoveAll(dataDir)
		return nil, err
	}
	if !o.NoSeed {
		if _, err := st.Seed(cfg.TenantID, cfg.Issuer); err != nil {
			st.Close()
			os.RemoveAll(dataDir)
			return nil, fmt.Errorf("seed: %w", err)
		}
	}

	signer, err := tokens.EnsureActiveKey(st, cfg.TenantID)
	if err != nil {
		st.Close()
		os.RemoveAll(dataDir)
		return nil, err
	}
	ts := &tokens.Service{Store: st, Signer: signer, Cfg: cfg}

	var cert *tlscert.Material
	if o.TLS {
		cert, err = tlscert.LoadOrCreate(cfg.TLSCertDir, cfg.BaseDomain, cfg.LocalDomains)
		if err != nil {
			st.Close()
			os.RemoveAll(dataDir)
			return nil, err
		}
	}

	handler := server.New(cfg, st, ts, cert, "embedded").Handler
	var hts *httptest.Server
	if o.TLS {
		hts = httptest.NewTLSServer(handler)
	} else {
		hts = httptest.NewServer(handler)
	}

	// Re-point advertised origins at the ephemeral listener so discovery,
	// issuer and token `iss` all agree with the URL clients actually use.
	cfg.Origins = config.Origins{Login: hts.URL, Portal: hts.URL, Graph: hts.URL}
	cfg.Issuer = hts.URL + "/" + cfg.TenantID + "/v2.0"

	_ = scheme
	return &Emulator{
		Origin:   hts.URL,
		Issuer:   cfg.Issuer,
		TenantID: cfg.TenantID,
		srv:      hts,
		st:       st,
		dataDir:  dataDir,
	}, nil
}

// tb is the minimal testing.TB surface StartT needs (satisfied by *testing.T
// and *testing.B) — declared locally so this package never imports testing.
type tb interface {
	Helper()
	Fatalf(format string, args ...any)
	Cleanup(func())
}

// StartT boots an instance and registers Close via t.Cleanup. It fails the
// test on error.
func StartT(t tb, opts ...Option) *Emulator {
	t.Helper()
	emu, err := Start(opts...)
	if err != nil {
		t.Fatalf("emulator.StartT: %v", err)
	}
	t.Cleanup(emu.Close)
	return emu
}

// Close stops the instance and removes its data directory.
func (e *Emulator) Close() {
	for _, fn := range e.cleanup {
		fn()
	}
	if e.srv != nil {
		e.srv.Close()
	}
	if e.st != nil {
		e.st.Close()
	}
	if e.dataDir != "" {
		os.RemoveAll(e.dataDir)
	}
}

// Authority is the MSAL authority URL (origin + tenant).
func (e *Emulator) Authority() string {
	return e.Origin + "/" + e.TenantID
}

// JWKSURL is the JWKS endpoint.
func (e *Emulator) JWKSURL() string {
	return e.Origin + "/" + e.TenantID + "/discovery/v2.0/keys"
}

// DiscoveryURL is the OIDC discovery document endpoint.
func (e *Emulator) DiscoveryURL() string {
	return e.Origin + "/" + e.TenantID + "/v2.0/.well-known/openid-configuration"
}

// HTTPClient returns a client that reaches this instance and, under TLS,
// trusts its self-signed certificate.
func (e *Emulator) HTTPClient() *http.Client {
	return e.srv.Client()
}

// Store exposes the underlying directory for advanced fixture setup
// (creating users/apps, approving device codes, etc.).
func (e *Emulator) Store() *store.Store {
	return e.st
}
