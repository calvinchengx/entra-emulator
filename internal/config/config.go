// Package config loads and validates emulator configuration with precedence
// environment > config file > defaults (see docs/02-configuration.md).
package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

const (
	DefaultTenantID   = "11111111-1111-1111-1111-111111111111"
	DefaultBaseDomain = "entra.localhost"
	DefaultConfigFile = "./entra-emulator.config.json"
	// DefaultManagedIdentityClientID is the seeded daemon app — the default
	// system-assigned managed identity (matches store.SeedAppDaemonID).
	DefaultManagedIdentityClientID = "cccccccc-0000-0000-0000-000000000002"
)

type TokenLifetimes struct {
	AuthCode     int `json:"authCode"`
	IDToken      int `json:"idToken"`
	AccessToken  int `json:"accessToken"`
	RefreshToken int `json:"refreshToken"`
	DeviceCode   int `json:"deviceCode"`
}

type Origins struct {
	Login  string
	Portal string
	Graph  string
}

// Config is the frozen, validated configuration read by every package.
type Config struct {
	Host            string
	Port            int
	TenantID        string
	OriginMode      string // subdomains | compat
	BaseDomain      string
	LocalDomains    []string
	Origins         Origins
	Issuer          string
	DBPath          string
	TLSEnabled      bool
	TLSCertPath     string // custom pair; empty = auto
	TLSKeyPath      string
	TLSCertDir      string
	RequirePassword bool
	RequireConsent  bool
	SeedOnStart     bool
	Lifetimes       TokenLifetimes
	DeviceInterval  int
	GraphResourceID string
	LogLevel        string

	// Managed-identity emulation (App Service protocol; roadmap #3).
	ManagedIdentitySecret   string // matched against the X-IDENTITY-HEADER
	ManagedIdentityClientID string // the system-assigned identity's appId
}

// fileConfig mirrors the JSON config file shape.
type fileConfig struct {
	Host            *string         `json:"host"`
	Port            *int            `json:"port"`
	TenantID        *string         `json:"tenantId"`
	OriginMode      *string         `json:"originMode"`
	BaseDomain      *string         `json:"baseDomain"`
	LocalDomains    *string         `json:"localDomains"`
	PublicOrigin    *string         `json:"publicOrigin"`
	LoginOrigin     *string         `json:"loginOrigin"`
	PortalOrigin    *string         `json:"portalOrigin"`
	GraphOrigin     *string         `json:"graphOrigin"`
	Issuer          *string         `json:"issuer"`
	DBPath          *string         `json:"dbPath"`
	RequirePassword *bool           `json:"requirePassword"`
	RequireConsent  *bool           `json:"requireConsent"`
	SeedOnStart     *bool           `json:"seedOnStart"`
	DeviceInterval  *int            `json:"deviceCodeInterval"`
	GraphResourceID *string         `json:"graphResourceId"`
	LogLevel        *string         `json:"logLevel"`
	TLS             *fileTLS        `json:"tls"`
	TokenLifetimes  *fileTLifetimes `json:"tokenLifetimes"`

	ManagedIdentitySecret   *string `json:"managedIdentitySecret"`
	ManagedIdentityClientID *string `json:"managedIdentityClientId"`
}

type fileTLS struct {
	Enabled  *bool   `json:"enabled"`
	CertPath *string `json:"certPath"`
	KeyPath  *string `json:"keyPath"`
	CertDir  *string `json:"certDir"`
}

type fileTLifetimes struct {
	AuthCode     *int `json:"authCode"`
	IDToken      *int `json:"idToken"`
	AccessToken  *int `json:"accessToken"`
	RefreshToken *int `json:"refreshToken"`
	DeviceCode   *int `json:"deviceCode"`
}

var guidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Load resolves configuration from the environment and optional config file.
// Every validation failure is reported; callers exit non-zero on error.
func Load(getenv func(string) string) (*Config, error) {
	file, err := readFile(pick(getenv("CONFIG_FILE"), DefaultConfigFile))
	if err != nil {
		return nil, err
	}

	var errs []string
	fail := func(key, msg string) { errs = append(errs, fmt.Sprintf("%s: %s", key, msg)) }

	c := &Config{
		Host:            resolveStr(getenv("HOST"), file.Host, "localhost"),
		TenantID:        strings.ToLower(resolveStr(getenv("TENANT_ID"), file.TenantID, DefaultTenantID)),
		OriginMode:      resolveStr(getenv("ORIGIN_MODE"), file.OriginMode, "subdomains"),
		BaseDomain:      resolveStr(getenv("BASE_DOMAIN"), file.BaseDomain, DefaultBaseDomain),
		DBPath:          resolveStr(getenv("DB_PATH"), file.DBPath, "./data/entra-emulator.db"),
		TLSCertDir:      "./data/tls",
		GraphResourceID: resolveStr(getenv("GRAPH_RESOURCE_ID"), file.GraphResourceID, "https://graph.microsoft.com"),
		LogLevel:        resolveStr(getenv("LOG_LEVEL"), file.LogLevel, "info"),
		// Public dev value, like the seeded secrets — documented insecure.
		ManagedIdentitySecret:   resolveStr(getenv("MANAGED_IDENTITY_SECRET"), file.ManagedIdentitySecret, "managed-identity-secret"),
		ManagedIdentityClientID: strings.ToLower(resolveStr(getenv("MANAGED_IDENTITY_CLIENT_ID"), file.ManagedIdentityClientID, DefaultManagedIdentityClientID)),
	}

	c.Port = resolveInt(getenv("PORT"), intp(file.Port), 8443, "PORT", fail)
	c.DeviceInterval = resolveInt(getenv("DEVICE_CODE_INTERVAL_SECONDS"), intp(file.DeviceInterval), 5, "DEVICE_CODE_INTERVAL_SECONDS", fail)
	c.TLSEnabled = resolveBool(getenv("TLS_ENABLED"), boolFrom(file.TLS, func(t *fileTLS) *bool { return t.Enabled }), true, "TLS_ENABLED", fail)
	c.RequirePassword = resolveBool(getenv("REQUIRE_PASSWORD"), file.RequirePassword, false, "REQUIRE_PASSWORD", fail)
	c.RequireConsent = resolveBool(getenv("REQUIRE_CONSENT"), file.RequireConsent, false, "REQUIRE_CONSENT", fail)
	c.SeedOnStart = resolveBool(getenv("SEED_ON_START"), file.SeedOnStart, true, "SEED_ON_START", fail)

	if file.TLS != nil {
		if file.TLS.CertPath != nil {
			c.TLSCertPath = *file.TLS.CertPath
		}
		if file.TLS.KeyPath != nil {
			c.TLSKeyPath = *file.TLS.KeyPath
		}
		if file.TLS.CertDir != nil {
			c.TLSCertDir = *file.TLS.CertDir
		}
	}
	if v := getenv("TLS_CERT"); v != "" {
		c.TLSCertPath = v
	}
	if v := getenv("TLS_KEY"); v != "" {
		c.TLSKeyPath = v
	}
	if v := getenv("TLS_CERT_DIR"); v != "" {
		c.TLSCertDir = v
	}

	lf := &TokenLifetimes{}
	fileLT := file.TokenLifetimes
	lf.AuthCode = resolveInt(getenv("TOKEN_LIFETIME_AUTH_CODE_SECONDS"), ltp(fileLT, func(t *fileTLifetimes) *int { return t.AuthCode }), 300, "TOKEN_LIFETIME_AUTH_CODE_SECONDS", fail)
	lf.IDToken = resolveInt(getenv("TOKEN_LIFETIME_ID_SECONDS"), ltp(fileLT, func(t *fileTLifetimes) *int { return t.IDToken }), 3600, "TOKEN_LIFETIME_ID_SECONDS", fail)
	lf.AccessToken = resolveInt(getenv("TOKEN_LIFETIME_ACCESS_SECONDS"), ltp(fileLT, func(t *fileTLifetimes) *int { return t.AccessToken }), 3600, "TOKEN_LIFETIME_ACCESS_SECONDS", fail)
	lf.RefreshToken = resolveInt(getenv("TOKEN_LIFETIME_REFRESH_SECONDS"), ltp(fileLT, func(t *fileTLifetimes) *int { return t.RefreshToken }), 86400, "TOKEN_LIFETIME_REFRESH_SECONDS", fail)
	lf.DeviceCode = resolveInt(getenv("TOKEN_LIFETIME_DEVICE_CODE_SECONDS"), ltp(fileLT, func(t *fileTLifetimes) *int { return t.DeviceCode }), 900, "TOKEN_LIFETIME_DEVICE_CODE_SECONDS", fail)
	c.Lifetimes = *lf

	if raw := resolveStr(getenv("LOCAL_DOMAINS"), file.LocalDomains, ""); raw != "" {
		for _, d := range strings.Split(raw, ",") {
			if d = strings.TrimSpace(d); d != "" {
				c.LocalDomains = append(c.LocalDomains, strings.ToLower(d))
			}
		}
	}

	// --- Validation ---
	if !guidRe.MatchString(c.TenantID) {
		fail("TENANT_ID", "must be a GUID")
	}
	if c.Port < 1 || c.Port > 65535 {
		fail("PORT", "must be 1-65535")
	}
	if c.OriginMode != "subdomains" && c.OriginMode != "compat" {
		fail("ORIGIN_MODE", `must be "subdomains" or "compat"`)
	}
	if (c.TLSCertPath == "") != (c.TLSKeyPath == "") {
		fail("TLS_CERT/TLS_KEY", "set both or neither")
	}
	for k, v := range map[string]int{
		"TOKEN_LIFETIME_AUTH_CODE_SECONDS": lf.AuthCode, "TOKEN_LIFETIME_ID_SECONDS": lf.IDToken,
		"TOKEN_LIFETIME_ACCESS_SECONDS": lf.AccessToken, "TOKEN_LIFETIME_REFRESH_SECONDS": lf.RefreshToken,
		"TOKEN_LIFETIME_DEVICE_CODE_SECONDS": lf.DeviceCode, "DEVICE_CODE_INTERVAL_SECONDS": c.DeviceInterval,
	} {
		if v < 1 {
			fail(k, "must be a positive integer")
		}
	}

	// --- Origin derivation (per-surface override > PUBLIC_ORIGIN > compat > subdomains) ---
	scheme := "https"
	if !c.TLSEnabled {
		scheme = "http"
	}
	publicOrigin := resolveStr(getenv("PUBLIC_ORIGIN"), file.PublicOrigin, "")
	collapse := publicOrigin
	if collapse == "" && c.OriginMode == "compat" {
		collapse = fmt.Sprintf("%s://localhost:%d", scheme, c.Port)
	}
	derive := func(sub string) string {
		if collapse != "" {
			return collapse
		}
		return fmt.Sprintf("%s://%s.%s:%d", scheme, sub, c.BaseDomain, c.Port)
	}
	c.Origins = Origins{
		Login:  resolveStr(getenv("LOGIN_ORIGIN"), file.LoginOrigin, derive("login")),
		Portal: resolveStr(getenv("PORTAL_ORIGIN"), file.PortalOrigin, derive("portal")),
		Graph:  resolveStr(getenv("GRAPH_ORIGIN"), file.GraphOrigin, derive("graph")),
	}
	c.Issuer = resolveStr(getenv("ISSUER"), file.Issuer, c.Origins.Login+"/"+c.TenantID+"/v2.0")

	for key, u := range map[string]string{
		"LOGIN_ORIGIN": c.Origins.Login, "PORTAL_ORIGIN": c.Origins.Portal,
		"GRAPH_ORIGIN": c.Origins.Graph, "ISSUER": c.Issuer,
	} {
		if parsed, err := url.Parse(u); err != nil || parsed.Scheme == "" || parsed.Host == "" {
			fail(key, fmt.Sprintf("not a valid absolute URL: %q", u))
		}
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("invalid configuration:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return c, nil
}

func readFile(path string) (*fileConfig, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &fileConfig{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("CONFIG_FILE: %w", err)
	}
	var fc fileConfig
	if err := json.Unmarshal(raw, &fc); err != nil {
		return nil, fmt.Errorf("CONFIG_FILE %s: invalid JSON: %w", path, err)
	}
	return &fc, nil
}

func pick(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

func resolveStr(env string, file *string, def string) string {
	if env != "" {
		return env
	}
	if file != nil && *file != "" {
		return *file
	}
	return def
}

func resolveInt(env string, file *int, def int, key string, fail func(string, string)) int {
	if env != "" {
		n, err := strconv.Atoi(env)
		if err != nil {
			fail(key, fmt.Sprintf("not an integer: %q", env))
			return def
		}
		return n
	}
	if file != nil {
		return *file
	}
	return def
}

func resolveBool(env string, file *bool, def bool, key string, fail func(string, string)) bool {
	if env != "" {
		switch strings.ToLower(env) {
		case "true", "1", "yes":
			return true
		case "false", "0", "no":
			return false
		default:
			fail(key, fmt.Sprintf("not a boolean: %q", env))
			return def
		}
	}
	if file != nil {
		return *file
	}
	return def
}

func intp(p *int) *int { return p }

func boolFrom(t *fileTLS, get func(*fileTLS) *bool) *bool {
	if t == nil {
		return nil
	}
	return get(t)
}

func ltp(t *fileTLifetimes, get func(*fileTLifetimes) *int) *int {
	if t == nil {
		return nil
	}
	return get(t)
}
