package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/config"
	"github.com/calvinchengx/entra-emulator/internal/manifest"
	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// TestManifestDirectoryIssuesTokens: apps, secrets, users, scopes and role
// assignments from the sample manifest work at the token endpoint, under the
// manifest's tenant.
func TestManifestDirectoryIssuesTokens(t *testing.T) {
	dir := t.TempDir()
	cfg, err := config.Load(func(k string) string {
		return map[string]string{
			"CONFIG_FILE":   filepath.Join(dir, "absent.json"),
			"MANIFEST_FILE": "../../samples/manifest/entra-emulator.manifest.json",
			"DB_PATH":       filepath.Join(dir, "m.db"),
			"TLS_ENABLED":   "false",
			"ORIGIN_MODE":   "compat",
		}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.EnsureTenant(cfg.TenantID, cfg.Issuer); err != nil {
		t.Fatal(err)
	}
	if err := manifest.Apply(st, cfg.Manifest); err != nil {
		t.Fatal(err)
	}
	signer, err := tokens.EnsureActiveKey(st, cfg.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	hts := httptest.NewServer(New(cfg, st, &tokens.Service{Store: st, Signer: signer, Cfg: cfg}, nil, "test").Handler)
	t.Cleanup(hts.Close)
	cfg.Origins = config.Origins{Login: hts.URL, Portal: hts.URL, Graph: hts.URL}
	cfg.Issuer = hts.URL + "/" + cfg.TenantID + "/v2.0"
	tokenURL := hts.URL + "/" + cfg.TenantID + "/oauth2/v2.0/token"

	// Client credentials: the worker's manifest secret, and the application
	// permission the manifest assigns it on the API.
	_, cc := postForm(t, http.DefaultClient, tokenURL, url.Values{
		"grant_type": {"client_credentials"}, "client_id": {"e5f7a9b1-4c6d-4e8f-a2b4-6c8e0f2a4b6d"},
		"client_secret": {"worker-dev-secret"}, "scope": {"api://contoso-api/.default"},
	})
	at, _ := cc["access_token"].(string)
	if at == "" {
		t.Fatalf("client credentials: %v", cc)
	}
	claims := decodeJWTPayload(t, at)
	if claims["aud"] != "api://contoso-api" || claims["tid"] != cfg.TenantID ||
		!slices.Equal(rolesOf(claims), []string{"Tasks.Read.All"}) {
		t.Fatalf("app-only claims: %v", claims)
	}

	// Password sign-in for a manifest user, for the API's delegated scope.
	_, ropc := postForm(t, http.DefaultClient, tokenURL, url.Values{
		"grant_type": {"password"}, "client_id": {"4b6c8d2e-1a3f-4e5b-8c7d-9f0a2b4c6d8e"},
		"username": {"alice@contoso.local"}, "password": {"Password1!"},
		"scope": {"openid api://contoso-api/access_as_user"},
	})
	at, _ = ropc["access_token"].(string)
	if at == "" {
		t.Fatalf("ROPC: %v", ropc)
	}
	claims = decodeJWTPayload(t, at)
	alice, _ := st.GetUserByUPN("alice@contoso.local")
	if claims["scp"] != "access_as_user" || claims["oid"] != alice.ID || claims["tid"] != cfg.TenantID {
		t.Fatalf("delegated claims: %v", claims)
	}
}
