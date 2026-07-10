package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/config"
	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// newTestServer boots the full handler stack over an ephemeral store on an
// httptest server (plain HTTP; TLS is orthogonal to the contracts).
func newTestServer(t *testing.T) (*httptest.Server, *config.Config, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	getenv := func(k string) string {
		switch k {
		case "DB_PATH":
			return filepath.Join(dir, "test.db")
		case "TLS_ENABLED":
			return "false"
		case "ORIGIN_MODE":
			return "compat"
		case "PORT":
			return "8443"
		}
		return ""
	}
	cfg, err := config.Load(getenv)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.Seed(cfg.TenantID, cfg.Issuer); err != nil {
		t.Fatal(err)
	}
	signer, err := tokens.EnsureActiveKey(st, cfg.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	ts := &tokens.Service{Store: st, Signer: signer, Cfg: cfg}
	srv := New(cfg, st, ts, nil, "test")
	hts := httptest.NewServer(srv.Handler)
	t.Cleanup(hts.Close)
	// Advertised origins must match the ephemeral listener for URL checks.
	cfg.Origins = config.Origins{Login: hts.URL, Portal: hts.URL, Graph: hts.URL}
	cfg.Issuer = hts.URL + "/" + cfg.TenantID + "/v2.0"
	return hts, cfg, st
}

const (
	tenant   = config.DefaultTenantID
	spaID    = store.SeedAppSPAID
	daemonID = store.SeedAppDaemonID
	aliceID  = store.SeedUserAliceID
	redirect = "https://localhost:3000"
)

func decodeJWTPayload(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", jwt)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func postForm(t *testing.T, client *http.Client, u string, form url.Values) (*http.Response, map[string]any) {
	t.Helper()
	resp, err := client.PostForm(u, form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp, body
}

func TestDiscoveryDocument(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	for _, alias := range []string{tenant, "common", "organizations", "consumers"} {
		resp, err := http.Get(hts.URL + "/" + alias + "/v2.0/.well-known/openid-configuration")
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&doc)
		resp.Body.Close()
		// GUID-form issuer regardless of alias. The doc is built from the
		// configured origins, which the harness re-pointed post-listen; the
		// path shape is the contract asserted here.
		iss, _ := doc["issuer"].(string)
		if !strings.HasSuffix(iss, "/"+tenant+"/v2.0") {
			t.Fatalf("alias %s: issuer %q is not GUID-form", alias, iss)
		}
		grants, _ := json.Marshal(doc["grant_types_supported"])
		for _, g := range []string{"authorization_code", "refresh_token", "client_credentials", "device_code"} {
			if !strings.Contains(string(grants), g) {
				t.Fatalf("grant_types_supported missing %s: %s", g, grants)
			}
		}
	}
	if resp, _ := http.Get(hts.URL + "/nope/v2.0/.well-known/openid-configuration"); resp.StatusCode != 404 {
		t.Fatalf("invalid tenant: want 404, got %d", resp.StatusCode)
	}
	_ = cfg
}

func TestJWKSAndTokenVerify(t *testing.T) {
	hts, _, _ := newTestServer(t)
	resp, err := http.Get(hts.URL + "/" + tenant + "/discovery/v2.0/keys")
	if err != nil {
		t.Fatal(err)
	}
	var set struct {
		Keys []map[string]string `json:"keys"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&set)
	resp.Body.Close()
	if len(set.Keys) != 1 {
		t.Fatalf("want 1 key, got %d", len(set.Keys))
	}
	k := set.Keys[0]
	if k["kty"] != "RSA" || k["alg"] != "RS256" || k["use"] != "sig" || k["kid"] == "" || k["e"] != "AQAB" {
		t.Fatalf("bad JWK: %v", k)
	}
	for _, private := range []string{"d", "p", "q"} {
		if _, ok := k[private]; ok {
			t.Fatalf("JWKS leaked private field %q", private)
		}
	}
}

func TestClientCredentials(t *testing.T) {
	hts, _, _ := newTestServer(t)
	tokenURL := hts.URL + "/" + tenant + "/oauth2/v2.0/token"

	resp, body := postForm(t, http.DefaultClient, tokenURL, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {daemonID},
		"client_secret": {store.SeedDaemonSecret},
		"scope":         {"api://" + daemonID + "/.default"},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("want 200, got %d: %v", resp.StatusCode, body)
	}
	claims := decodeJWTPayload(t, body["access_token"].(string))
	if claims["sub"] != daemonID || claims["aud"] != "api://"+daemonID {
		t.Fatalf("bad app-only claims: %v", claims)
	}
	roles, _ := json.Marshal(claims["roles"])
	if !strings.Contains(string(roles), "Tasks.Read.All") {
		t.Fatalf("roles missing Tasks.Read.All: %s", roles)
	}
	if _, hasOID := claims["oid"]; hasOID {
		t.Fatal("app-only token must not carry oid")
	}
	if _, hasIDToken := body["id_token"]; hasIDToken {
		t.Fatal("client_credentials must not return id_token")
	}
	if _, hasCI := body["client_info"]; hasCI {
		t.Fatal("client_credentials must not return client_info")
	}

	// Wrong secret → invalid_client 401.
	resp, body = postForm(t, http.DefaultClient, tokenURL, url.Values{
		"grant_type": {"client_credentials"}, "client_id": {daemonID},
		"client_secret": {"wrong"}, "scope": {"api://" + daemonID + "/.default"},
	})
	if resp.StatusCode != 401 || body["error"] != "invalid_client" {
		t.Fatalf("want 401 invalid_client, got %d %v", resp.StatusCode, body)
	}
	// Public client → invalid_client.
	resp, body = postForm(t, http.DefaultClient, tokenURL, url.Values{
		"grant_type": {"client_credentials"}, "client_id": {spaID},
		"scope": {"https://graph.microsoft.com/.default"},
	})
	if resp.StatusCode != 401 || body["error"] != "invalid_client" {
		t.Fatalf("public client: want 401 invalid_client, got %d %v", resp.StatusCode, body)
	}
	// Non-.default scope → invalid_scope.
	resp, body = postForm(t, http.DefaultClient, tokenURL, url.Values{
		"grant_type": {"client_credentials"}, "client_id": {daemonID},
		"client_secret": {store.SeedDaemonSecret}, "scope": {"openid"},
	})
	if body["error"] != "invalid_scope" {
		t.Fatalf("want invalid_scope, got %d %v", resp.StatusCode, body)
	}
}

var stateRe = regexp.MustCompile(`name="__el_state" value="([^"]+)"`)

// driveAuthCode performs the interactive flow and returns the token response.
func driveAuthCode(t *testing.T, hts *httptest.Server, verifier string) map[string]any {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}

	challenge := base64.RawURLEncoding.EncodeToString(func() []byte {
		s := sha256.Sum256([]byte(verifier))
		return s[:]
	}())
	authorizeURL := hts.URL + "/" + tenant + "/oauth2/v2.0/authorize?" + url.Values{
		"client_id": {spaID}, "response_type": {"code"}, "redirect_uri": {redirect},
		"scope": {"openid profile email offline_access"}, "state": {"st1"}, "nonce": {"n1"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}.Encode()

	resp, err := client.Get(authorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	html := string(raw)
	m := stateRe.FindStringSubmatch(html)
	if m == nil {
		t.Fatalf("no signed state in picker page: %s", html[:min(300, len(html))])
	}

	resp, err = client.PostForm(hts.URL+"/"+tenant+"/oauth2/v2.0/authorize", url.Values{
		"__el_state": {m[1]}, "__el_user": {aliceID},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 {
		t.Fatalf("want 302 after sign-in, got %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Query().Get("state") != "st1" {
		t.Fatalf("state not echoed: %s", loc)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect: %s", loc)
	}

	resp2, body := postForm(t, client, hts.URL+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {redirect}, "client_id": {spaID}, "code_verifier": {verifier},
	})
	if resp2.StatusCode != 200 {
		t.Fatalf("token exchange failed: %d %v", resp2.StatusCode, body)
	}
	return body
}

func TestAuthCodePKCEFlow(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	body := driveAuthCode(t, hts, "verifier-supercalifragilistic-0123456789")

	idc := decodeJWTPayload(t, body["id_token"].(string))
	if idc["nonce"] != "n1" || idc["aud"] != spaID || idc["oid"] != aliceID || idc["ver"] != "2.0" {
		t.Fatalf("bad id token claims: %v", idc)
	}
	acc := decodeJWTPayload(t, body["access_token"].(string))
	if acc["aud"] != cfg.GraphResourceID {
		t.Fatalf("default audience should be Graph, got %v", acc["aud"])
	}
	if idc["sub"] != acc["sub"] {
		t.Fatal("pairwise sub must match across id and access tokens")
	}
	ci, err := base64.RawURLEncoding.DecodeString(body["client_info"].(string))
	if err != nil || !strings.Contains(string(ci), aliceID) {
		t.Fatalf("client_info missing/invalid: %s", ci)
	}
	if body["refresh_token"] == nil {
		t.Fatal("offline_access grant must return a refresh token")
	}
}

func TestPKCEMismatchAndReplay(t *testing.T) {
	hts, _, _ := newTestServer(t)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}

	verifier := "correct-verifier-abcdefghijklmnopqrstuvwxyz-123456"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	resp, _ := client.Get(hts.URL + "/" + tenant + "/oauth2/v2.0/authorize?" + url.Values{
		"client_id": {spaID}, "response_type": {"code"}, "redirect_uri": {redirect},
		"scope": {"openid"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}.Encode())
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := stateRe.FindStringSubmatch(string(raw))
	resp, _ = client.PostForm(hts.URL+"/"+tenant+"/oauth2/v2.0/authorize",
		url.Values{"__el_state": {m[1]}, "__el_user": {aliceID}})
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")

	// Wrong verifier → invalid_grant; the code stays unconsumed? No — PKCE
	// failure precedes consumption, so the correct retry must still work.
	resp2, body := postForm(t, client, hts.URL+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {redirect}, "client_id": {spaID}, "code_verifier": {"wrong-verifier-0000000000000000000000000000"},
	})
	if resp2.StatusCode != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("PKCE mismatch: want 400 invalid_grant, got %d %v", resp2.StatusCode, body)
	}
	resp2, body = postForm(t, client, hts.URL+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {redirect}, "client_id": {spaID}, "code_verifier": {verifier},
	})
	if resp2.StatusCode != 200 {
		t.Fatalf("correct verifier after failed attempt should succeed: %d %v", resp2.StatusCode, body)
	}
	// Replay → invalid_grant.
	resp2, body = postForm(t, client, hts.URL+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {redirect}, "client_id": {spaID}, "code_verifier": {verifier},
	})
	if resp2.StatusCode != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("code replay: want 400 invalid_grant, got %d %v", resp2.StatusCode, body)
	}
}

func TestRefreshRotationAndFamilyRevocation(t *testing.T) {
	hts, _, _ := newTestServer(t)
	body := driveAuthCode(t, hts, "verifier-for-refresh-testing-0123456789abcdef")
	tokenURL := hts.URL + "/" + tenant + "/oauth2/v2.0/token"
	rt1 := body["refresh_token"].(string)

	resp, body2 := postForm(t, http.DefaultClient, tokenURL, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {rt1}, "client_id": {spaID},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("refresh failed: %d %v", resp.StatusCode, body2)
	}
	rt2 := body2["refresh_token"].(string)
	if rt2 == rt1 {
		t.Fatal("refresh token was not rotated")
	}
	if body2["id_token"] == nil {
		t.Fatal("openid grant must re-mint the id token on refresh")
	}

	// Reuse of rt1 → invalid_grant + family revocation (rt2 dies too).
	resp, body2 = postForm(t, http.DefaultClient, tokenURL, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {rt1}, "client_id": {spaID},
	})
	if resp.StatusCode != 400 || body2["error"] != "invalid_grant" {
		t.Fatalf("reuse: want 400 invalid_grant, got %d %v", resp.StatusCode, body2)
	}
	resp, body2 = postForm(t, http.DefaultClient, tokenURL, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {rt2}, "client_id": {spaID},
	})
	if resp.StatusCode != 400 || body2["error"] != "invalid_grant" {
		t.Fatalf("family revocation: rt2 should be dead, got %d %v", resp.StatusCode, body2)
	}
}

func TestGraphAndUserInfo(t *testing.T) {
	hts, _, _ := newTestServer(t)
	body := driveAuthCode(t, hts, "verifier-for-graph-testing-0123456789abcdefgh")
	access := body["access_token"].(string)

	get := func(path, bearer string) (*http.Response, map[string]any) {
		req, _ := http.NewRequest("GET", hts.URL+path, nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp, out
	}

	resp, me := get("/graph/v1.0/me", access)
	if resp.StatusCode != 200 || me["userPrincipalName"] != "alice@entralocal.dev" {
		t.Fatalf("graph /me: %d %v", resp.StatusCode, me)
	}
	resp, _ = get("/graph/v1.0/me", "")
	if resp.StatusCode != 401 || resp.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("missing bearer: want 401 + WWW-Authenticate, got %d", resp.StatusCode)
	}
	resp, ui := get("/graph/oidc/userinfo", access)
	acc := decodeJWTPayload(t, access)
	if resp.StatusCode != 200 || ui["sub"] != acc["sub"] {
		t.Fatalf("userinfo sub mismatch: %v vs %v", ui["sub"], acc["sub"])
	}
	// Paged users with $top=1 → nextLink preserving $top.
	resp, page := get("/graph/v1.0/users?$top=1", access)
	if resp.StatusCode != 200 {
		t.Fatalf("users paging: %d", resp.StatusCode)
	}
	next, _ := page["@odata.nextLink"].(string)
	if !strings.Contains(next, "%24top=1") && !strings.Contains(next, "$top=1") {
		t.Fatalf("nextLink must preserve $top: %q", next)
	}
	// App-only token on /me → 403; on /users → 200.
	respT, cc := postForm(t, http.DefaultClient, hts.URL+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type": {"client_credentials"}, "client_id": {daemonID},
		"client_secret": {store.SeedDaemonSecret}, "scope": {"https://graph.microsoft.com/.default"},
	})
	if respT.StatusCode != 200 {
		t.Fatalf("graph .default client_credentials failed: %v", cc)
	}
	appToken := cc["access_token"].(string)
	resp, _ = get("/graph/v1.0/me", appToken)
	if resp.StatusCode != 403 {
		t.Fatalf("app-only /me: want 403, got %d", resp.StatusCode)
	}
	resp, _ = get("/graph/v1.0/users", appToken)
	if resp.StatusCode != 200 {
		t.Fatalf("app-only /users: want 200, got %d", resp.StatusCode)
	}
}

func TestDeviceCodeFlow(t *testing.T) {
	hts, _, st := newTestServer(t)
	base := hts.URL + "/" + tenant + "/oauth2/v2.0"

	resp, da := postForm(t, http.DefaultClient, base+"/devicecode", url.Values{
		"client_id": {spaID}, "scope": {"openid profile offline_access"},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("device authorization failed: %d %v", resp.StatusCode, da)
	}
	userCode := da["user_code"].(string)
	if !regexp.MustCompile(`^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$`).MatchString(userCode) {
		t.Fatalf("bad user_code format: %q", userCode)
	}

	poll := url.Values{"grant_type": {"device_code"}, "device_code": {da["device_code"].(string)},
		"client_id": {spaID}, "scope": {"stray-ignored"}, "client_info": {"1"}}
	resp, body := postForm(t, http.DefaultClient, base+"/token", poll)
	if resp.StatusCode != 400 || body["error"] != "authorization_pending" {
		t.Fatalf("pending poll: want authorization_pending, got %d %v", resp.StatusCode, body)
	}

	// Approve server-side (the HTML state machine has its own smoke tests).
	if err := st.SetDeviceCodeDecision(userCode, "approved", aliceID); err != nil {
		t.Fatal(err)
	}
	resp, body = postForm(t, http.DefaultClient, base+"/token", poll)
	if resp.StatusCode != 200 {
		t.Fatalf("approved poll failed: %d %v", resp.StatusCode, body)
	}
	if body["refresh_token"] == nil || body["client_info"] == nil {
		t.Fatalf("device response missing refresh_token/client_info: %v", body)
	}
	idc := decodeJWTPayload(t, body["id_token"].(string))
	if idc["oid"] != aliceID {
		t.Fatalf("approving user should be alice, got %v", idc["oid"])
	}
	// Single-use.
	resp, body = postForm(t, http.DefaultClient, base+"/token", poll)
	if resp.StatusCode != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("re-poll after mint: want invalid_grant, got %d %v", resp.StatusCode, body)
	}
}

func TestAdminSecretShowOnce(t *testing.T) {
	hts, _, _ := newTestServer(t)
	call := func(method, path string, body any) (int, map[string]any) {
		var payload *strings.Reader
		if body != nil {
			raw, _ := json.Marshal(body)
			payload = strings.NewReader(string(raw))
		} else {
			payload = strings.NewReader("")
		}
		req, _ := http.NewRequest(method, hts.URL+path, payload)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	status, app := call("POST", "/admin/api/apps", map[string]any{
		"displayName": "Test App", "isConfidential": true})
	if status != 201 {
		t.Fatalf("create app: %d %v", status, app)
	}
	appID := app["id"].(string)
	status, sec := call("POST", "/admin/api/apps/"+appID+"/secrets", map[string]any{"displayName": "s1"})
	if status != 201 || sec["secretText"] == nil {
		t.Fatalf("secret create must return secretText once: %d %v", status, sec)
	}
	status, got := call("GET", "/admin/api/apps/"+appID, nil)
	raw, _ := json.Marshal(got["secrets"])
	if strings.Contains(string(raw), sec["secretText"].(string)) {
		t.Fatal("secretText leaked on subsequent GET")
	}
	// The returned secret authenticates immediately.
	resp, tok := postForm(t, http.DefaultClient, hts.URL+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type": {"client_credentials"}, "client_id": {appID},
		"client_secret": {sec["secretText"].(string)}, "scope": {"https://graph.microsoft.com/.default"},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("fresh app+secret should mint: %d %v", resp.StatusCode, tok)
	}
	// Duplicate seeded UPN → 409.
	status, _ = call("POST", "/admin/api/users", map[string]any{
		"userPrincipalName": "alice@entralocal.dev", "displayName": "Dup"})
	if status != 409 {
		t.Fatalf("duplicate UPN: want 409, got %d", status)
	}
	_ = status
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
