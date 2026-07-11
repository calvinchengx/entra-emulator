package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

const (
	fabricResource  = "https://api.fabric.microsoft.com"
	powerBIResource = "https://analysis.windows.net/powerbi/api"
	fabricAppID     = "00000009-0000-0000-c000-000000000000"
)

// TestFabricClientCredentialsAudience proves roadmap #16a: client_credentials
// for a recognized Fabric resource mints a correct-aud token without any
// registered resource app.
func TestFabricClientCredentialsAudience(t *testing.T) {
	hts, _, _ := newTestServer(t)
	tokenURL := hts.URL + "/" + tenant + "/oauth2/v2.0/token"

	cases := []struct {
		scope   string
		wantAud string
	}{
		{fabricResource + "/.default", fabricResource},
		{powerBIResource + "/.default", powerBIResource},
		{fabricAppID + "/.default", fabricResource}, // first-party app id → canonical Fabric aud
	}
	for _, tc := range cases {
		resp, body := postForm(t, http.DefaultClient, tokenURL, url.Values{
			"grant_type": {"client_credentials"}, "client_id": {daemonID},
			"client_secret": {store.SeedDaemonSecret}, "scope": {tc.scope},
		})
		if resp.StatusCode != 200 {
			t.Fatalf("scope %s: want 200, got %d %v", tc.scope, resp.StatusCode, body)
		}
		claims := decodeJWTPayload(t, body["access_token"].(string))
		if claims["aud"] != tc.wantAud {
			t.Fatalf("scope %s: aud = %v, want %s", tc.scope, claims["aud"], tc.wantAud)
		}
		if claims["appid"] != daemonID {
			t.Fatalf("scope %s: appid = %v, want %s", tc.scope, claims["appid"], daemonID)
		}
		verifyAgainstJWKS(t, hts.URL, tenant, body["access_token"].(string))
	}
}

// TestFabricDelegatedScopeCarveOut proves roadmap #16c: bare Fabric scopes are
// auto-consented and mint a delegated token with aud=Fabric.
func TestFabricDelegatedScopeCarveOut(t *testing.T) {
	hts, _, _ := newTestServer(t)
	body := driveAuthCodeScope(t, hts, "verifier-fabric-carveout-0123456789xyz", "openid Fabric.Embed Item.Read.All")
	claims := decodeJWTPayload(t, body["access_token"].(string))
	if claims["aud"] != fabricResource {
		t.Fatalf("delegated Fabric aud = %v, want %s", claims["aud"], fabricResource)
	}
	scp, _ := claims["scp"].(string)
	if !strings.Contains(scp, "Fabric.Embed") || !strings.Contains(scp, "Item.Read.All") {
		t.Fatalf("scp missing Fabric scopes: %q", scp)
	}
}

// TestWorkspaceIdentityLifecycle proves roadmap #16b: a workspace-identity
// object with an internal (credential-less) token, name-follows-workspace,
// state gating, and cascade delete.
func TestWorkspaceIdentityLifecycle(t *testing.T) {
	hts, _, _ := newTestServer(t)

	// Create with gofakeit-generated workspace name.
	status, wi := postJSON(t, hts.URL+"/admin/api/workspace-identities", map[string]any{})
	if status != 201 {
		t.Fatalf("create workspace identity: %d %v", status, wi)
	}
	wiID, _ := wi["id"].(string)
	appID, _ := wi["appId"].(string)
	wsID, _ := wi["workspaceId"].(string)
	name, _ := wi["workspaceName"].(string)
	if wiID == "" || appID == "" || wsID == "" || name == "" {
		t.Fatalf("incomplete workspace identity DTO: %v", wi)
	}
	if wi["state"] != "Active" {
		t.Fatalf("new workspace identity state = %v, want Active", wi["state"])
	}

	// The SP app exists and its display name follows the workspace name.
	status, appDTO := getJSON(t, hts.URL+"/admin/api/apps/"+appID)
	if status != 200 || appDTO["displayName"] != name {
		t.Fatalf("SP app not created / name mismatch: %d %v", status, appDTO)
	}

	// Internal token minting — no credential supplied, aud=Fabric by default.
	tokURL := hts.URL + "/fabric/workspaceidentities/" + wiID + "/token"
	resp, tok := getRaw(t, tokURL)
	if resp != 200 {
		t.Fatalf("workspace identity token: want 200, got %d %v", resp, tok)
	}
	claims := decodeJWTPayload(t, tok["access_token"].(string))
	if claims["aud"] != fabricResource {
		t.Fatalf("workspace identity token aud = %v, want %s", claims["aud"], fabricResource)
	}
	if claims["appid"] != appID {
		t.Fatalf("workspace identity token appid = %v, want SP %s", claims["appid"], appID)
	}
	if tok["workspace_id"] != wsID {
		t.Fatalf("token response workspace_id = %v, want %s", tok["workspace_id"], wsID)
	}
	verifyAgainstJWKS(t, hts.URL, tenant, tok["access_token"].(string))

	// Rename the workspace → SP display name follows.
	status, _ = patchJSON(t, hts.URL+"/admin/api/workspace-identities/"+wiID, map[string]any{"workspaceName": "Renamed Space"})
	if status != 200 {
		t.Fatalf("rename: %d", status)
	}
	if _, appDTO = getJSON(t, hts.URL+"/admin/api/apps/"+appID); appDTO["displayName"] != "Renamed Space" {
		t.Fatalf("SP display name did not follow workspace rename: %v", appDTO["displayName"])
	}

	// A non-Active identity does not mint tokens.
	if status, _ = patchJSON(t, hts.URL+"/admin/api/workspace-identities/"+wiID, map[string]any{"state": "Failed"}); status != 200 {
		t.Fatalf("set state Failed: %d", status)
	}
	if code, _ := getRaw(t, tokURL); code != 409 {
		t.Fatalf("Failed identity should not mint a token: got %d", code)
	}

	// Delete cascades the SP app.
	if code := deleteStatus(t, hts.URL+"/admin/api/workspace-identities/"+wiID); code != 204 {
		t.Fatalf("delete workspace identity: want 204, got %d", code)
	}
	if code, _ := getJSON(t, hts.URL+"/admin/api/workspace-identities/"+wiID); code != 404 {
		t.Fatalf("deleted identity GET: want 404, got %d", code)
	}
	if code, _ := getJSON(t, hts.URL+"/admin/api/apps/"+appID); code != 404 {
		t.Fatalf("SP app should be gone after cascade: got %d", code)
	}
}

// driveAuthCodeScope runs the PKCE auth-code flow for the seeded SPA with a
// caller-chosen scope and returns the token response.
func driveAuthCodeScope(t *testing.T, hts *httptest.Server, verifier, scope string) map[string]any {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}

	challenge := pkceChallenge(verifier)
	authorizeURL := hts.URL + "/" + tenant + "/oauth2/v2.0/authorize?" + url.Values{
		"client_id": {spaID}, "response_type": {"code"}, "redirect_uri": {redirect},
		"scope": {scope}, "state": {"st1"}, "nonce": {"n1"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}.Encode()

	resp, err := client.Get(authorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := stateRe.FindStringSubmatch(string(raw))
	if m == nil {
		t.Fatalf("no signed state in picker page")
	}
	resp, err = client.PostForm(hts.URL+"/"+tenant+"/oauth2/v2.0/authorize", url.Values{
		"__ee_state": {m[1]}, "__ee_user": {aliceID},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 {
		t.Fatalf("want 302 after sign-in, got %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
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

// getRaw issues a GET and decodes a JSON object body, returning status + body.
func getRaw(t *testing.T, u string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// patchJSON issues a PATCH with a JSON body.
func patchJSON(t *testing.T, u string, body map[string]any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPatch, u, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}
