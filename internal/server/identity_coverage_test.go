package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestScopeResolutionAndRefresh exercises ResolveDelegatedScopes /
// appExposesScope (via the SPA's exposed scope) and the refresh_token grant's
// narrowing, rotation-reuse, and unknown-token branches.
func TestScopeResolutionAndRefresh(t *testing.T) {
	hts, _, _ := newTestServer(t)
	// Request reserved scopes + the SPA's resource-qualified exposed scope
	// (api://<spaID>/access_as_user) — the `resource/name` form drives
	// findResourceApp + appExposesScope.
	body := driveAuthCodeScope(t, hts,
		"verifier-scope-resolution-0123456789abcd",
		"openid profile offline_access api://"+spaID+"/access_as_user")
	rt, _ := body["refresh_token"].(string)
	if rt == "" {
		t.Fatalf("no refresh token in response: %v", body)
	}
	scp, _ := body["scope"].(string)
	if !strings.Contains(scp, "access_as_user") {
		t.Fatalf("exposed scope should survive resolution: %q", scp)
	}

	tokenURL := hts.URL + "/" + tenant + "/oauth2/v2.0/token"

	// Refresh with a narrowed subset scope → ok, rotates the token.
	resp, ref := postForm(t, http.DefaultClient, tokenURL, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {rt},
		"client_id": {spaID}, "scope": {"openid profile"},
	})
	if resp.StatusCode != 200 || ref["access_token"] == nil {
		t.Fatalf("refresh narrowed: %d %v", resp.StatusCode, ref)
	}

	// Reusing the now-rotated original token → invalid_grant (family revoke).
	resp2, b2 := postForm(t, http.DefaultClient, tokenURL, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {spaID},
	})
	if resp2.StatusCode != 400 || b2["error"] != "invalid_grant" {
		t.Fatalf("reused refresh: want invalid_grant, got %d %v", resp2.StatusCode, b2)
	}

	// Unknown refresh token → invalid_grant.
	resp3, b3 := postForm(t, http.DefaultClient, tokenURL, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {"not-a-token"}, "client_id": {spaID},
	})
	if resp3.StatusCode != 400 || b3["error"] != "invalid_grant" {
		t.Fatalf("unknown refresh: want invalid_grant, got %d %v", resp3.StatusCode, b3)
	}
}

// TestLogoutWithIDTokenHint covers handleLogout's id_token_hint → client
// inference → validated redirect branch.
func TestLogoutWithIDTokenHint(t *testing.T) {
	hts, _, _ := newTestServer(t)
	body := driveAuthCode(t, hts, "verifier-logout-hint-0123456789abcdefgh")
	idToken, _ := body["id_token"].(string)
	if idToken == "" {
		t.Fatal("no id_token")
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(hts.URL + "/" + tenant + "/oauth2/v2.0/logout?" + url.Values{
		"id_token_hint": {idToken}, "post_logout_redirect_uri": {redirect},
	}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 {
		t.Fatalf("logout with id_token_hint should redirect: got %d", resp.StatusCode)
	}
}

// TestFabricTokenErrors covers handleWorkspaceIdentityToken's not-found and
// not-active branches.
func TestFabricTokenErrors(t *testing.T) {
	hts, _, _ := newTestServer(t)
	base := hts.URL + "/admin/api"
	fabTok := func(id string) int {
		resp, err := http.Get(hts.URL + "/fabric/workspaceidentities/" + id + "/token")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// Unknown identity → not 200.
	if fabTok("00000000-0000-0000-0000-0000000000ff") == 200 {
		t.Fatal("unknown workspace identity should not mint a token")
	}

	// Create then set inactive → token refused.
	_, wi := postJSON(t, base+"/workspace-identities", map[string]any{})
	id := wi["id"].(string)
	if fabTok(id) != 200 {
		t.Fatalf("active identity should mint: got %d", fabTok(id))
	}
	if code, _ := patchJSON(t, base+"/workspace-identities/"+id, map[string]any{"state": "Failed"}); code != 200 {
		t.Fatalf("set state: %d", code)
	}
	if fabTok(id) == 200 {
		t.Fatal("non-active identity should not mint a token")
	}
}

// TestDeviceCodeErrorPages covers loadPendingDeviceCode's not-found and denied
// branches through the verification UI.
func TestDeviceCodeErrorPages(t *testing.T) {
	hts, _, st := newTestServer(t)
	base := hts.URL + "/" + tenant + "/oauth2/v2.0"
	verify := base + "/devicecode/verify"

	// Unknown user code → "not found" page.
	_, page := postFormHTML(t, http.DefaultClient, verify, url.Values{
		"__ee_step": {"lookup"}, "user_code": {"BCDF-GHJK"},
	})
	if !strings.Contains(strings.ToLower(page), "found") {
		t.Fatalf("unknown code should render a not-found page: %s", page[:min(200, len(page))])
	}

	// Real code, denied server-side → lookup renders the denied page.
	_, da := postForm(t, http.DefaultClient, base+"/devicecode", url.Values{
		"client_id": {spaID}, "scope": {"openid"},
	})
	userCode := da["user_code"].(string)
	if err := st.SetDeviceCodeDecision(userCode, "denied", ""); err != nil {
		t.Fatal(err)
	}
	_, page2 := postFormHTML(t, http.DefaultClient, verify, url.Values{
		"__ee_step": {"lookup"}, "user_code": {userCode},
	})
	if !strings.Contains(strings.ToLower(page2), "denied") {
		t.Fatalf("denied code should render a denied page: %s", page2[:min(200, len(page2))])
	}
}
