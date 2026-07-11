package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// getFreshAuthCode drives the interactive flow up to the redirect and returns a
// fresh, unconsumed authorization code (for negative token-exchange tests).
func getFreshAuthCode(t *testing.T, hts *httptest.Server, verifier string) string {
	t.Helper()
	client := noRedirectJar()
	authorize := hts.URL + "/" + tenant + "/oauth2/v2.0/authorize"
	authURL := authorize + "?" + url.Values{
		"client_id": {spaID}, "response_type": {"code"}, "redirect_uri": {redirect},
		"scope": {"openid"}, "state": {"s"},
		"code_challenge": {pkceChallenge(verifier)}, "code_challenge_method": {"S256"},
	}.Encode()
	state := authPickerState(t, client, authURL)
	resp, err := client.PostForm(authorize, url.Values{"__ee_state": {state}, "__ee_user": {aliceID}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect: %q", resp.Header.Get("Location"))
	}
	return code
}

// TestAuthCodeExchangeErrors covers grantAuthorizationCode's PKCE-mismatch,
// redirect-mismatch, and consumed-code branches.
func TestAuthCodeExchangeErrors(t *testing.T) {
	hts, _, _ := newTestServer(t)
	tokenURL := hts.URL + "/" + tenant + "/oauth2/v2.0/token"
	v := "verifier-exchange-errors-0123456789abcdefghij"

	exchange := func(code, redir, ver string) (int, string) {
		r, b := postForm(t, http.DefaultClient, tokenURL, url.Values{
			"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redir},
			"client_id": {spaID}, "code_verifier": {ver},
		})
		e, _ := b["error"].(string)
		return r.StatusCode, e
	}

	// Wrong PKCE verifier → invalid_grant.
	if code, e := exchange(getFreshAuthCode(t, hts, v), redirect, "wrong-verifier-000000000000000000000000000000"); code != 400 || e != "invalid_grant" {
		t.Fatalf("wrong verifier: want invalid_grant, got %d %q", code, e)
	}
	// Mismatched redirect_uri → invalid_grant.
	if code, e := exchange(getFreshAuthCode(t, hts, v), "https://evil.example/cb", v); code != 400 || e != "invalid_grant" {
		t.Fatalf("wrong redirect: want invalid_grant, got %d %q", code, e)
	}
	// Reuse a consumed code → invalid_grant.
	c := getFreshAuthCode(t, hts, v)
	if code, _ := exchange(c, redirect, v); code != 200 {
		t.Fatalf("first exchange should succeed, got %d", code)
	}
	if code, e := exchange(c, redirect, v); code != 400 || e != "invalid_grant" {
		t.Fatalf("reused code: want invalid_grant, got %d %q", code, e)
	}
}

// TestDeviceVerifyBranches covers handleDeviceVerify's unknown-step branch and
// the device-code page GET (handleDeviceCodePage).
func TestDeviceVerifyBranches(t *testing.T) {
	hts, _, _ := newTestServer(t)
	base := hts.URL + "/" + tenant + "/oauth2/v2.0"

	// Unknown step → 400 error page.
	resp, err := http.PostForm(base+"/devicecode/verify", url.Values{"__ee_step": {"bogus"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("unknown device step: want 400, got %d", resp.StatusCode)
	}

	// GET the code-entry page (prefilled) → 200.
	resp2, err := http.Get(base + "/devicecode?user_code=BCDF-GHJK")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("device code page: want 200, got %d", resp2.StatusCode)
	}
}
