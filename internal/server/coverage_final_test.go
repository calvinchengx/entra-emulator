package server

import (
	"net/http"
	"net/url"
	"testing"
)

// TestAuthCodeClientMismatch covers grantAuthorizationCode's client-check:
// redeeming the SPA's code as a different client → invalid_grant.
func TestAuthCodeClientMismatch(t *testing.T) {
	hts, _, _ := newTestServer(t)
	v := "verifier-client-mismatch-0123456789abcdefghij"
	code := getFreshAuthCode(t, hts, v)
	resp, body := postForm(t, http.DefaultClient, hts.URL+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
		"client_id": {daemonID}, "client_secret": {"daemon-app-secret"}, "code_verifier": {v},
	})
	if resp.StatusCode != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("client mismatch: want invalid_grant, got %d %v", resp.StatusCode, body)
	}
}

// TestLogoutWithSession covers clearSession's session-present branch: sign in,
// then log out.
func TestLogoutWithSession(t *testing.T) {
	hts, _, _ := newTestServer(t)
	authorize := hts.URL + "/" + tenant + "/oauth2/v2.0/authorize"
	client := noRedirectJar()
	authURL := authorize + "?" + url.Values{
		"client_id": {spaID}, "response_type": {"code"}, "redirect_uri": {redirect},
		"scope": {"openid"}, "state": {"s"},
		"code_challenge": {pkceChallenge("verifier-logout-session-0123456789abcd")}, "code_challenge_method": {"S256"},
	}.Encode()
	state := authPickerState(t, client, authURL)
	resp, err := client.PostForm(authorize, url.Values{"__ee_state": {state}, "__ee_user": {aliceID}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// Log out with the live session → signed-out page (200).
	resp2, err := client.Get(hts.URL + "/" + tenant + "/oauth2/v2.0/logout")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("logout with session: want 200, got %d", resp2.StatusCode)
	}
}

// TestAuthorizeLoginHint covers renderSignIn's login_hint pre-selection branch.
func TestAuthorizeLoginHint(t *testing.T) {
	hts, _, _ := newTestServer(t)
	authorize := hts.URL + "/" + tenant + "/oauth2/v2.0/authorize"
	client := noRedirectJar()
	authURL := authorize + "?" + url.Values{
		"client_id": {spaID}, "response_type": {"code"}, "redirect_uri": {redirect},
		"scope": {"openid"}, "state": {"s"}, "login_hint": {"alice@entraemulator.dev"},
		"code_challenge": {pkceChallenge("verifier-login-hint-0123456789abcdefgh")}, "code_challenge_method": {"S256"},
	}.Encode()
	// authPickerState fails if the account picker (with login_hint applied) didn't render.
	_ = authPickerState(t, client, authURL)
}
