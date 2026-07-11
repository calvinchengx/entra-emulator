package server

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
)

func noRedirectJar() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// authPickerState GETs the authorize URL and returns the signed state from the
// account-picker / password page.
func authPickerState(t *testing.T, client *http.Client, authURL string) string {
	t.Helper()
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := stateRe.FindStringSubmatch(string(raw))
	if m == nil {
		t.Fatalf("no signed state on sign-in page: %.200s", raw)
	}
	return m[1]
}

// TestSignInSubmitErrors covers handleSignInSubmit's invalid-user and
// invalid-state branches (re-render vs error page).
func TestSignInSubmitErrors(t *testing.T) {
	hts, _, _ := newTestServer(t)
	authorize := hts.URL + "/" + tenant + "/oauth2/v2.0/authorize"
	authURL := authorize + "?" + url.Values{
		"client_id": {spaID}, "response_type": {"code"}, "redirect_uri": {redirect},
		"scope": {"openid"}, "state": {"s"},
		"code_challenge": {pkceChallenge(verifierPK)}, "code_challenge_method": {"S256"},
	}.Encode()
	client := noRedirectJar()
	state := authPickerState(t, client, authURL)

	// Unknown user id → re-renders the picker with an error (200).
	resp, err := client.PostForm(authorize, url.Values{"__ee_state": {state}, "__ee_user": {"00000000-0000-0000-0000-0000000000ff"}})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(strings.ToLower(string(raw)), "valid account") {
		t.Fatalf("bad user: want re-rendered sign-in, got %d", resp.StatusCode)
	}

	// Garbage signed state → error page, never a redirect.
	resp2, _ := client.PostForm(authorize, url.Values{"__ee_state": {"garbage"}, "__ee_user": {aliceID}})
	resp2.Body.Close()
	if resp2.StatusCode == 302 {
		t.Fatal("invalid state should not redirect")
	}
}

// TestSignInPasswordFailure covers the RequirePassword wrong-password re-render
// and the correct-password success path of handleSignInSubmit.
func TestSignInPasswordFailure(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	cfg.RequirePassword = true
	authorize := hts.URL + "/" + tenant + "/oauth2/v2.0/authorize"
	authURL := authorize + "?" + url.Values{
		"client_id": {spaID}, "response_type": {"code"}, "redirect_uri": {redirect},
		"scope": {"openid"}, "state": {"s"},
		"code_challenge": {pkceChallenge(verifierPK)}, "code_challenge_method": {"S256"},
	}.Encode()
	client := noRedirectJar()

	// Wrong password → re-rendered password form with an error.
	state := authPickerState(t, client, authURL)
	resp, _ := client.PostForm(authorize, url.Values{
		"__ee_state": {state}, "__ee_username": {"alice@entraemulator.dev"}, "__ee_password": {"wrong"},
	})
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(strings.ToLower(string(raw)), "incorrect") {
		t.Fatalf("wrong password: want re-rendered form, got %d", resp.StatusCode)
	}

	// Correct password → 302 with a code.
	state2 := authPickerState(t, client, authURL)
	resp2, _ := client.PostForm(authorize, url.Values{
		"__ee_state": {state2}, "__ee_username": {"alice@entraemulator.dev"}, "__ee_password": {"Password1!"},
	})
	resp2.Body.Close()
	if resp2.StatusCode != 302 || !strings.Contains(resp2.Header.Get("Location"), "code=") {
		t.Fatalf("correct password: want 302 with code, got %d", resp2.StatusCode)
	}
}

// TestAuthorizeResponseModes covers deliverAuthorizeResult's form_post and
// fragment response-mode branches.
func TestAuthorizeResponseModes(t *testing.T) {
	hts, _, _ := newTestServer(t)
	authorize := hts.URL + "/" + tenant + "/oauth2/v2.0/authorize"

	drive := func(respMode string) (*http.Response, string) {
		client := noRedirectJar()
		authURL := authorize + "?" + url.Values{
			"client_id": {spaID}, "response_type": {"code"}, "redirect_uri": {redirect},
			"scope": {"openid"}, "state": {"rm"}, "response_mode": {respMode},
			"code_challenge": {pkceChallenge(verifierPK)}, "code_challenge_method": {"S256"},
		}.Encode()
		state := authPickerState(t, client, authURL)
		resp, err := client.PostForm(authorize, url.Values{"__ee_state": {state}, "__ee_user": {aliceID}})
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, string(raw)
	}

	resp, body := drive("form_post")
	if resp.StatusCode != 200 || !strings.Contains(body, "<form") || !strings.Contains(body, "code") {
		t.Fatalf("form_post: want auto-submit form, got %d", resp.StatusCode)
	}

	resp2, _ := drive("fragment")
	if resp2.StatusCode != 302 || !strings.Contains(resp2.Header.Get("Location"), "#") {
		t.Fatalf("fragment: want 302 with #fragment, got %d %q", resp2.StatusCode, resp2.Header.Get("Location"))
	}
}

// TestAuthorizeInvalidScope covers the scope-resolution rejection: a
// resource-qualified scope for an unknown app → error=invalid_scope, delivered
// to the redirect at the authorize (GET) stage.
func TestAuthorizeInvalidScope(t *testing.T) {
	hts, _, _ := newTestServer(t)
	authorize := hts.URL + "/" + tenant + "/oauth2/v2.0/authorize"
	authURL := authorize + "?" + url.Values{
		"client_id": {spaID}, "response_type": {"code"}, "redirect_uri": {redirect},
		"scope": {"openid api://nonexistent-resource/Do.Stuff"}, "state": {"s"},
		"code_challenge": {pkceChallenge(verifierPK)}, "code_challenge_method": {"S256"},
	}.Encode()
	client := noRedirectJar()
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Query().Get("error") != "invalid_scope" {
		t.Fatalf("unresolvable resource scope: want error=invalid_scope, got %q", resp.Header.Get("Location"))
	}
}
