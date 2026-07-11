package server

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestTokenEndpointErrors exercises the token endpoint's client-auth and
// grant-validation error branches (authenticateClient, decodeBasicComponent,
// grantAuthorizationCode negatives).
func TestTokenEndpointErrors(t *testing.T) {
	hts, _, _ := newTestServer(t)
	tokenURL := hts.URL + "/" + tenant + "/oauth2/v2.0/token"

	// Client credentials via HTTP Basic (exercises decodeBasicComponent).
	basic := base64.StdEncoding.EncodeToString([]byte(daemonID + ":daemon-app-secret"))
	req, _ := http.NewRequest("POST", tokenURL, strings.NewReader(url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"api://" + daemonID + "/.default"},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+basic)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("client_credentials via Basic auth: want 200, got %d", resp.StatusCode)
	}

	// Malformed Basic header → invalid_client.
	req2, _ := http.NewRequest("POST", tokenURL, strings.NewReader("grant_type=client_credentials"))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Authorization", "Basic !!!not-base64!!!")
	resp2, _ := http.DefaultClient.Do(req2)
	resp2.Body.Close()
	if resp2.StatusCode == 200 {
		t.Fatal("malformed Basic auth should not succeed")
	}

	cases := []struct {
		name string
		form url.Values
		want string // expected OAuth error code
	}{
		{"unsupported grant", url.Values{"grant_type": {"telepathy"}}, "unsupported_grant_type"},
		{"missing grant", url.Values{"client_id": {spaID}}, "unsupported_grant_type"},
		{"bad secret", url.Values{
			"grant_type": {"client_credentials"}, "client_id": {daemonID},
			"client_secret": {"wrong"}, "scope": {"api://" + daemonID + "/.default"},
		}, "invalid_client"},
		{"authz code unknown", url.Values{
			"grant_type": {"authorization_code"}, "client_id": {spaID},
			"code": {"nope"}, "redirect_uri": {redirect},
		}, "invalid_grant"},
	}
	for _, tc := range cases {
		resp, body := postForm(t, http.DefaultClient, tokenURL, tc.form)
		if resp.StatusCode == 200 || body["error"] != tc.want {
			t.Fatalf("%s: want error %q, got %d %v", tc.name, tc.want, resp.StatusCode, body)
		}
	}
}

// TestAuthorizeEndpointErrors covers the authorize handler's rejection paths.
func TestAuthorizeEndpointErrors(t *testing.T) {
	hts, _, _ := newTestServer(t)
	authorize := hts.URL + "/" + tenant + "/oauth2/v2.0/authorize"
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// Unknown client and bad redirect are shown as an error page (never redirected).
	for _, q := range []url.Values{
		{"client_id": {"00000000-0000-0000-0000-0000000000ff"}, "redirect_uri": {redirect}, "response_type": {"code"}},
		{"client_id": {spaID}, "redirect_uri": {"https://evil.example/cb"}, "response_type": {"code"}},
	} {
		resp, err := client.Get(authorize + "?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == 302 {
			t.Fatalf("invalid client/redirect must not redirect: %v", q)
		}
	}

	// Registered client + redirect but an unsupported response_type → redirected
	// back with error=unsupported_response_type.
	resp, err := client.Get(authorize + "?" + url.Values{
		"client_id": {spaID}, "redirect_uri": {redirect},
		"response_type": {"token"}, "state": {"s"},
	}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); resp.StatusCode == 302 && !strings.Contains(loc, "error=") {
		t.Fatalf("unsupported response_type should carry an error: %q", loc)
	}
}

// TestRequirePasswordFlow drives the ROPC-style password form path
// (renderPasswordForm / renderErrorPage) by flipping the shared config.
func TestRequirePasswordFlow(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	cfg.RequirePassword = true // shared pointer → affects live handlers

	authorize := hts.URL + "/" + tenant + "/oauth2/v2.0/authorize?" + url.Values{
		"client_id": {spaID}, "redirect_uri": {redirect},
		"response_type": {"code"}, "scope": {"openid"}, "state": {"s"},
		"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}.Encode()

	// The sign-in page now asks for a username + password.
	resp, err := http.Get(authorize)
	if err != nil {
		t.Fatal(err)
	}
	rawBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	raw := string(rawBytes)
	if !strings.Contains(raw, "password") {
		t.Fatalf("RequirePassword sign-in should render a password form, got: %s", raw[:min(200, len(raw))])
	}

	// Device-code page also renders under RequirePassword (its lookup branch).
	dc := hts.URL + "/" + tenant + "/oauth2/v2.0/devicecode"
	if r, _ := postForm(t, http.DefaultClient, dc, url.Values{"client_id": {spaID}, "scope": {"openid"}}); r.StatusCode != 200 {
		t.Fatalf("device authorization under RequirePassword: %d", r.StatusCode)
	}
}
