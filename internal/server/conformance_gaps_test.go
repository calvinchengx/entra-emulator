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
	"strings"
	"testing"
)

// Three defects the OIDF Basic OP conformance plan found, none of which any
// existing test could see (docs/23-oidf-conformance.md). The conformance suite
// is a weekly job against a container stack; these are the same contracts
// asserted where they run on every push.

// authCodeFor drives the interactive flow and returns the authorization code
// WITHOUT exchanging it, so a test can decide what to do with it. driveAuthCode
// exchanges and discards the code, which is exactly what a replay test needs
// back.
func authCodeFor(t *testing.T, hts *httptest.Server, verifier string) (string, *http.Client) {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}

	sum := sha256.Sum256([]byte(verifier))
	resp, err := client.Get(hts.URL + "/" + tenant + "/oauth2/v2.0/authorize?" + url.Values{
		"client_id": {spaID}, "response_type": {"code"}, "redirect_uri": {redirect},
		"scope": {"openid profile email offline_access"}, "state": {"st1"}, "nonce": {"n1"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := stateRe.FindStringSubmatch(string(raw))
	if m == nil {
		t.Fatalf("no signed state in the sign-in page")
	}
	resp, err = client.PostForm(hts.URL+"/"+tenant+"/oauth2/v2.0/authorize", url.Values{
		"__ee_state": {m[1]}, "__ee_user": {aliceID},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in the redirect: %s", loc)
	}
	return code, client
}

// OIDC Core 5.3.1 and RFC 6750 2.2: a form-encoded POST may carry the access
// token as an `access_token` body parameter. The emulator read the
// Authorization header and nothing else, so oidcc-userinfo-post-body reported
// that the endpoint "does not appear to support access tokens passed in the
// POST body" while GET and POST-with-header both passed.
func TestUserInfoAcceptsTheTokenInThePostBody(t *testing.T) {
	hts, _, _ := newTestServer(t)
	access := driveAuthCode(t, hts, "verifier-for-userinfo-post-body-0123456789")["access_token"].(string)
	endpoint := hts.URL + "/graph/oidc/userinfo"

	post := func(form url.Values, header string) (*http.Response, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest("POST", endpoint, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if header != "" {
			req.Header.Set("Authorization", "Bearer "+header)
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

	t.Run("token in the body is accepted", func(t *testing.T) {
		resp, ui := post(url.Values{"access_token": {access}}, "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("want 200, got %d %v", resp.StatusCode, ui)
		}
		if ui["sub"] == nil || ui["sub"] != decodeJWTPayload(t, access)["sub"] {
			t.Errorf("sub mismatch: %v", ui["sub"])
		}
	})

	t.Run("the body form validates identically to the header form", func(t *testing.T) {
		// Not a duplicate of the case above: it proves the new path did not get
		// its own, laxer validation. A garbage token must be refused the same
		// way whichever way it arrived.
		resp, out := post(url.Values{"access_token": {"not-a-token"}}, "")
		if resp.StatusCode != http.StatusUnauthorized || out["error"] != "invalid_token" {
			t.Fatalf("want 401 invalid_token, got %d %v", resp.StatusCode, out)
		}
	})

	t.Run("both at once is an invalid_request", func(t *testing.T) {
		// RFC 6750 3.1: a client MUST NOT use more than one method to present
		// the credential. Silently preferring one would hide a confused client.
		resp, out := post(url.Values{"access_token": {access}}, access)
		if resp.StatusCode != http.StatusBadRequest || out["error"] != "invalid_request" {
			t.Fatalf("want 400 invalid_request, got %d %v", resp.StatusCode, out)
		}
	})

	t.Run("graph itself still takes the header only", func(t *testing.T) {
		// The body form is a userinfo affordance, not a Graph one: real Entra's
		// Graph accepts the header alone, and widening it here would be a
		// divergence dressed up as a fix.
		req, _ := http.NewRequest("POST", hts.URL+"/graph/v1.0/me",
			strings.NewReader(url.Values{"access_token": {access}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Errorf("Graph must not accept a body token, got 200")
		}
	})
}

// RFC 6749 4.1.2: on a replayed authorization code the server must deny the
// request and SHOULD revoke what that code already produced. The access token
// is a stateless JWT verified offline against JWKS, as in Entra, so it cannot
// be withdrawn; the refresh chain can be, and was not.
func TestAuthCodeReplayRevokesTheRefreshChain(t *testing.T) {
	hts, _, _ := newTestServer(t)
	const verifier = "verifier-for-code-replay-revocation-0123456789"
	code, client := authCodeFor(t, hts, verifier)

	exchange := func(form url.Values) (*http.Response, map[string]any) {
		t.Helper()
		return postForm(t, client, hts.URL+"/"+tenant+"/oauth2/v2.0/token", form)
	}
	codeForm := url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {redirect}, "client_id": {spaID}, "code_verifier": {verifier},
	}

	resp, first := exchange(codeForm)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first exchange: %d %v", resp.StatusCode, first)
	}
	refresh, _ := first["refresh_token"].(string)
	if refresh == "" {
		t.Fatalf("no refresh token to revoke: %v", first)
	}

	// Rotate once first, so the assertion covers a chain rather than the single
	// row the exchange created. A successor that did not inherit the link would
	// survive the replay and this would catch it.
	resp, rotated := exchange(url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh},
		"client_id": {spaID}, "scope": {"openid offline_access"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotation: %d %v", resp.StatusCode, rotated)
	}
	successor, _ := rotated["refresh_token"].(string)
	if successor == "" {
		t.Fatalf("no successor refresh token: %v", rotated)
	}

	resp, replay := exchange(codeForm)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("a replayed code must be refused, got 200 %v", replay)
	}
	if replay["error"] != "invalid_grant" {
		t.Errorf("error = %v, want invalid_grant", replay["error"])
	}

	resp, after := exchange(url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {successor},
		"client_id": {spaID}, "scope": {"openid offline_access"},
	})
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("the refresh chain must not survive the replay, got 200 %v", after)
	}
}

// The negative control for the test above: an ordinary rotation must not look
// like a replay. Without this, revoking every refresh token unconditionally
// would pass the test above and break every refreshing client.
func TestOrdinaryRefreshIsUnaffectedByTheReplayRule(t *testing.T) {
	hts, _, _ := newTestServer(t)
	body := driveAuthCode(t, hts, "verifier-for-untouched-refresh-0123456789ab")
	refresh, _ := body["refresh_token"].(string)
	if refresh == "" {
		t.Fatalf("no refresh token: %v", body)
	}
	for i := 0; i < 3; i++ {
		resp, out := postForm(t, http.DefaultClient, hts.URL+"/"+tenant+"/oauth2/v2.0/token", url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {refresh},
			"client_id": {spaID}, "scope": {"openid offline_access"},
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("rotation %d: %d %v", i, resp.StatusCode, out)
		}
		refresh, _ = out["refresh_token"].(string)
		if refresh == "" {
			t.Fatalf("rotation %d returned no successor: %v", i, out)
		}
	}
}
