package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// A code-flow request without openid (e.g. Swagger UI asking only for an API
// scope) is accepted, like Entra, and the token response has no id_token.
func TestAuthorizeCodeFlowWithoutOpenID(t *testing.T) {
	hts, _, _ := newTestServer(t)
	authorize := hts.URL + "/" + tenant + "/oauth2/v2.0/authorize"
	authURL := authorize + "?" + url.Values{
		"client_id": {spaID}, "response_type": {"code"}, "redirect_uri": {redirect},
		"scope": {"User.Read"}, "state": {"s"},
		"code_challenge": {pkceChallenge(verifierPK)}, "code_challenge_method": {"S256"},
	}.Encode()
	client := noRedirectJar()

	// Reaches the sign-in page instead of redirecting with invalid_scope.
	state := authPickerState(t, client, authURL)
	resp, err := client.PostForm(authorize, url.Values{"__ee_state": {state}, "__ee_user": {aliceID}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	code := loc.Query().Get("code")
	if resp.StatusCode != 302 || code == "" {
		t.Fatalf("want 302 with code, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	tokResp, err := http.PostForm(hts.URL+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type": {"authorization_code"}, "client_id": {spaID}, "code": {code},
		"redirect_uri": {redirect}, "code_verifier": {verifierPK},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tokResp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(tokResp.Body).Decode(&body)
	if tokResp.StatusCode != 200 || body["access_token"] == nil {
		t.Fatalf("want access token, got %d %v", tokResp.StatusCode, body)
	}
	if _, ok := body["id_token"]; ok {
		t.Fatal("no openid requested, so no id_token expected")
	}
}

// An id_token is still never issued without openid, and an empty scope is refused.
func TestAuthorizeOpenIDStillRequiredForIDTokenAndScopeRequired(t *testing.T) {
	hts, _, _ := newTestServer(t)
	authorize := hts.URL + "/" + tenant + "/oauth2/v2.0/authorize"
	cases := map[string]url.Values{
		"id_token without openid": {
			"client_id": {spaID}, "response_type": {"id_token"}, "redirect_uri": {redirect},
			"scope": {"User.Read"}, "state": {"s"}, "nonce": {"n"},
		},
		"empty scope": {
			"client_id": {spaID}, "response_type": {"code"}, "redirect_uri": {redirect},
			"scope": {""}, "state": {"s"},
			"code_challenge": {pkceChallenge(verifierPK)}, "code_challenge_method": {"S256"},
		},
	}
	for name, q := range cases {
		resp, err := noRedirectJar().Get(authorize + "?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 302 || !strings.Contains(resp.Header.Get("Location"), "error=invalid_scope") {
			t.Fatalf("%s: want redirect with invalid_scope, got %d %s", name, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
}
