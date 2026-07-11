package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestDiscoveryDocument covers handleDiscovery / issuerFor / userinfoEndpoint.
func TestDiscoveryDocFields(t *testing.T) {
	hts, _, _ := newTestServer(t)
	code, doc := getJSON(t, hts.URL+"/"+tenant+"/v2.0/.well-known/openid-configuration")
	if code != 200 {
		t.Fatalf("discovery: %d", code)
	}
	for _, k := range []string{"issuer", "jwks_uri", "authorization_endpoint", "token_endpoint", "device_authorization_endpoint"} {
		if doc[k] == nil || doc[k] == "" {
			t.Fatalf("discovery missing %q: %v", k, doc)
		}
	}
}

// TestOBOErrorPaths covers grantOnBehalfOf's rejection branches.
func TestOBOErrorPaths(t *testing.T) {
	hts, _, _ := newTestServer(t)
	tokenURL := hts.URL + "/" + tenant + "/oauth2/v2.0/token"
	obo := func(form url.Values) (int, string) {
		form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
		resp, body := postForm(t, http.DefaultClient, tokenURL, form)
		e, _ := body["error"].(string)
		return resp.StatusCode, e
	}

	// Public client (the SPA) can't do OBO → invalid_client.
	if _, e := obo(url.Values{"client_id": {spaID}, "assertion": {"x"}, "requested_token_use": {"on_behalf_of"}}); e != "invalid_client" {
		t.Fatalf("public client OBO: want invalid_client, got %q", e)
	}
	// Confidential client, missing requested_token_use → invalid_request.
	base := url.Values{"client_id": {daemonID}, "client_secret": {"daemon-app-secret"}}
	f := cloneVals(base)
	f.Set("assertion", "x")
	if _, e := obo(f); e != "invalid_request" {
		t.Fatalf("missing requested_token_use: want invalid_request, got %q", e)
	}
	// Missing assertion → invalid_request.
	f = cloneVals(base)
	f.Set("requested_token_use", "on_behalf_of")
	if _, e := obo(f); e != "invalid_request" {
		t.Fatalf("missing assertion: want invalid_request, got %q", e)
	}
	// Garbage assertion → invalid_grant.
	f = cloneVals(base)
	f.Set("requested_token_use", "on_behalf_of")
	f.Set("assertion", "not.a.jwt")
	if _, e := obo(f); e != "invalid_grant" {
		t.Fatalf("bad assertion: want invalid_grant, got %q", e)
	}
}

// TestAuthorizeValidation covers handleAuthorize's parameter-rejection branches.
func TestAuthorizeValidation(t *testing.T) {
	hts, _, _ := newTestServer(t)
	authorize := hts.URL + "/" + tenant + "/oauth2/v2.0/authorize"
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// Missing redirect_uri (can't safely redirect) → error page, not a 302.
	resp, err := client.Get(authorize + "?" + url.Values{"client_id": {spaID}, "response_type": {"code"}}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == 302 {
		t.Fatal("missing redirect_uri must not redirect")
	}

	// Registered client + redirect but missing response_type → redirected with an error.
	resp2, _ := client.Get(authorize + "?" + url.Values{
		"client_id": {spaID}, "redirect_uri": {redirect}, "state": {"s"},
	}.Encode())
	resp2.Body.Close()
	if loc := resp2.Header.Get("Location"); resp2.StatusCode == 302 && !strings.Contains(loc, "error=") {
		t.Fatalf("missing response_type should carry an error: %q", loc)
	}
}

// TestDeviceAuthErrors covers handleDeviceAuthorization's client-validation branches.
func TestDeviceAuthErrors(t *testing.T) {
	hts, _, _ := newTestServer(t)
	dc := hts.URL + "/" + tenant + "/oauth2/v2.0/devicecode"

	// Missing client_id → error.
	if resp, body := postForm(t, http.DefaultClient, dc, url.Values{"scope": {"openid"}}); resp.StatusCode == 200 || body["error"] == nil {
		t.Fatalf("device auth no client_id: want error, got %d %v", resp.StatusCode, body)
	}
	// Unknown client_id → error.
	if resp, body := postForm(t, http.DefaultClient, dc, url.Values{
		"client_id": {"00000000-0000-0000-0000-0000000000ff"}, "scope": {"openid"},
	}); resp.StatusCode == 200 || body["error"] == nil {
		t.Fatalf("device auth unknown client: want error, got %d %v", resp.StatusCode, body)
	}
}

// TestConsentInvalidState covers handleConsentDecision's invalid-state branch.
func TestConsentInvalidState(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	cfg.RequireConsent = true
	resp, err := http.PostForm(hts.URL+"/"+tenant+"/oauth2/v2.0/authorize", url.Values{
		"__ee_consent": {"1"}, "__ee_state": {"garbage"}, "__ee_decision": {"approve"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == 302 {
		t.Fatal("invalid consent state must not redirect")
	}
}

func cloneVals(v url.Values) url.Values {
	out := url.Values{}
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}
