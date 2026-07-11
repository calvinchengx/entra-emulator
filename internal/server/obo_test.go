package server

import (
	"net/http"
	"net/url"
	"testing"
)

// forgeUserToken mints a delegated access token for Alice with a chosen
// audience, via the token forge — standing in for a token a client acquired
// for the middle-tier API.
func forgeUserToken(t *testing.T, origin, audience string) string {
	t.Helper()
	status, body := postJSON(t, origin+"/admin/api/tokens", map[string]any{
		"userId":   aliceID,
		"clientId": spaID,
		"audience": audience,
	})
	if status != 200 {
		t.Fatalf("forge user token: %d %v", status, body)
	}
	return body["token"].(string)
}

func TestOnBehalfOfHappyPath(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	tokenURL := hts.URL + "/" + tenant + "/oauth2/v2.0/token"

	// The middle-tier (daemon) received a user token addressed to it.
	assertion := forgeUserToken(t, hts.URL, "api://"+daemonID)

	// It exchanges that token for a downstream (Graph) token as the same user.
	resp, body := postForm(t, http.DefaultClient, tokenURL, url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"client_id":           {daemonID},
		"client_secret":       {"daemon-app-secret"},
		"assertion":           {assertion},
		"scope":               {"User.Read"},
		"requested_token_use": {"on_behalf_of"},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("OBO: want 200, got %d %v", resp.StatusCode, body)
	}
	claims := decodeJWTPayload(t, body["access_token"].(string))
	// Same user, now issued to the middle-tier, for the downstream resource.
	if claims["oid"] != aliceID {
		t.Fatalf("OBO token should preserve the user oid: %v", claims["oid"])
	}
	if claims["appid"] != daemonID || claims["azp"] != daemonID {
		t.Fatalf("OBO token should be issued to the middle-tier: %v", claims)
	}
	if claims["aud"] != cfg.GraphResourceID {
		t.Fatalf("OBO downstream audience should be Graph: %v", claims["aud"])
	}
	if scp, _ := claims["scp"].(string); scp != "User.Read" {
		t.Fatalf("OBO scp should reflect the downstream scope: %v", claims["scp"])
	}
}

func TestOnBehalfOfRejectsWrongAudience(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	tokenURL := hts.URL + "/" + tenant + "/oauth2/v2.0/token"

	// A token addressed to Graph, NOT to the middle-tier — must not be redeemable.
	assertion := forgeUserToken(t, hts.URL, cfg.GraphResourceID)

	resp, body := postForm(t, http.DefaultClient, tokenURL, url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"client_id":           {daemonID},
		"client_secret":       {"daemon-app-secret"},
		"assertion":           {assertion},
		"scope":               {"User.Read"},
		"requested_token_use": {"on_behalf_of"},
	})
	if resp.StatusCode != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("wrong-audience assertion: want 400 invalid_grant, got %d %v", resp.StatusCode, body)
	}
}

func TestOnBehalfOfRequiresTokenUseAndSecret(t *testing.T) {
	hts, _, _ := newTestServer(t)
	tokenURL := hts.URL + "/" + tenant + "/oauth2/v2.0/token"
	assertion := forgeUserToken(t, hts.URL, "api://"+daemonID)

	// Missing requested_token_use.
	resp, body := postForm(t, http.DefaultClient, tokenURL, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"client_id":  {daemonID}, "client_secret": {"daemon-app-secret"},
		"assertion": {assertion}, "scope": {"User.Read"},
	})
	if resp.StatusCode != 400 || body["error"] != "invalid_request" {
		t.Fatalf("missing requested_token_use: want 400 invalid_request, got %d %v", resp.StatusCode, body)
	}

	// Wrong client secret.
	resp, body = postForm(t, http.DefaultClient, tokenURL, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"client_id":  {daemonID}, "client_secret": {"wrong"},
		"assertion": {assertion}, "scope": {"User.Read"}, "requested_token_use": {"on_behalf_of"},
	})
	if resp.StatusCode != 401 || body["error"] != "invalid_client" {
		t.Fatalf("wrong secret: want 401 invalid_client, got %d %v", resp.StatusCode, body)
	}
}

func TestOnBehalfOfRejectsAppOnlyAssertion(t *testing.T) {
	hts, _, _ := newTestServer(t)
	tokenURL := hts.URL + "/" + tenant + "/oauth2/v2.0/token"

	// An app-only token (no oid) forged with the middle-tier audience.
	status, forged := postJSON(t, hts.URL+"/admin/api/tokens", map[string]any{
		"clientId": daemonID, "audience": "api://" + daemonID, // no userId => app-only
	})
	if status != 200 {
		t.Fatalf("forge app-only: %d %v", status, forged)
	}

	resp, body := postForm(t, http.DefaultClient, tokenURL, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"client_id":  {daemonID}, "client_secret": {"daemon-app-secret"},
		"assertion": {forged["token"].(string)}, "scope": {"User.Read"},
		"requested_token_use": {"on_behalf_of"},
	})
	if resp.StatusCode != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("app-only assertion: want 400 invalid_grant, got %d %v", resp.StatusCode, body)
	}
}
