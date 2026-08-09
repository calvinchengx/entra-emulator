package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestScopeEchoOnExchangeAndRefresh covers two things the token endpoint gets
// wrong if it confuses the client's scope vocabulary with its own.
//
// A client asks for a resource scope fully qualified — "api://<app>/<name>" —
// while the emulator stores and claims the short name. Two consequences:
//
//  1. Narrowing on exchange must compare like for like. Comparing the raw
//     request against the stored short names rejected every resource-qualified
//     request with invalid_scope.
//  2. The response's `scope` must echo the client's strings. MSAL treats a
//     requested scope missing from the response as DECLINED and fails the whole
//     acquisition, so echoing short names makes the scope unusable.
//
// The `scp` CLAIM is unaffected and keeps short names, which is Entra's shape.
func TestScopeEchoOnExchangeAndRefresh(t *testing.T) {
	hts, _, _ := newTestServer(t)
	tokenURL := hts.URL + "/" + tenant + "/oauth2/v2.0/token"

	// Expose a delegated scope on the daemon so it can be a resource.
	if code, _ := postJSON(t, hts.URL+"/admin/api/apps/"+daemonID+"/scopes",
		map[string]any{"value": "access_as_user"}); code != http.StatusCreated && code != http.StatusConflict {
		t.Fatalf("expose scope: %d", code)
	}
	qualified := "api://" + daemonID + "/access_as_user"

	body := driveAuthCodeScope(t, hts, "verifier-for-scope-echo-0123456789abcdefgh",
		"openid profile offline_access "+qualified)

	// A client that sends no `scope` on the token request gets the authorized
	// short names back. Every MSAL does send one — that path is asserted below
	// and by the MSAL Go witness in e2e/go — so this documents the fallback
	// rather than claiming it is what a real client sees.
	t.Run("no scope on the exchange echoes the authorized names", func(t *testing.T) {
		echoed, _ := body["scope"].(string)
		if !strings.Contains(echoed, "access_as_user") {
			t.Errorf("response scope = %q, want the authorized scope", echoed)
		}
	})

	t.Run("the scp claim still carries short names", func(t *testing.T) {
		claims := decodeJWTPayload(t, body["access_token"].(string))
		scp, _ := claims["scp"].(string)
		if !strings.Contains(scp, "access_as_user") {
			t.Errorf("scp = %q, want the short name", scp)
		}
		if strings.Contains(scp, "api://") {
			t.Errorf("scp = %q leaked the qualified form; Entra emits short names", scp)
		}
	})

	t.Run("refreshing with the qualified scope is accepted and echoed", func(t *testing.T) {
		rt, _ := body["refresh_token"].(string)
		if rt == "" {
			t.Fatal("no refresh token to exercise the refresh path")
		}
		resp, refreshed := postForm(t, http.DefaultClient, tokenURL, url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {spaID},
			"scope": {"openid profile offline_access " + qualified},
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("refresh with a qualified scope: %d %v — comparing the raw "+
				"request against stored short names rejects it", resp.StatusCode, refreshed)
		}
		if echoed, _ := refreshed["scope"].(string); !strings.Contains(echoed, qualified) {
			t.Errorf("refresh response scope = %q, want it to contain %q", echoed, qualified)
		}
	})

	// The tolerance is deliberate but bounded: a scope the grant never carried
	// must still be refused, or narrowing would be no check at all.
	t.Run("a scope outside the grant is still refused", func(t *testing.T) {
		resp, out := postForm(t, http.DefaultClient, tokenURL, url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {body["refresh_token"].(string)},
			"client_id": {spaID}, "scope": {"api://" + daemonID + "/never_granted"},
		})
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("an unregistered scope was accepted: %v", out)
		}
		// Assert WHY: any non-200 would satisfy the check above, including a
		// refresh token that had simply been rotated away by an earlier subtest.
		if out["error"] != "invalid_scope" {
			t.Fatalf("refused, but not as invalid_scope: %v", out)
		}
	})
}
