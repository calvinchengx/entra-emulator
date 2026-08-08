package server

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestFrontchannelLogout covers OP-initiated notification of relying parties.
// The load-bearing property is SCOPE: only the apps this session actually
// signed into are notified — logging a user out of apps they never used would
// be worse than not notifying at all.
func TestFrontchannelLogout(t *testing.T) {
	hts, _, _ := newTestServer(t)

	// The SPA registers a logout URI; the daemon app registers one too but is
	// never signed into, so it must NOT be notified.
	if code, _ := patchJSON(t, hts.URL+"/admin/api/apps/"+spaID, map[string]any{
		"frontchannelLogoutUri": "https://localhost:3000/signout",
	}); code != http.StatusOK {
		t.Fatalf("register SPA logout uri: %d", code)
	}
	if code, _ := patchJSON(t, hts.URL+"/admin/api/apps/"+daemonID, map[string]any{
		"frontchannelLogoutUri": "https://localhost:4000/never-signed-in",
	}); code != http.StatusOK {
		t.Fatalf("register daemon logout uri: %d", code)
	}

	// Sign in to the SPA, keeping the session cookie.
	client := noRedirectJar()
	authorize := hts.URL + "/" + tenant + "/oauth2/v2.0/authorize"
	authURL := authorize + "?" + url.Values{
		"client_id": {spaID}, "response_type": {"code"}, "redirect_uri": {redirect},
		"scope": {"openid"}, "state": {"s"},
		"code_challenge":        {pkceChallenge("verifier-fcl-0123456789abcdefghijk")},
		"code_challenge_method": {"S256"},
	}.Encode()
	state := authPickerState(t, client, authURL)
	resp, err := client.PostForm(authorize, url.Values{"__ee_state": {state}, "__ee_user": {aliceID}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// Log out on the same session.
	out, err := client.Get(hts.URL + "/" + tenant + "/oauth2/v2.0/logout")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Body.Close()
	bodyBytes, _ := io.ReadAll(out.Body)
	body := string(bodyBytes)

	t.Run("notifies the app that was signed into", func(t *testing.T) {
		if out.StatusCode != http.StatusOK {
			t.Fatalf("logout page: want 200, got %d", out.StatusCode)
		}
		if !strings.Contains(body, "https://localhost:3000/signout") {
			t.Fatalf("the signed-into app was not notified:\n%s", body)
		}
		if !strings.Contains(body, "<iframe") {
			t.Errorf("front-channel logout is delivered by iframe:\n%s", body)
		}
	})

	t.Run("does NOT notify an app the session never used", func(t *testing.T) {
		if strings.Contains(body, "never-signed-in") {
			t.Fatalf("notified an app this session never signed into:\n%s", body)
		}
	})

	t.Run("each notification carries iss and sid", func(t *testing.T) {
		// The spec requires both so the RP knows which OP and which session.
		if !strings.Contains(body, "iss=") || !strings.Contains(body, "sid=") {
			t.Errorf("logout iframes must carry iss and sid:\n%s", body)
		}
	})

	t.Run("discovery advertises it now that it is real", func(t *testing.T) {
		_, doc := getJSON(t, hts.URL+"/"+tenant+"/v2.0/.well-known/openid-configuration")
		if doc["frontchannel_logout_supported"] != true {
			t.Errorf("frontchannel_logout_supported should be advertised: %v", doc["frontchannel_logout_supported"])
		}
	})

	t.Run("a session with no registered RPs keeps the plain signed-out page", func(t *testing.T) {
		// Unchanged behaviour for the common case: no RP logout URIs, no iframes.
		fresh := noRedirectJar()
		resp, err := fresh.Get(hts.URL + "/" + tenant + "/oauth2/v2.0/logout")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(b), "<iframe") {
			t.Errorf("no RPs to notify, so no iframes should render")
		}
	})
}
