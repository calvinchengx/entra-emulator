package server

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// tokenExpiresIn reads expires_in from a client-credentials response, and the
// exp/iat delta from the token itself — the two must agree, or the advertised
// lifetime is a lie about the token actually issued.
func tokenExpiresIn(t *testing.T, hts string) (advertised int, actual int) {
	t.Helper()
	_, body := postForm(t, http.DefaultClient, hts+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type": {"client_credentials"}, "client_id": {daemonID},
		"client_secret": {store.SeedDaemonSecret},
		"scope":         {"https://graph.microsoft.com/.default"},
	})
	adv, _ := body["expires_in"].(float64)
	tok, _ := body["access_token"].(string)
	if tok == "" {
		t.Fatalf("no access_token: %v", body)
	}
	claims := decodeJWTPayload(t, tok)
	exp, _ := claims["exp"].(float64)
	iat, _ := claims["iat"].(float64)
	return int(adv), int(exp - iat)
}

// TestTokenLifetimePolicy covers Entra's tokenLifetimePolicy. A policy that
// only appears in a catalogue would be worthless — the assertion that matters
// is that assigning one changes the `exp` of the tokens actually minted.
func TestTokenLifetimePolicy(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)
	policies := hts.URL + "/graph/v1.0/policies/tokenLifetimePolicies"

	// Baseline: the configured default.
	adv, actual := tokenExpiresIn(t, hts.URL)
	if adv != cfg.Lifetimes.AccessToken || actual != cfg.Lifetimes.AccessToken {
		t.Fatalf("baseline lifetime: advertised=%d actual=%d, want %d", adv, actual, cfg.Lifetimes.AccessToken)
	}

	// Entra carries the settings as JSON inside a string, so we send exactly that.
	code, policy := postJSONAuth(t, policies, app, map[string]any{
		"displayName": "Eight hour access",
		"definition": []string{
			`{"TokenLifetimePolicy":{"Version":1,"AccessTokenLifetime":"08:00:00"}}`,
		},
	})
	if code != http.StatusCreated {
		t.Fatalf("create policy: %d %v", code, policy)
	}
	policyID, _ := policy["id"].(string)

	t.Run("assigning it changes the minted token's exp", func(t *testing.T) {
		if code, body := postJSONAuth(t, hts.URL+"/graph/v1.0/applications/"+daemonID+"/tokenLifetimePolicies/$ref",
			app, map[string]any{"@odata.id": hts.URL + "/graph/v1.0/policies/tokenLifetimePolicies/" + policyID}); code != http.StatusNoContent {
			t.Fatalf("assign: %d %v", code, body)
		}
		adv, actual := tokenExpiresIn(t, hts.URL)
		if adv != 8*3600 {
			t.Errorf("expires_in = %d, want 28800", adv)
		}
		if actual != 8*3600 {
			t.Errorf("token exp-iat = %d, want 28800 — the policy did not reach the token", actual)
		}
	})

	t.Run("it lists on the application", func(t *testing.T) {
		status, list := graphGet(t, hts.URL, "/graph/v1.0/applications/"+daemonID+"/tokenLifetimePolicies", app)
		if status != http.StatusOK || len(list["value"].([]any)) != 1 {
			t.Fatalf("app policies: %d %v", status, list)
		}
	})

	t.Run("unassigning restores the configured default", func(t *testing.T) {
		if code := deleteAuthStatus(t,
			hts.URL+"/graph/v1.0/applications/"+daemonID+"/tokenLifetimePolicies/"+policyID+"/$ref", app); code != http.StatusNoContent {
			t.Fatalf("unassign: %d", code)
		}
		if _, actual := tokenExpiresIn(t, hts.URL); actual != cfg.Lifetimes.AccessToken {
			t.Fatalf("after unassign exp-iat = %d, want the default %d", actual, cfg.Lifetimes.AccessToken)
		}
	})

	t.Run("an organization default applies with no assignment", func(t *testing.T) {
		code, orgPolicy := postJSONAuth(t, policies, app, map[string]any{
			"displayName": "Org default two hours",
			"definition": []string{
				`{"TokenLifetimePolicy":{"Version":1,"AccessTokenLifetime":"02:00:00"}}`,
			},
			"isOrganizationDefault": true,
		})
		if code != http.StatusCreated {
			t.Fatalf("create org default: %d %v", code, orgPolicy)
		}
		if _, actual := tokenExpiresIn(t, hts.URL); actual != 2*3600 {
			t.Fatalf("org default exp-iat = %d, want 7200", actual)
		}
		// Clean up so later subtests see the configured default again.
		_ = deleteAuthStatus(t, policies+"/"+orgPolicy["id"].(string), app)
	})

	t.Run("a definition that sets nothing is refused", func(t *testing.T) {
		// Silently inert is worse than rejected: the caller would believe a
		// lifetime had been applied.
		for _, bad := range [][]string{
			{`{"TokenLifetimePolicy":{"Version":1}}`},
			{`{"TokenLifetimePolicy":{"Version":1,"AccessTokenLifetime":"not-a-duration"}}`},
			{`not even json`},
		} {
			if code, _ := postJSONAuth(t, policies, app, map[string]any{
				"displayName": "Inert", "definition": bad,
			}); code != http.StatusBadRequest {
				t.Errorf("definition %v: want 400, got %d", bad, code)
			}
		}
	})

	t.Run("validation and unknown ids", func(t *testing.T) {
		if code, _ := postJSONAuth(t, policies, app, map[string]any{"displayName": "No definition"}); code != http.StatusBadRequest {
			t.Errorf("missing definition: want 400")
		}
		if code, _ := postJSONAuth(t, hts.URL+"/graph/v1.0/applications/"+daemonID+"/tokenLifetimePolicies/$ref",
			app, map[string]any{"@odata.id": "https://x/" + store.NewGUID()}); code != http.StatusNotFound {
			t.Errorf("assigning an unknown policy: want 404, got %d", code)
		}
	})
}

// TestParseTimeSpanTable covers the .NET duration format Entra's definitions
// use — not ISO-8601, not seconds — including the day component.
func TestParseTimeSpanTable(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int
		ok   bool
	}{
		{"08:00:00", 8 * 3600, true},
		{"00:30:00", 1800, true},
		{"1.00:00:00", 86400, true},
		{"2.03:04:05", 2*86400 + 3*3600 + 4*60 + 5, true},
		{"", 0, false},
		{"00:00:00", 0, false},
		{"not-a-duration", 0, false},
		{"8h", 0, false},
		{"PT8H", 0, false},
	} {
		got, ok := store.ParseTimeSpan(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("ParseTimeSpan(%q) = %d,%v; want %d,%v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}
