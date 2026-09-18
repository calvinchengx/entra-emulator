package server

import (
	"net/http"
	"net/url"
	"testing"
)

// A refresh exchange must describe the SAME authentication the code exchange
// described. `refresh_tokens` recorded the grant and nothing about the
// authentication behind it, so `amr` and `auth_time` were dropped the moment a
// client refreshed — and the emulator contradicted itself rather than merely
// omitting something: the same app, the same session, the same user, two ID
// tokens that disagree about how and when the user authenticated.
//
// That self-contradiction is the reason this is provable without a tenant.

const verifierRC = "verifier-refresh-context-0123456789abcdefgh"

// refreshIDToken redeems a refresh token and returns the new ID token's claims.
func refreshIDToken(t *testing.T, client *http.Client, hts, rt string) (map[string]any, string) {
	t.Helper()
	resp, body := postForm(t, client, hts+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {rt},
		"client_id": {spaID}, "scope": {"openid offline_access"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh: %d %v", resp.StatusCode, body)
	}
	idt, _ := body["id_token"].(string)
	if idt == "" {
		t.Fatalf("no id_token on refresh: %v", body)
	}
	next, _ := body["refresh_token"].(string)
	return decodeJWTPayload(t, idt), next
}

// signInForRefresh authenticates and returns the first token response's ID
// token claims plus its refresh token.
func signInForRefresh(t *testing.T, hts string) (*http.Client, map[string]any, string) {
	t.Helper()
	client := noRedirectJar()
	step := authorizeStep(t, client, hts, url.Values{"code_challenge": {pkceChallenge(verifierRC)}})
	loc := signIn(t, client, hts, step.signInState)
	resp, body := postForm(t, client, hts+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")},
		"redirect_uri": {redirect}, "client_id": {spaID}, "code_verifier": {verifierRC},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("code exchange: %d %v", resp.StatusCode, body)
	}
	rt, _ := body["refresh_token"].(string)
	if rt == "" {
		t.Fatalf("no refresh_token (offline_access was requested): %v", body)
	}
	return client, decodeJWTPayload(t, body["id_token"].(string)), rt
}

// TestRefreshKeepsAmr: the code exchange reports amr:["pwd"], so the refresh
// must too. A claim that appears and then vanishes is worse than one that is
// never emitted — a client that reads it sees the user's authentication method
// change without the user doing anything.
func TestRefreshKeepsAmr(t *testing.T) {
	hts, _, _ := newTestServer(t)
	client, first, rt := signInForRefresh(t, hts.URL)

	firstAmr, ok := first["amr"].([]any)
	if !ok || len(firstAmr) == 0 {
		t.Fatalf("precondition: the code exchange should report amr, got %v", first["amr"])
	}
	refreshed, _ := refreshIDToken(t, client, hts.URL, rt)
	got, ok := refreshed["amr"].([]any)
	if !ok || len(got) == 0 {
		t.Fatalf("amr disappeared on refresh: code exchange said %v, refresh says %v",
			first["amr"], refreshed["amr"])
	}
	if got[0] != firstAmr[0] {
		t.Fatalf("amr changed across a refresh: %v then %v", firstAmr, got)
	}
}

// TestRefreshKeepsAuthTimeForAnOptedInApp. auth_time is an optionalClaims
// opt-in, and an opt-in is a property of the APP, not of one exchange — so it
// must hold for every ID token that app receives.
func TestRefreshKeepsAuthTimeForAnOptedInApp(t *testing.T) {
	hts, _, _ := newTestServer(t)
	if code, body := patchJSON(t, hts.URL+"/admin/api/apps/"+spaID, map[string]any{
		"optionalClaims": map[string]any{"idToken": []map[string]any{{"name": "auth_time"}}},
	}); code != http.StatusOK {
		t.Fatalf("patch optionalClaims: %d %v", code, body)
	}

	client, first, rt := signInForRefresh(t, hts.URL)
	authTime, ok := first["auth_time"].(float64)
	if !ok {
		t.Fatalf("precondition: the opted-in app should get auth_time on the code exchange: %v", first)
	}

	// Move the clock so a refresh that re-derived auth_time from "now" is
	// visibly different from one that carried the authentication instant.
	setClock(t, hts.URL, map[string]any{"advanceSeconds": 600})
	refreshed, _ := refreshIDToken(t, client, hts.URL, rt)
	got, ok := refreshed["auth_time"].(float64)
	if !ok {
		t.Fatalf("auth_time disappeared on refresh for an opted-in app: %v", refreshed)
	}
	if got != authTime {
		t.Fatalf("auth_time changed across a refresh: %v then %v (the user did not re-authenticate)",
			authTime, got)
	}
}

// TestRotatedRefreshTokenStillCarriesTheAuthentication. Rotation mints a
// SUCCESSOR row; if the successor does not inherit the authentication context,
// the claims survive exactly one refresh and vanish on the second — which would
// pass a single-refresh test and fail in any real client's lifetime.
func TestRotatedRefreshTokenStillCarriesTheAuthentication(t *testing.T) {
	hts, _, _ := newTestServer(t)
	if code, body := patchJSON(t, hts.URL+"/admin/api/apps/"+spaID, map[string]any{
		"optionalClaims": map[string]any{"idToken": []map[string]any{{"name": "auth_time"}}},
	}); code != http.StatusOK {
		t.Fatalf("patch optionalClaims: %d %v", code, body)
	}
	client, first, rt := signInForRefresh(t, hts.URL)
	authTime := first["auth_time"].(float64)

	for i := 1; i <= 3; i++ {
		var claims map[string]any
		claims, rt = refreshIDToken(t, client, hts.URL, rt)
		if rt == "" {
			t.Fatalf("refresh %d returned no successor token", i)
		}
		if got, ok := claims["auth_time"].(float64); !ok || got != authTime {
			t.Fatalf("refresh %d lost auth_time: want %v, got %v", i, authTime, claims["auth_time"])
		}
		if amr, ok := claims["amr"].([]any); !ok || len(amr) == 0 || amr[0] != "pwd" {
			t.Fatalf("refresh %d lost amr: %v", i, claims["amr"])
		}
	}
}
