package server

import (
	"net/http"
	"net/url"
	"testing"
)

func setClock(t *testing.T, origin string, body map[string]any) map[string]any {
	t.Helper()
	code, out := postJSON(t, origin+"/admin/api/clock", body)
	if code != 200 {
		t.Fatalf("set clock: %d %v", code, out)
	}
	return out
}

// TestClockAdvanceExpiresAccessToken is the headline use case: mint a valid
// token, jump the clock past its lifetime, and watch Graph reject it as
// expired — no real sleep.
func TestClockAdvanceExpiresAccessToken(t *testing.T) {
	hts, cfg, _ := newTestServer(t)

	// Forge a normal valid access token for Alice.
	_, forged := postJSON(t, hts.URL+"/admin/api/tokens", map[string]any{"userId": aliceID})
	token := forged["token"].(string)

	// Valid now.
	if code := graphMe(t, hts.URL, token); code != 200 {
		t.Fatalf("token should be valid before advancing clock, got %d", code)
	}

	// Advance past the access-token lifetime + skew.
	setClock(t, hts.URL, map[string]any{"advanceSeconds": cfg.Lifetimes.AccessToken + 120})

	// Same token is now expired.
	if code := graphMe(t, hts.URL, token); code != 401 {
		t.Fatalf("token should be expired after advancing clock, got %d", code)
	}

	// Resetting the clock makes it valid again (exp is absolute, real time is back).
	deleteReq(t, hts.URL+"/admin/api/clock")
	if code := graphMe(t, hts.URL, token); code != 200 {
		t.Fatalf("token should be valid again after clock reset, got %d", code)
	}
}

// TestClockAdvanceExpiresRefreshToken advances past the refresh-token
// lifetime and asserts redemption fails.
func TestClockAdvanceExpiresRefreshToken(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	body := driveAuthCode(t, hts, "verifier-clock-refresh-0123456789abcdefghij")
	rt := body["refresh_token"].(string)
	tokenURL := hts.URL + "/" + tenant + "/oauth2/v2.0/token"

	// Advance past the refresh lifetime.
	setClock(t, hts.URL, map[string]any{"advanceSeconds": cfg.Lifetimes.RefreshToken + 60})

	resp, out := postForm(t, http.DefaultClient, tokenURL, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {spaID},
	})
	if resp.StatusCode != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("expired refresh token: want 400 invalid_grant, got %d %v", resp.StatusCode, out)
	}
}

// TestClockFreezeDeterministicIat freezes time and asserts two forged tokens
// share the same iat.
func TestClockFreezeDeterministicIat(t *testing.T) {
	hts, _, _ := newTestServer(t)

	state := setClock(t, hts.URL, map[string]any{"frozen": true})
	if state["frozen"] != true {
		t.Fatalf("clock should report frozen: %v", state)
	}

	forgeIat := func() float64 {
		_, forged := postJSON(t, hts.URL+"/admin/api/tokens", map[string]any{"userId": aliceID})
		claims := decodeJWTPayload(t, forged["token"].(string))
		return claims["iat"].(float64)
	}
	if a, b := forgeIat(), forgeIat(); a != b {
		t.Fatalf("frozen clock should yield identical iat: %v vs %v", a, b)
	}

	// GET reflects the frozen state.
	code, got := getJSON(t, hts.URL+"/admin/api/clock")
	if code != 200 || got["frozen"] != true {
		t.Fatalf("GET clock should show frozen: %d %v", code, got)
	}
}

func deleteReq(t *testing.T, url string) {
	t.Helper()
	req, _ := http.NewRequest("DELETE", url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}
