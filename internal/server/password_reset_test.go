package server

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// ropcStatus attempts a ROPC sign-in and reports the HTTP status, so a test can
// assert that a credential works or has stopped working.
func ropcStatus(t *testing.T, hts, upn, password string) int {
	t.Helper()
	resp, _ := postForm(t, http.DefaultClient, hts+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type": {"password"}, "client_id": {spaID},
		"username": {upn}, "password": {password},
		"scope": {"api://" + spaID + "/access_as_user"},
	})
	return resp.StatusCode
}

// TestPasswordReset covers Graph's resetPassword on the password
// authentication method. The reset has to be REAL to be worth anything: the
// old credential must stop working and the new one must sign in.
func TestPasswordReset(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)
	const upn = "alice@entraemulator.dev"
	const oldPassword = "Password1!"
	resetURL := hts.URL + "/graph/v1.0/users/" + aliceID +
		"/authentication/passwordMethods/28c10230-6103-485e-b985-444c60001490/resetPassword"

	// Baseline: the seeded credential works.
	if s := ropcStatus(t, hts.URL, upn, oldPassword); s != http.StatusOK {
		t.Fatalf("seeded password should sign in, got %d", s)
	}

	t.Run("an explicit new password takes effect and revokes the old one", func(t *testing.T) {
		const newPassword = "Rotated1!Secret"
		code, body := postJSONAuth(t, resetURL, app, map[string]any{"newPassword": newPassword})
		if code != http.StatusAccepted {
			t.Fatalf("resetPassword: want 202, got %d %v", code, body)
		}
		if s := ropcStatus(t, hts.URL, upn, newPassword); s != http.StatusOK {
			t.Fatalf("the new password must sign in, got %d", s)
		}
		if s := ropcStatus(t, hts.URL, upn, oldPassword); s == http.StatusOK {
			t.Fatal("the OLD password still signs in — the reset did not take effect")
		}
	})

	t.Run("omitting the password returns a generated one that works", func(t *testing.T) {
		code, body := postJSONAuth(t, resetURL, app, map[string]any{})
		if code != http.StatusAccepted {
			t.Fatalf("system-generated reset: want 202, got %d %v", code, body)
		}
		generated, _ := body["newPassword"].(string)
		if generated == "" {
			t.Fatalf("a system-generated reset must return the password: %v", body)
		}
		if body["@odata.type"] != "#microsoft.graph.passwordResetResponse" {
			t.Errorf("@odata.type = %v", body["@odata.type"])
		}
		if s := ropcStatus(t, hts.URL, upn, generated); s != http.StatusOK {
			t.Fatalf("the generated password must sign in, got %d", s)
		}
	})

	t.Run("unknown user and wrong method id are 404", func(t *testing.T) {
		bad := hts.URL + "/graph/v1.0/users/" + store.NewGUID() +
			"/authentication/passwordMethods/28c10230-6103-485e-b985-444c60001490/resetPassword"
		if code, _ := postJSONAuth(t, bad, app, map[string]any{"newPassword": "X1!aaaaa"}); code != http.StatusNotFound {
			t.Errorf("unknown user: want 404, got %d", code)
		}
		wrongMethod := hts.URL + "/graph/v1.0/users/" + aliceID +
			"/authentication/passwordMethods/" + store.NewGUID() + "/resetPassword"
		if code, _ := postJSONAuth(t, wrongMethod, app, map[string]any{"newPassword": "X1!aaaaa"}); code != http.StatusNotFound {
			t.Errorf("wrong method id: want 404, got %d", code)
		}
	})
}
