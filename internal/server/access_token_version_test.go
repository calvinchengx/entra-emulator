package server

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// accessTokenAcceptedVersion through the admin API: validated, shown on the
// app, and an app set to 2 gets aud = its client id in client-credentials
// tokens even when the scope names its App ID URI.
func TestAccessTokenAcceptedVersion(t *testing.T) {
	hts, _, _ := newTestServer(t)
	appURL := hts.URL + "/admin/api/apps/" + daemonID
	tokenURL := hts.URL + "/" + tenant + "/oauth2/v2.0/token"

	clientCredentialsAud := func() any {
		t.Helper()
		resp, body := postForm(t, http.DefaultClient, tokenURL, url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {daemonID},
			"client_secret": {store.SeedDaemonSecret},
			"scope":         {"api://" + daemonID + "/.default"},
		})
		if resp.StatusCode != 200 {
			t.Fatalf("token: %d %v", resp.StatusCode, body)
		}
		return decodeJWTPayload(t, body["access_token"].(string))["aud"]
	}

	if aud := clientCredentialsAud(); aud != "api://"+daemonID {
		t.Fatalf("default aud = %v, want api://%s", aud, daemonID)
	}

	if code, body := patchJSON(t, appURL, map[string]any{"accessTokenAcceptedVersion": 3}); code != 400 {
		t.Fatalf("version 3 should be rejected: %d %v", code, body)
	}

	code, app := patchJSON(t, appURL, map[string]any{"accessTokenAcceptedVersion": 2})
	if code != 200 || app["accessTokenAcceptedVersion"] != float64(2) {
		t.Fatalf("set version 2: %d %v", code, app)
	}
	if aud := clientCredentialsAud(); aud != daemonID {
		t.Fatalf("version 2 aud = %v, want %s", aud, daemonID)
	}

	code, app = patchJSON(t, appURL, map[string]any{"accessTokenAcceptedVersion": 0})
	if code != 200 || app["accessTokenAcceptedVersion"] != nil {
		t.Fatalf("clear version: %d %v", code, app)
	}

	code, created := postJSON(t, hts.URL+"/admin/api/apps", map[string]any{
		"displayName": "v2 app", "accessTokenAcceptedVersion": 2,
	})
	if code != 201 || created["accessTokenAcceptedVersion"] != float64(2) {
		t.Fatalf("create with version 2: %d %v", code, created)
	}
}
