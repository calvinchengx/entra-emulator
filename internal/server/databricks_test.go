package server

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

const databricksAppID = "2ff814a6-3304-4ab8-85cb-cd0e6f879c1d"

// TestDatabricksClientCredentialsAudience proves client_credentials for the
// Azure Databricks first-party app id mints a correct-aud token without any
// registered resource app.
func TestDatabricksClientCredentialsAudience(t *testing.T) {
	hts, _, _ := newTestServer(t)
	tokenURL := hts.URL + "/" + tenant + "/oauth2/v2.0/token"
	resp, body := postForm(t, http.DefaultClient, tokenURL, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {daemonID},
		"client_secret": {store.SeedDaemonSecret},
		"scope":         {databricksAppID + "/.default"},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("want 200, got %d %v", resp.StatusCode, body)
	}
	claims := decodeJWTPayload(t, body["access_token"].(string))
	if claims["aud"] != databricksAppID {
		t.Fatalf("aud = %v, want %s", claims["aud"], databricksAppID)
	}
	if claims["appid"] != daemonID {
		t.Fatalf("appid = %v, want %s", claims["appid"], daemonID)
	}
	verifyAgainstJWKS(t, hts.URL, tenant, body["access_token"].(string))
}
