package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

func TestROPCHappyPath(t *testing.T) {
	hts, _, _ := newTestServer(t)

	resp, body := postForm(t, http.DefaultClient, hts.URL+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type": {"password"}, "client_id": {spaID},
		"username": {"alice@entraemulator.dev"}, "password": {store.SeedPassword},
		"scope": {"openid profile offline_access"},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("ropc: want 200, got %d %v", resp.StatusCode, body)
	}
	idc := decodeJWTPayload(t, body["id_token"].(string))
	if idc["oid"] != aliceID {
		t.Fatalf("ropc token should be Alice, got %v", idc["oid"])
	}
	amr, _ := json.Marshal(idc["amr"])
	if string(amr) != `["pwd"]` {
		t.Fatalf("ropc id token should carry amr:[pwd], got %s", amr)
	}
	if body["refresh_token"] == nil {
		t.Fatal("offline_access should yield a refresh token")
	}
}

func TestROPCWrongPassword(t *testing.T) {
	hts, _, _ := newTestServer(t)
	resp, body := postForm(t, http.DefaultClient, hts.URL+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type": {"password"}, "client_id": {spaID},
		"username": {"alice@entraemulator.dev"}, "password": {"wrong"},
		"scope": {"openid"},
	})
	if resp.StatusCode != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("wrong password: want 400 invalid_grant, got %d %v", resp.StatusCode, body)
	}
}

func TestROPCMissingCredentials(t *testing.T) {
	hts, _, _ := newTestServer(t)
	resp, body := postForm(t, http.DefaultClient, hts.URL+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type": {"password"}, "client_id": {spaID}, "scope": {"openid"},
	})
	if resp.StatusCode != 400 || body["error"] != "invalid_request" {
		t.Fatalf("missing creds: want 400 invalid_request, got %d %v", resp.StatusCode, body)
	}
}

func TestROPCConfidentialRequiresSecret(t *testing.T) {
	hts, _, _ := newTestServer(t)
	// Daemon is confidential; ROPC without its secret → invalid_client.
	resp, body := postForm(t, http.DefaultClient, hts.URL+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type": {"password"}, "client_id": {daemonID},
		"username": {"alice@entraemulator.dev"}, "password": {store.SeedPassword},
		"scope": {"openid"},
	})
	if resp.StatusCode != 401 || body["error"] != "invalid_client" {
		t.Fatalf("confidential ROPC without secret: want 401 invalid_client, got %d %v", resp.StatusCode, body)
	}
}
