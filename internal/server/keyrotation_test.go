package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

func jwtHeaderKid(t *testing.T, jwt string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(jwt, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	var h struct {
		Kid string `json:"kid"`
	}
	_ = json.Unmarshal(raw, &h)
	return h.Kid
}

func jwksKids(t *testing.T, origin string) []string {
	t.Helper()
	resp, err := http.Get(origin + "/" + tenant + "/discovery/v2.0/keys")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&set)
	kids := make([]string, 0, len(set.Keys))
	for _, k := range set.Keys {
		kids = append(kids, k.Kid)
	}
	return kids
}

func mintCC(t *testing.T, origin string) string {
	t.Helper()
	_, body := postForm(t, http.DefaultClient, origin+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type": {"client_credentials"}, "client_id": {daemonID},
		"client_secret": {store.SeedDaemonSecret}, "scope": {"https://graph.microsoft.com/.default"},
	})
	tok, _ := body["access_token"].(string)
	if tok == "" {
		t.Fatalf("no token: %v", body)
	}
	return tok
}

func TestSigningKeyRotationWithGrace(t *testing.T) {
	hts, _, _ := newTestServer(t)

	before := jwksKids(t, hts.URL)
	if len(before) != 1 {
		t.Fatalf("expected 1 initial key, got %d", len(before))
	}
	oldKid := before[0]
	oldToken := mintCC(t, hts.URL)
	if jwtHeaderKid(t, oldToken) != oldKid {
		t.Fatalf("token not signed by the active key")
	}

	// Rotate with a 1h grace window.
	status, body := postJSON(t, hts.URL+"/admin/api/signing-keys/rotate", map[string]any{"graceSeconds": 3600})
	if status != 200 {
		t.Fatalf("rotate: %d %v", status, body)
	}
	newKid := body["activeKid"].(string)
	if newKid == oldKid {
		t.Fatal("rotation should produce a new kid")
	}

	// JWKS now publishes both keys; new tokens use the new kid.
	after := jwksKids(t, hts.URL)
	if len(after) != 2 {
		t.Fatalf("expected 2 keys during grace, got %d: %v", len(after), after)
	}
	newToken := mintCC(t, hts.URL)
	if jwtHeaderKid(t, newToken) != newKid {
		t.Fatalf("new token should use the rotated kid %s, got %s", newKid, jwtHeaderKid(t, newToken))
	}

	// A token issued before rotation still verifies against Graph (old key
	// still in JWKS during grace).
	req, _ := http.NewRequest("GET", hts.URL+"/graph/v1.0/users", nil)
	req.Header.Set("Authorization", "Bearer "+oldToken)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("pre-rotation token should still work during grace, got %d", resp.StatusCode)
	}
}

func TestSigningKeyRotationNoGraceDropsOldKey(t *testing.T) {
	hts, _, _ := newTestServer(t)
	oldKid := jwksKids(t, hts.URL)[0]

	status, body := postJSON(t, hts.URL+"/admin/api/signing-keys/rotate", map[string]any{"graceSeconds": 0})
	if status != 200 {
		t.Fatalf("rotate: %d %v", status, body)
	}
	kids := jwksKids(t, hts.URL)
	if len(kids) != 1 {
		t.Fatalf("grace=0 should immediately drop the old key, got %d keys", len(kids))
	}
	if kids[0] == oldKid {
		t.Fatal("the sole published key should be the new one")
	}
}
