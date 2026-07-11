package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calvinchengx/entra-emulator/emulator"
)

const resourceAudience = "api://docs-api"

// forgeAccessToken uses the emulator's admin token forge to mint an access
// token with a chosen audience, user subject, and groups claim — exactly the
// shape a real Entra access token for this resource would carry.
func forgeAccessToken(t *testing.T, emu *emulator.Emulator, oid string, groups []string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"tokenType":   "access",
		"userId":      oid,
		"audience":    resourceAudience,
		"scopes":      []string{"access_as_user"},
		"extraClaims": map[string]any{"groups": groups},
	})
	resp, err := emu.HTTPClient().Post(emu.Origin+"/admin/api/tokens", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Token == "" {
		t.Fatalf("forge returned no token (status %d)", resp.StatusCode)
	}
	return out.Token
}

func newResourceAPI(t *testing.T, emu *emulator.Emulator) (*httptest.Server, *InMemoryPDP) {
	t.Helper()
	pdp := NewInMemoryPDP()
	srv := &ResourceServer{
		Validator: &TokenValidator{
			JWKSURL:  emu.JWKSURL(),
			Issuer:   emu.Issuer,
			Audience: resourceAudience,
			Client:   emu.HTTPClient(),
		},
		PDP: pdp,
	}
	api := httptest.NewServer(srv.Handler())
	t.Cleanup(api.Close)
	return api, pdp
}

func call(t *testing.T, method, url, bearer string) int {
	t.Helper()
	req, _ := http.NewRequest(method, url, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestExternalizedAuthz(t *testing.T) {
	emu := emulator.StartT(t)
	api, pdp := newResourceAPI(t, emu)

	// Policy: Alice may read doc:readme directly; the "engineering" group may
	// read doc:handbook. Nobody has writer on doc:readme.
	pdp.Write("user:"+emulator.AliceOID, "reader", "doc:readme")
	pdp.Write("group:engineering#member", "reader", "doc:handbook")

	aliceToken := forgeAccessToken(t, emu, emulator.AliceOID, []string{"engineering"})

	// Direct user tuple → allowed.
	if code := call(t, "GET", api.URL+"/documents/readme", aliceToken); code != 200 {
		t.Fatalf("read readme (direct grant): want 200, got %d", code)
	}
	// No writer tuple → denied by the PDP (authenticated but not authorized).
	if code := call(t, "POST", api.URL+"/documents/readme", aliceToken); code != 403 {
		t.Fatalf("write readme (no grant): want 403, got %d", code)
	}
	// Group-derived tuple → allowed via the groups claim.
	if code := call(t, "GET", api.URL+"/documents/handbook", aliceToken); code != 200 {
		t.Fatalf("read handbook (group grant): want 200, got %d", code)
	}
	// A document with no tuple at all → denied.
	if code := call(t, "GET", api.URL+"/documents/secret", aliceToken); code != 403 {
		t.Fatalf("read secret (no grant): want 403, got %d", code)
	}

	// Missing token → 401 (authentication failure, never reaches the PDP).
	if code := call(t, "GET", api.URL+"/documents/readme", ""); code != 401 {
		t.Fatalf("no token: want 401, got %d", code)
	}

	// Wrong-audience token → 401. Mint one for a different resource.
	wrongAud := forgeWrongAudience(t, emu)
	if code := call(t, "GET", api.URL+"/documents/readme", wrongAud); code != 401 {
		t.Fatalf("wrong-audience token: want 401, got %d", code)
	}
}

func forgeWrongAudience(t *testing.T, emu *emulator.Emulator) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"tokenType": "access", "userId": emulator.AliceOID, "audience": "api://some-other-api",
	})
	resp, err := emu.HTTPClient().Post(emu.Origin+"/admin/api/tokens", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out.Token
}
