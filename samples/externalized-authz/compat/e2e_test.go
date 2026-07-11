//go:build pdp_integration

package compat

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/calvinchengx/entra-emulator/emulator"
	"github.com/calvinchengx/entra-emulator/samples/externalized-authz/authz"
)

// This file proves the *full* pattern end-to-end against a real engine: the
// embedded emulator issues a genuine RS256 token, the sample's ResourceServer
// validates it via JWKS (authN), then asks the engine-backed PDP (authZ). It
// catches claim-mapping regressions (oid→subject, groups→userset) that the
// pure contract test can't.

const resourceAudience = "api://docs-api"

// e2eFacts are the canonical facts rebased onto the emulator's real Alice oid,
// so the seeded grants line up with the token the emulator actually mints.
func e2eFacts(aliceOID string) []Fact {
	return []Fact{
		{"user:" + aliceOID, "reader", "doc:readme"},
		{"group:eng#member", "reader", "doc:handbook"},
	}
}

// runE2E drives the real ResourceServer over HTTP with a real emulator token,
// backed by the harness's PDP.
func runE2E(t *testing.T, h PDPHarness) {
	t.Helper()
	h.Start(t)
	t.Cleanup(h.Close)

	emu := emulator.StartT(t)
	h.Seed(t, e2eFacts(emulator.AliceOID))

	srv := &authz.ResourceServer{
		Validator: &authz.TokenValidator{
			JWKSURL:  emu.JWKSURL(),
			Issuer:   emu.Issuer,
			Audience: resourceAudience,
			Client:   emu.HTTPClient(),
		},
		PDP: h.PDP(),
	}
	api := httptest.NewServer(srv.Handler())
	t.Cleanup(api.Close)

	token := forgeToken(t, emu, emulator.AliceOID, []string{"eng"})

	cases := []struct {
		name, method, path, bearer string
		want                       int
	}{
		{"direct reader → 200", "GET", "/documents/readme", token, 200},
		{"no writer grant → 403", "POST", "/documents/readme", token, 403},
		{"group reader → 200", "GET", "/documents/handbook", token, 200},
		{"no tuple → 403", "GET", "/documents/secret", token, 403},
		{"missing token → 401", "GET", "/documents/readme", "", 401},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if got := call(t, c.method, api.URL+c.path, c.bearer); got != c.want {
				t.Fatalf("%s %s: got %d, want %d", c.method, c.path, got, c.want)
			}
		})
	}
}

// forgeToken mints an access token for a user with the given groups claim via
// the emulator's admin token forge — the shape a real Entra token carries.
func forgeToken(t *testing.T, emu *emulator.Emulator, oid string, groups []string) string {
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
