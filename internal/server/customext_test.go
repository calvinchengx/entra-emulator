package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeExtension is a webhook implementing the onTokenIssuanceStart contract.
// It records the request it received and returns the given claims.
type fakeExtension struct {
	claims     map[string]any
	gotType    string
	gotUserUPN string
	gotBearer  string
	hang       bool // if true, block until the caller cancels (timeout test)
}

func (f *fakeExtension) handler(w http.ResponseWriter, r *http.Request) {
	if f.hang {
		// Sleep well past the callout timeout so the emulator gives up first;
		// a finite sleep keeps httptest shutdown deterministic.
		time.Sleep(2 * time.Second)
		return
	}
	raw, _ := io.ReadAll(r.Body)
	var req map[string]any
	_ = json.Unmarshal(raw, &req)
	f.gotType, _ = req["type"].(string)
	f.gotBearer = r.Header.Get("Authorization")
	if data, ok := req["data"].(map[string]any); ok {
		if ac, ok := data["authenticationContext"].(map[string]any); ok {
			if u, ok := ac["user"].(map[string]any); ok {
				f.gotUserUPN, _ = u["userPrincipalName"].(string)
			}
		}
	}
	resp := map[string]any{
		"data": map[string]any{
			"@odata.type": "microsoft.graph.onTokenIssuanceStartResponseData",
			"actions": []map[string]any{{
				"@odata.type": "microsoft.graph.tokenIssuanceStart.provideClaimsForToken",
				"claims":      f.claims,
			}},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func configureExtension(t *testing.T, origin, appID string, body map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("PUT", origin+"/admin/api/apps/"+appID+"/custom-extension", strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("configure extension: want 200, got %d", resp.StatusCode)
	}
}

func TestCustomExtensionMergesClaims(t *testing.T) {
	hts, _, _ := newTestServer(t)

	ext := &fakeExtension{claims: map[string]any{
		"CustomRoles": []string{"Writer", "Editor"},
		"DateOfBirth": "01/01/2000",
	}}
	extSrv := httptest.NewServer(http.HandlerFunc(ext.handler))
	defer extSrv.Close()

	configureExtension(t, hts.URL, spaID, map[string]any{"endpoint": extSrv.URL})

	body := driveAuthCode(t, hts, "verifier-customext-0123456789abcdefghijklmno")
	idc := decodeJWTPayload(t, body["id_token"].(string))

	// The webhook received the documented request shape + the user.
	if ext.gotType != "microsoft.graph.authenticationEvent.tokenIssuanceStart" {
		t.Fatalf("webhook got wrong event type: %q", ext.gotType)
	}
	if ext.gotUserUPN != "alice@entraemulator.dev" {
		t.Fatalf("webhook got wrong user: %q", ext.gotUserUPN)
	}
	if !strings.HasPrefix(ext.gotBearer, "Bearer ") {
		t.Fatalf("callout should carry a system bearer token, got %q", ext.gotBearer)
	}
	// The returned custom claims are merged into the token.
	if idc["DateOfBirth"] != "01/01/2000" {
		t.Fatalf("custom claim not merged: %v", idc)
	}
	roles, _ := json.Marshal(idc["CustomRoles"])
	if string(roles) != `["Writer","Editor"]` {
		t.Fatalf("CustomRoles not merged: %s", roles)
	}
}

func TestCustomExtensionCannotOverrideProtocolClaims(t *testing.T) {
	hts, _, _ := newTestServer(t)

	ext := &fakeExtension{claims: map[string]any{
		"tid":   "hijacked-tenant",
		"iss":   "https://evil.example",
		"extra": "ok",
	}}
	extSrv := httptest.NewServer(http.HandlerFunc(ext.handler))
	defer extSrv.Close()
	configureExtension(t, hts.URL, spaID, map[string]any{"endpoint": extSrv.URL})

	body := driveAuthCode(t, hts, "verifier-protect-0123456789abcdefghijklmnop")
	idc := decodeJWTPayload(t, body["id_token"].(string))

	if idc["tid"] == "hijacked-tenant" || idc["iss"] == "https://evil.example" {
		t.Fatalf("extension overrode a protocol claim: tid=%v iss=%v", idc["tid"], idc["iss"])
	}
	if idc["extra"] != "ok" {
		t.Fatal("non-protocol custom claim should still be merged")
	}
}

func TestCustomExtensionAllowlist(t *testing.T) {
	hts, _, _ := newTestServer(t)

	ext := &fakeExtension{claims: map[string]any{"Wanted": "yes", "Unwanted": "no"}}
	extSrv := httptest.NewServer(http.HandlerFunc(ext.handler))
	defer extSrv.Close()
	configureExtension(t, hts.URL, spaID, map[string]any{
		"endpoint": extSrv.URL, "claims": []string{"Wanted"},
	})

	body := driveAuthCode(t, hts, "verifier-allowlist-0123456789abcdefghijklmn")
	idc := decodeJWTPayload(t, body["id_token"].(string))
	if idc["Wanted"] != "yes" {
		t.Fatal("allowlisted claim should be merged")
	}
	if _, present := idc["Unwanted"]; present {
		t.Fatal("non-allowlisted claim must be dropped")
	}
}

func TestCustomExtensionTimeoutAndContinue(t *testing.T) {
	hts, _, _ := newTestServer(t)

	ext := &fakeExtension{claims: map[string]any{"X": "y"}, hang: true}
	extSrv := httptest.NewServer(http.HandlerFunc(ext.handler))
	defer extSrv.Close()

	// 200ms timeout so the test is fast; the webhook never responds.
	configureExtension(t, hts.URL, spaID, map[string]any{
		"endpoint": extSrv.URL, "timeoutMs": 200,
	})

	// The flow still completes and issues a valid token, just unenriched.
	body := driveAuthCode(t, hts, "verifier-timeout-0123456789abcdefghijklmnop")
	if body["id_token"] == nil {
		t.Fatal("token should still be issued when the webhook times out")
	}
	idc := decodeJWTPayload(t, body["id_token"].(string))
	if _, present := idc["X"]; present {
		t.Fatal("no enrichment should occur on webhook timeout")
	}
	if idc["oid"] != aliceID {
		t.Fatalf("token should still be a valid Alice token: %v", idc["oid"])
	}
}
