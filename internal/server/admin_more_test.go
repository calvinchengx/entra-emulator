package server

import (
	"net/http"
	"net/url"
	"testing"
)

// TestAdminMoreBranches covers admin success-path branches the CRUD/error
// suites don't reach: member removal, full app create, secret expiry, password
// patch, and reset without reseed.
func TestAdminMoreBranches(t *testing.T) {
	hts, _, _ := newTestServer(t)
	base := hts.URL + "/admin/api"

	// removeMember success: add Alice to a group, then remove her (204).
	_, g := postJSON(t, base+"/groups", map[string]any{"displayName": "RM Group"})
	gid := g["id"].(string)
	if code, _ := postJSON(t, base+"/groups/"+gid+"/members", map[string]any{"userId": aliceID}); code != 204 {
		t.Fatalf("add member: %d", code)
	}
	if code := deleteStatus(t, base+"/groups/"+gid+"/members/"+aliceID); code != 204 {
		t.Fatalf("remove member: %d", code)
	}

	// createApp with the confidential + appIdUri + group-claims body branches.
	code, app := postJSON(t, base+"/apps", map[string]any{
		"displayName": "Full App", "isConfidential": true, "appIdUri": "api://full-app",
		"groupMembershipClaims": "SecurityGroup", "groupOverageLimit": 50,
	})
	if code != 201 {
		t.Fatalf("create full app: %d %v", code, app)
	}
	aid := app["id"].(string)

	// addSecret with an expiry window.
	if code, s := postJSON(t, base+"/apps/"+aid+"/secrets", map[string]any{
		"displayName": "expiring", "expiresInDays": 30,
	}); code != 201 || s["expiresAt"] == nil {
		t.Fatalf("secret with expiry: %d %v", code, s)
	}

	// patchUser password (the hash branch) → hasPassword true.
	_, u := postJSON(t, base+"/users", map[string]any{
		"userPrincipalName": "pw@entraemulator.dev", "displayName": "PW User",
	})
	uid := u["id"].(string)
	if code, p := patchJSON(t, base+"/users/"+uid, map[string]any{"password": "N3wPassw0rd!"}); code != 200 || p["hasPassword"] != true {
		t.Fatalf("patch password: %d %v", code, p)
	}
	// Clear the password with an explicit null → hasPassword false.
	if code, p := patchJSON(t, base+"/users/"+uid, map[string]any{"password": nil}); code != 200 || p["hasPassword"] != false {
		t.Fatalf("clear password: %d %v", code, p)
	}

	// patchWorkspaceIdentity to a valid state.
	_, wi := postJSON(t, base+"/workspace-identities", map[string]any{})
	if code, _ := patchJSON(t, base+"/workspace-identities/"+wi["id"].(string), map[string]any{"state": "Provisioning"}); code != 200 {
		t.Fatalf("patch WI state: %d", code)
	}

	// reset WITHOUT reseed → directory emptied (do this last).
	if code, r := postJSON(t, base+"/reset", map[string]any{"reseed": false}); code != 200 || r["reseeded"] != false {
		t.Fatalf("reset no-reseed: %d %v", code, r)
	}
	if code, list := getJSON(t, base+"/users"); code != 200 || int(list["count"].(float64)) != 0 {
		t.Fatalf("after no-reseed reset, users should be empty: %v", list)
	}
}

// TestAdminSeedAfterReset covers seed's not-yet-seeded branch: reset without
// reseed empties the directory, then seed re-populates it.
func TestAdminSeedAfterReset(t *testing.T) {
	hts, _, _ := newTestServer(t)
	base := hts.URL + "/admin/api"
	if code, _ := postJSON(t, base+"/reset", map[string]any{"reseed": false}); code != 200 {
		t.Fatalf("reset: %d", code)
	}
	if code, s := postJSON(t, base+"/seed", map[string]any{}); code != 200 || s["seeded"] != true {
		t.Fatalf("seed after empty reset: want seeded=true, got %d %v", code, s)
	}
	if code, list := getJSON(t, base+"/users"); code != 200 || int(list["count"].(float64)) < 2 {
		t.Fatalf("seed should re-populate users: %v", list)
	}
}

// TestDeviceCodeExpired covers grantDeviceCode's expiry branch via clock control.
func TestDeviceCodeExpired(t *testing.T) {
	hts, _, _ := newTestServer(t)
	base := hts.URL + "/" + tenant + "/oauth2/v2.0"
	_, da := postForm(t, http.DefaultClient, base+"/devicecode", url.Values{
		"client_id": {spaID}, "scope": {"openid"},
	})

	// Advance the emulator clock past the device-code lifetime (default 900s).
	if code, _ := postJSON(t, hts.URL+"/admin/api/clock", map[string]any{"advanceSeconds": 2000}); code != 200 {
		t.Fatalf("advance clock: %d", code)
	}

	resp, body := postForm(t, http.DefaultClient, base+"/token", url.Values{
		"grant_type": {"device_code"}, "device_code": {da["device_code"].(string)}, "client_id": {spaID},
	})
	if resp.StatusCode == 200 {
		t.Fatalf("expired device code should not mint a token: %v", body)
	}
}
