package server

import "testing"

// TestAdminExtras covers admin endpoints the CRUD/error suites don't touch:
// list endpoints, health, export/import round-trip, seed --force, reset with
// key reset, key rotation, and the non-default create branches.
func TestAdminExtras(t *testing.T) {
	hts, _, _ := newTestServer(t)
	base := hts.URL + "/admin/api"

	// Health + list endpoints (handleHealth / listGroups / listApps).
	if code, h := getJSON(t, base+"/health"); code != 200 || h["tenantId"] != tenant {
		t.Fatalf("admin health: %d %v", code, h)
	}
	if code, g := getJSON(t, base+"/groups"); code != 200 || g["value"] == nil {
		t.Fatalf("list groups: %d %v", code, g)
	}
	if code, a := getJSON(t, base+"/apps"); code != 200 || int(a["count"].(float64)) < 2 {
		t.Fatalf("list apps: %d %v", code, a)
	}

	// Export → import round-trip (exportDirectory + importDirectory happy path).
	code, snap := getJSON(t, base+"/export")
	if code != 200 || snap["users"] == nil {
		t.Fatalf("export: %d %v", code, snap)
	}
	if code, r := postJSON(t, base+"/import", snap); code != 200 || r["imported"] == nil {
		t.Fatalf("import round-trip: %d %v", code, r)
	}

	// seed --force (re-seeds even when already seeded).
	if code, s := postJSON(t, base+"/seed", map[string]any{"force": true}); code != 200 || s["seeded"] != true {
		t.Fatalf("seed --force: %d %v", code, s)
	}
	// reset with key reset (resetKeys branch).
	if code, r := postJSON(t, base+"/reset", map[string]any{"reseed": true, "resetKeys": true}); code != 200 || r["reset"] != true {
		t.Fatalf("reset resetKeys: %d %v", code, r)
	}

	// Signing-key rotation with a zero grace window.
	if code, rot := postJSON(t, base+"/signing-keys/rotate", map[string]any{"graceSeconds": 0}); code != 200 || rot["activeKid"] == nil {
		t.Fatalf("rotate: %d %v", code, rot)
	}

	// createTenant with explicit fields (non-generated branch).
	if code, ten := postJSON(t, base+"/tenants", map[string]any{
		"displayName": "Explicit Ltd", "initialDomain": "explicit.onmicrosoft.com",
	}); code != 201 || ten["initialDomain"] != "explicit.onmicrosoft.com" {
		t.Fatalf("create tenant explicit: %d %v", code, ten)
	}

	// createWorkspaceIdentity with an explicit workspace name/id.
	if code, wi := postJSON(t, base+"/workspace-identities", map[string]any{
		"workspaceName": "Named WS", "workspaceId": "00000000-0000-0000-0000-00000000ab01",
	}); code != 201 || wi["workspaceName"] != "Named WS" {
		t.Fatalf("create WI explicit: %d %v", code, wi)
	}

	// createApp with the confidential + appIdUri branch.
	if code, app := postJSON(t, base+"/apps", map[string]any{
		"displayName": "Conf App", "isConfidential": true, "appIdUri": "api://conf",
	}); code != 201 || app["isConfidential"] != true {
		t.Fatalf("create confidential app: %d %v", code, app)
	}

	// deletePasskey for a missing credential → 404 (requireRow).
	if code := deleteStatus(t, base+"/users/"+aliceID+"/passkeys/does-not-exist"); code != 404 {
		t.Fatalf("delete missing passkey: want 404, got %d", code)
	}
}
