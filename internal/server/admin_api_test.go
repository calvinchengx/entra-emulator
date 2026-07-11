package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// putJSON issues a PUT with a JSON body.
func putJSON(t *testing.T, url string, body map[string]any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPut, url, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// These tests exercise the admin REST API directly (docs/11-admin-api.md) —
// the portal's contract and the write path underpinning several roadmap items
// (directory CRUD, tenants #15b, workspace identities #16, key credentials #13,
// custom extensions #10, passkeys #11). They reuse postJSON/getJSON/patchJSON/
// deleteStatus from the sibling test files.

func TestAdminUserCRUD(t *testing.T) {
	hts, _, _ := newTestServer(t)
	base := hts.URL + "/admin/api/users"

	// Validation: missing required fields → 400.
	if code, _ := postJSON(t, base, map[string]any{"displayName": "No UPN"}); code != 400 {
		t.Fatalf("missing UPN: want 400, got %d", code)
	}

	// Create.
	code, created := postJSON(t, base, map[string]any{
		"userPrincipalName": "dave@entraemulator.dev", "displayName": "Dave Example",
		"mail": "dave@entraemulator.dev", "password": "S3cret!pass",
	})
	if code != 201 {
		t.Fatalf("create user: %d %v", code, created)
	}
	id, _ := created["id"].(string)
	if created["hasPassword"] != true {
		t.Fatalf("hasPassword should be true: %v", created)
	}

	// Duplicate UPN → 409.
	if code, _ := postJSON(t, base, map[string]any{
		"userPrincipalName": "dave@entraemulator.dev", "displayName": "Dupe",
	}); code != 409 {
		t.Fatalf("duplicate UPN: want 409, got %d", code)
	}

	// Get, list.
	if code, got := getJSON(t, base+"/"+id); code != 200 || got["displayName"] != "Dave Example" {
		t.Fatalf("get user: %d %v", code, got)
	}
	if code, list := getJSON(t, base); code != 200 || int(list["count"].(float64)) < 3 {
		t.Fatalf("list users: %d %v", code, list)
	}

	// Patch (displayName + clear password via null).
	if code, patched := patchJSON(t, base+"/"+id, map[string]any{
		"displayName": "Dave Renamed", "password": nil,
	}); code != 200 || patched["displayName"] != "Dave Renamed" || patched["hasPassword"] != false {
		t.Fatalf("patch user: %d %v", code, patched)
	}

	// listUserGroups (none) → 200 empty page.
	if code, groups := getJSON(t, base+"/"+id+"/groups"); code != 200 || int(groups["count"].(float64)) != 0 {
		t.Fatalf("list user groups: %d %v", code, groups)
	}

	// Delete → 204, then 404.
	if code := deleteStatus(t, base+"/"+id); code != 204 {
		t.Fatalf("delete user: %d", code)
	}
	if code, _ := getJSON(t, base+"/"+id); code != 404 {
		t.Fatalf("deleted user GET: want 404, got %d", code)
	}
}

func TestAdminGroupCRUDAndMembers(t *testing.T) {
	hts, _, _ := newTestServer(t)
	gbase := hts.URL + "/admin/api/groups"

	code, gr := postJSON(t, gbase, map[string]any{"displayName": "Sales", "description": "d"})
	if code != 201 {
		t.Fatalf("create group: %d %v", code, gr)
	}
	gid, _ := gr["id"].(string)

	// Patch.
	if code, _ := patchJSON(t, gbase+"/"+gid, map[string]any{"description": "updated"}); code != 200 {
		t.Fatalf("patch group: %d", code)
	}

	// Add member (Alice), list, remove.
	if code, _ := postJSON(t, gbase+"/"+gid+"/members", map[string]any{"userId": aliceID}); code != 204 {
		t.Fatalf("add member: %d", code)
	}
	if code, members := getJSON(t, gbase+"/"+gid+"/members"); code != 200 || int(members["count"].(float64)) != 1 {
		t.Fatalf("list members: %d %v", code, members)
	}
	// Unknown user → 400 invalid_reference.
	if code, _ := postJSON(t, gbase+"/"+gid+"/members", map[string]any{"userId": "nope"}); code != 400 {
		t.Fatalf("add unknown member: want 400, got %d", code)
	}
	if code := deleteStatus(t, gbase+"/"+gid+"/members/"+aliceID); code != 204 {
		t.Fatalf("remove member: %d", code)
	}

	// Delete group.
	if code := deleteStatus(t, gbase+"/"+gid); code != 204 {
		t.Fatalf("delete group: %d", code)
	}
	if code, _ := getJSON(t, gbase+"/"+gid); code != 404 {
		t.Fatalf("deleted group GET: want 404, got %d", code)
	}
}

func TestAdminAppCRUDAndSubcollections(t *testing.T) {
	hts, _, _ := newTestServer(t)
	abase := hts.URL + "/admin/api/apps"

	code, app := postJSON(t, abase, map[string]any{"displayName": "My App", "isConfidential": true})
	if code != 201 {
		t.Fatalf("create app: %d %v", code, app)
	}
	id, _ := app["id"].(string)

	// Patch scalar.
	if code, _ := patchJSON(t, abase+"/"+id, map[string]any{"appIdUri": "api://my-app"}); code != 200 {
		t.Fatalf("patch app: %d", code)
	}

	// Redirect URIs add/delete.
	code, ru := postJSON(t, abase+"/"+id+"/redirectUris", map[string]any{"uri": "https://app/cb", "type": "web"})
	if code != 201 {
		t.Fatalf("add redirect: %d %v", code, ru)
	}
	uriID := fmt.Sprintf("%d", int64(ru["id"].(float64)))
	if code := deleteStatus(t, abase+"/"+id+"/redirectUris/"+uriID); code != 204 {
		t.Fatalf("delete redirect: %d", code)
	}

	// Secret show-once add/delete.
	code, sec := postJSON(t, abase+"/"+id+"/secrets", map[string]any{"displayName": "s1"})
	if code != 201 || sec["secretText"] == nil {
		t.Fatalf("add secret: %d %v", code, sec)
	}
	if code := deleteStatus(t, abase+"/"+id+"/secrets/"+sec["id"].(string)); code != 204 {
		t.Fatalf("delete secret: %d", code)
	}

	// Scope add/patch/delete.
	code, sc := postJSON(t, abase+"/"+id+"/scopes", map[string]any{"value": "access_as_user"})
	if code != 201 {
		t.Fatalf("add scope: %d %v", code, sc)
	}
	scID := sc["id"].(string)
	if code, patched := patchJSON(t, abase+"/"+id+"/scopes/"+scID, map[string]any{"isEnabled": false}); code != 200 || patched["isEnabled"] != false {
		t.Fatalf("patch scope: %d %v", code, patched)
	}
	if code := deleteStatus(t, abase+"/"+id+"/scopes/"+scID); code != 204 {
		t.Fatalf("delete scope: %d", code)
	}

	// Role add/patch/delete.
	code, ro := postJSON(t, abase+"/"+id+"/roles", map[string]any{"value": "Tasks.Read.All", "allowedMemberTypes": []string{"Application"}})
	if code != 201 {
		t.Fatalf("add role: %d %v", code, ro)
	}
	roID := ro["id"].(string)
	if code, _ := patchJSON(t, abase+"/"+id+"/roles/"+roID, map[string]any{"isEnabled": false}); code != 200 {
		t.Fatalf("patch role: %d", code)
	}
	if code := deleteStatus(t, abase+"/"+id+"/roles/"+roID); code != 204 {
		t.Fatalf("delete role: %d", code)
	}

	// Key credential add/list/delete (roadmap #13).
	pem := "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----"
	code, kc := postJSON(t, abase+"/"+id+"/keyCredentials", map[string]any{"publicKey": pem, "displayName": "cert1"})
	if code != 201 {
		t.Fatalf("add key credential: %d %v", code, kc)
	}
	if code, list := getJSON(t, abase+"/"+id+"/keyCredentials"); code != 200 || int(list["count"].(float64)) != 1 {
		t.Fatalf("list key credentials: %d %v", code, list)
	}
	if code := deleteStatus(t, abase+"/"+id+"/keyCredentials/"+kc["id"].(string)); code != 204 {
		t.Fatalf("delete key credential: %d", code)
	}

	// Custom extension set/list/delete (roadmap #10).
	if code, _ := putJSON(t, abase+"/"+id+"/custom-extension", map[string]any{"endpoint": "https://ext.example/hook"}); code != 200 {
		t.Fatalf("set custom extension: %d", code)
	}
	if code, ce := getJSON(t, hts.URL+"/admin/api/custom-extensions"); code != 200 {
		t.Fatalf("list custom extensions: %d %v", code, ce)
	}
	if code := deleteStatus(t, abase+"/"+id+"/custom-extension"); code != 204 {
		t.Fatalf("delete custom extension: %d", code)
	}

	// Delete app (cascades sub-collections) → 204, then 404.
	if code := deleteStatus(t, abase+"/"+id); code != 204 {
		t.Fatalf("delete app: %d", code)
	}
	if code, _ := getJSON(t, abase+"/"+id); code != 404 {
		t.Fatalf("deleted app GET: want 404, got %d", code)
	}
}

func TestAdminTenantAndWorkspaceLists(t *testing.T) {
	hts, _, _ := newTestServer(t)

	// Tenants: list (home present), get home, get unknown → 404.
	code, tl := getJSON(t, hts.URL+"/admin/api/tenants")
	if code != 200 || len(tl["value"].([]any)) < 1 {
		t.Fatalf("list tenants: %d %v", code, tl)
	}
	if code, _ := getJSON(t, hts.URL+"/admin/api/tenants/"+tenant); code != 200 {
		t.Fatalf("get home tenant: %d", code)
	}
	if code, _ := getJSON(t, hts.URL+"/admin/api/tenants/"+store.NewGUID()); code != 404 {
		t.Fatalf("get unknown tenant: want 404, got %d", code)
	}

	// Workspace identities: create then list + get.
	code, wi := postJSON(t, hts.URL+"/admin/api/workspace-identities", map[string]any{})
	if code != 201 {
		t.Fatalf("create workspace identity: %d %v", code, wi)
	}
	if code, wl := getJSON(t, hts.URL+"/admin/api/workspace-identities"); code != 200 || len(wl["value"].([]any)) != 1 {
		t.Fatalf("list workspace identities: %d %v", code, wl)
	}
	if code, _ := getJSON(t, hts.URL+"/admin/api/workspace-identities/"+wi["id"].(string)); code != 200 {
		t.Fatalf("get workspace identity: %d", code)
	}
}

func TestAdminSystemEndpoints(t *testing.T) {
	hts, _, _ := newTestServer(t)

	// Passkeys: list for a seeded user (none) → 200 empty.
	if code, pk := getJSON(t, hts.URL+"/admin/api/users/"+aliceID+"/passkeys"); code != 200 || int(pk["count"].(float64)) != 0 {
		t.Fatalf("list passkeys: %d %v", code, pk)
	}

	// Certificate endpoints: TLS disabled in the harness → 404.
	if code, _ := getJSON(t, hts.URL+"/admin/api/certificate"); code != 404 {
		t.Fatalf("certificate meta (no TLS): want 404, got %d", code)
	}

	// Seed when already seeded → {seeded:false}.
	if code, s := postJSON(t, hts.URL+"/admin/api/seed", map[string]any{}); code != 200 || s["seeded"] != false {
		t.Fatalf("seed already-seeded: %d %v", code, s)
	}

	// Reset with reseed keeps the directory populated.
	if code, r := postJSON(t, hts.URL+"/admin/api/reset", map[string]any{"reseed": true}); code != 200 || r["reset"] != true {
		t.Fatalf("reset: %d %v", code, r)
	}
	if code, list := getJSON(t, hts.URL+"/admin/api/users"); code != 200 || int(list["count"].(float64)) < 2 {
		t.Fatalf("users after reseed: %d %v", code, list)
	}
}
