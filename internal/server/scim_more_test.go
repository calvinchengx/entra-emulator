package server

import (
	"bytes"
	"net/http"
	"net/url"
	"testing"
)

// TestSCIMDiscoveryAndUserOps covers the discovery endpoints, user filter/PUT/
// PATCH paths, and error branches the lifecycle test doesn't reach.
func TestSCIMDiscoveryAndUserOps(t *testing.T) {
	hts, _, _ := newTestServer(t)
	base := hts.URL + "/scim/v2"

	// Discovery: ResourceTypes + Schemas.
	if code, rt := scimReq(t, "GET", base+"/ResourceTypes", nil); code != 200 || int(rt["totalResults"].(float64)) != 2 {
		t.Fatalf("ResourceTypes: %d %v", code, rt)
	}
	if code, sc := scimReq(t, "GET", base+"/Schemas", nil); code != 200 || int(sc["totalResults"].(float64)) != 2 {
		t.Fatalf("Schemas: %d %v", code, sc)
	}

	// List + userName filter + unsupported filter.
	if code, l := scimReq(t, "GET", base+"/Users?startIndex=1&count=1", nil); code != 200 || int(l["totalResults"].(float64)) < 2 {
		t.Fatalf("list users paged: %d %v", code, l)
	}
	if code, f := scimReq(t, "GET", base+"/Users?filter="+url.QueryEscape(`userName eq "alice@entraemulator.dev"`), nil); code != 200 || int(f["totalResults"].(float64)) != 1 {
		t.Fatalf("userName filter: %d %v", code, f)
	}
	if code, _ := scimReq(t, "GET", base+"/Users?filter="+url.QueryEscape(`email eq "x"`), nil); code != 400 {
		t.Fatalf("unsupported filter: want 400, got %d", code)
	}

	// Create: missing userName → 400; valid → 201.
	if code, _ := scimReq(t, "POST", base+"/Users", map[string]any{"active": true}); code != 400 {
		t.Fatalf("create no userName: want 400, got %d", code)
	}
	code, created := scimReq(t, "POST", base+"/Users", map[string]any{
		"userName":    "scim.user@entraemulator.dev",
		"displayName": "SCIM User",
		"name":        map[string]any{"givenName": "Scim", "familyName": "User"},
		"password":    "Passw0rd!",
		"active":      true,
	})
	if code != 201 {
		t.Fatalf("create user: %d %v", code, created)
	}
	uid := created["id"].(string)

	// PUT replace.
	if code, _ := scimReq(t, "PUT", base+"/Users/"+uid, map[string]any{
		"userName": "scim.user@entraemulator.dev", "displayName": "Replaced",
	}); code != 200 {
		t.Fatalf("PUT replace: %d", code)
	}

	patch := func(ops ...map[string]any) int {
		code, _ := scimReq(t, "PATCH", base+"/Users/"+uid, map[string]any{
			"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"}, "Operations": ops,
		})
		return code
	}
	// Pathed replaces (active/displayName/name.*) + a remove op.
	if patch(
		map[string]any{"op": "replace", "path": "active", "value": false},
		map[string]any{"op": "replace", "path": "displayName", "value": "Patched"},
		map[string]any{"op": "replace", "path": "name.givenName", "value": "Pat"},
		map[string]any{"op": "replace", "path": "name.familyName", "value": "Ched"},
		map[string]any{"op": "remove", "path": "nickName"},
	) != 200 {
		t.Fatal("pathed patch")
	}
	// No-path replace (value is an attribute object).
	if patch(map[string]any{"op": "replace", "value": map[string]any{"displayName": "NoPath", "active": true}}) != 200 {
		t.Fatal("no-path patch")
	}

	// Delete → 204, then get → 404.
	if code, _ := scimReq(t, "DELETE", base+"/Users/"+uid, nil); code != 204 {
		t.Fatalf("delete user: %d", code)
	}
	if code, _ := scimReq(t, "GET", base+"/Users/"+uid, nil); code != 404 {
		t.Fatalf("get deleted user: want 404, got %d", code)
	}

	// Malformed body → 400 (decode error branch).
	req, _ := http.NewRequest("POST", base+"/Users", bytes.NewReader([]byte("{bad")))
	req.Header.Set("Authorization", "Bearer "+scimToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("malformed create: want 400, got %d", resp.StatusCode)
	}
}

// TestSCIMGroupOps covers group list/filter/create-with-members/get/patch/delete.
func TestSCIMGroupOps(t *testing.T) {
	hts, _, _ := newTestServer(t)
	base := hts.URL + "/scim/v2"

	// A member to add.
	_, u := scimReq(t, "POST", base+"/Users", map[string]any{"userName": "grp.member@entraemulator.dev"})
	uid := u["id"].(string)

	// List + displayName filter (seeded Engineering group).
	if code, l := scimReq(t, "GET", base+"/Groups", nil); code != 200 || int(l["totalResults"].(float64)) < 1 {
		t.Fatalf("list groups: %d %v", code, l)
	}
	if code, l := scimReq(t, "GET", base+"/Groups?filter="+url.QueryEscape(`displayName eq "Engineering"`), nil); code != 200 || int(l["totalResults"].(float64)) != 1 {
		t.Fatalf("group filter: %d %v", code, l)
	}

	// Create: missing displayName → 400; valid with a member → 201.
	if code, _ := scimReq(t, "POST", base+"/Groups", map[string]any{}); code != 400 {
		t.Fatalf("create no displayName: want 400, got %d", code)
	}
	code, g := scimReq(t, "POST", base+"/Groups", map[string]any{
		"displayName": "SCIM Group", "members": []map[string]any{{"value": uid}},
	})
	if code != 201 {
		t.Fatalf("create group: %d %v", code, g)
	}
	gid := g["id"].(string)

	if code, got := scimReq(t, "GET", base+"/Groups/"+gid, nil); code != 200 || got["displayName"] != "SCIM Group" {
		t.Fatalf("get group: %d %v", code, got)
	}

	patchG := func(ops ...map[string]any) int {
		code, _ := scimReq(t, "PATCH", base+"/Groups/"+gid, map[string]any{
			"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"}, "Operations": ops,
		})
		return code
	}
	// Rename, add a member (array value), then remove via path filter.
	if patchG(map[string]any{"op": "replace", "path": "displayName", "value": "Renamed Group"}) != 200 {
		t.Fatal("rename group")
	}
	if patchG(map[string]any{"op": "add", "path": "members", "value": []map[string]any{{"value": aliceID}}}) != 200 {
		t.Fatal("add member")
	}
	if patchG(map[string]any{"op": "remove", "path": `members[value eq "` + uid + `"]`}) != 200 {
		t.Fatal("remove member via filter")
	}

	if code, _ := scimReq(t, "DELETE", base+"/Groups/"+gid, nil); code != 204 {
		t.Fatalf("delete group: %d", code)
	}
	if code, _ := scimReq(t, "GET", base+"/Groups/"+gid, nil); code != 404 {
		t.Fatalf("get deleted group: want 404, got %d", code)
	}
}

// TestSCIMErrorPaths covers the not-found / conflict / malformed branches of the
// mutating handlers (delete/PUT/PATCH on missing ids, duplicate create).
func TestSCIMErrorPaths(t *testing.T) {
	hts, _, _ := newTestServer(t)
	base := hts.URL + "/scim/v2"
	missing := "00000000-0000-0000-0000-0000000000ff"
	patchOp := map[string]any{"Operations": []any{}}

	code := func(method, u string, body any) int { c, _ := scimReq(t, method, u, body); return c }
	expect(t, "delete missing user", code("DELETE", base+"/Users/"+missing, nil), 404)
	expect(t, "delete missing group", code("DELETE", base+"/Groups/"+missing, nil), 404)
	expect(t, "PUT missing user", code("PUT", base+"/Users/"+missing, map[string]any{"userName": "x"}), 404)
	expect(t, "PATCH missing user", code("PATCH", base+"/Users/"+missing, patchOp), 404)
	expect(t, "PATCH missing group", code("PATCH", base+"/Groups/"+missing, patchOp), 404)

	// Duplicate userName (alice is seeded) → 409 conflict via writeStoreErr.
	expect(t, "duplicate user", code("POST", base+"/Users", map[string]any{"userName": "alice@entraemulator.dev"}), 409)

	// Malformed PATCH body → 400 (decodePatch error) on a real user.
	_, u := scimReq(t, "POST", base+"/Users", map[string]any{"userName": "patch.err@entraemulator.dev"})
	req, _ := http.NewRequest("PATCH", base+"/Users/"+u["id"].(string), bytes.NewReader([]byte("{bad")))
	req.Header.Set("Authorization", "Bearer "+scimToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	expect(t, "malformed patch", resp.StatusCode, 400)
}
