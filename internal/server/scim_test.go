package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"
)

const scimToken = "scim-secret-token" // scim.DefaultToken

// scimReq issues an authenticated SCIM request and returns status + decoded body.
func scimReq(t *testing.T, method, u string, body any) (int, map[string]any) {
	t.Helper()
	var r io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		r = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, u, r)
	req.Header.Set("Authorization", "Bearer "+scimToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestSCIMAuthAndDiscovery(t *testing.T) {
	hts, _, _ := newTestServer(t)

	// No / wrong bearer → 401.
	req, _ := http.NewRequest("GET", hts.URL+"/scim/v2/Users", nil)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("missing token: want 401, got %d", resp.StatusCode)
	}
	req.Header.Set("Authorization", "Bearer nope")
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("wrong token: want 401, got %d", resp.StatusCode)
	}

	// ServiceProviderConfig advertises patch + filter.
	code, cfg := scimReq(t, "GET", hts.URL+"/scim/v2/ServiceProviderConfig", nil)
	if code != 200 || cfg["patch"].(map[string]any)["supported"] != true {
		t.Fatalf("service provider config: %d %v", code, cfg)
	}
}

func TestSCIMUserLifecycle(t *testing.T) {
	hts, _, _ := newTestServer(t)
	base := hts.URL + "/scim/v2/Users"

	// Seeded users are listed.
	code, list := scimReq(t, "GET", base, nil)
	if code != 200 || int(list["totalResults"].(float64)) < 2 {
		t.Fatalf("list users: %d %v", code, list)
	}

	// Correlation filter → exactly Alice.
	code, filtered := scimReq(t, "GET", base+"?"+url.Values{"filter": {`userName eq "alice@entraemulator.dev"`}}.Encode(), nil)
	res := filtered["Resources"].([]any)
	if code != 200 || len(res) != 1 || res[0].(map[string]any)["userName"] != "alice@entraemulator.dev" {
		t.Fatalf("filter: %d %v", code, filtered)
	}

	// Create.
	code, created := scimReq(t, "POST", base, map[string]any{
		"userName":    "carol@entraemulator.dev",
		"displayName": "Carol Example",
		"name":        map[string]any{"givenName": "Carol", "familyName": "Example"},
		"emails":      []map[string]any{{"value": "carol@entraemulator.dev", "primary": true}},
		"active":      true,
		"password":    "S3cret!pass",
	})
	if code != 201 {
		t.Fatalf("create: %d %v", code, created)
	}
	id := created["id"].(string)
	if created["active"] != true || created["userName"] != "carol@entraemulator.dev" {
		t.Fatalf("created shape: %v", created)
	}

	// Duplicate userName → 409.
	if code, _ := scimReq(t, "POST", base, map[string]any{"userName": "carol@entraemulator.dev"}); code != 409 {
		t.Fatalf("duplicate userName: want 409, got %d", code)
	}

	// Get.
	if code, got := scimReq(t, "GET", base+"/"+id, nil); code != 200 || got["displayName"] != "Carol Example" {
		t.Fatalf("get: %d %v", code, got)
	}

	// PATCH replace active=false (Entra's soft-deprovision).
	code, patched := scimReq(t, "PATCH", base+"/"+id, map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{"op": "replace", "path": "active", "value": false}},
	})
	if code != 200 || patched["active"] != false {
		t.Fatalf("patch active: %d %v", code, patched)
	}

	// Delete → 204, then 404.
	if code, _ := scimReq(t, "DELETE", base+"/"+id, nil); code != 204 {
		t.Fatalf("delete: want 204, got %d", code)
	}
	if code, _ := scimReq(t, "GET", base+"/"+id, nil); code != 404 {
		t.Fatalf("get deleted: want 404, got %d", code)
	}
}

func TestSCIMGroupMembership(t *testing.T) {
	hts, _, _ := newTestServer(t)
	base := hts.URL + "/scim/v2/Groups"

	// Create a group with Alice as an initial member.
	code, g := scimReq(t, "POST", base, map[string]any{
		"displayName": "SCIM Test Group",
		"members":     []map[string]any{{"value": aliceID}},
	})
	if code != 201 {
		t.Fatalf("create group: %d %v", code, g)
	}
	gid := g["id"].(string)
	if members := g["members"].([]any); len(members) != 1 {
		t.Fatalf("initial member missing: %v", g["members"])
	}

	// PATCH remove Alice via the members[value eq "id"] path.
	code, _ = scimReq(t, "PATCH", base+"/"+gid, map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{"op": "remove", "path": `members[value eq "` + aliceID + `"]`}},
	})
	if code != 200 {
		t.Fatalf("patch remove member: %d", code)
	}
	_, after := scimReq(t, "GET", base+"/"+gid, nil)
	if len(after["members"].([]any)) != 0 {
		t.Fatalf("member not removed: %v", after["members"])
	}

	// Rename via PATCH replace displayName.
	code, renamed := scimReq(t, "PATCH", base+"/"+gid, map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{"op": "replace", "path": "displayName", "value": "Renamed Group"}},
	})
	if code != 200 || renamed["displayName"] != "Renamed Group" {
		t.Fatalf("rename: %d %v", code, renamed)
	}

	if code, _ := scimReq(t, "DELETE", base+"/"+gid, nil); code != 204 {
		t.Fatalf("delete group: %d", code)
	}
}
