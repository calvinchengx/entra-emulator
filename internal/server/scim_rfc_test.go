package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// scimReqRaw sends a body verbatim, for the malformed-payload paths that
// json.Marshal would never produce.
func scimReqRaw(t *testing.T, method, u, body string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, u, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+scimToken)
	req.Header.Set("Content-Type", "application/scim+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, u, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// Coverage for the RFC 7644 surface a real SCIM client exercises: externalId
// correlation (§3.4.2), attribute projection (§3.9), query-by-POST (§3.4.3) and
// the PatchOp paths (§3.5.2) that previously returned 200 OK while changing
// nothing.

// mkUser creates a SCIM user and returns its id.
func mkUser(t *testing.T, base string, body map[string]any) (string, map[string]any) {
	t.Helper()
	code, res := scimReq(t, "POST", base+"/Users", body)
	if code != 201 {
		t.Fatalf("create user: %d %v", code, res)
	}
	id, _ := res["id"].(string)
	if id == "" {
		t.Fatalf("create user returned no id: %v", res)
	}
	return id, res
}

func TestSCIMExternalID(t *testing.T) {
	hts, _, _ := newTestServer(t)
	base := hts.URL + "/scim/v2"

	id, created := mkUser(t, base, map[string]any{
		"userName": "ext.user@entraemulator.dev", "externalId": "ext-001", "displayName": "Ext",
	})
	if created["externalId"] != "ext-001" {
		t.Fatalf("create did not echo externalId: %v", created)
	}

	// It must survive a round trip, not just the create response.
	if _, got := scimReq(t, "GET", base+"/Users/"+id, nil); got["externalId"] != "ext-001" {
		t.Fatalf("externalId not persisted: %v", got)
	}

	// Correlation by externalId is how a provisioning client re-finds a user
	// whose local mapping it lost.
	_, list := scimReq(t, "GET", base+"/Users?filter="+url.QueryEscape(`externalId eq "ext-001"`), nil)
	if int(list["totalResults"].(float64)) != 1 {
		t.Fatalf("externalId filter: %v", list)
	}

	// PATCH replace, then remove.
	if code, patched := scimReq(t, "PATCH", base+"/Users/"+id, patchOps(
		map[string]any{"op": "replace", "path": "externalId", "value": "ext-002"},
	)); code != 200 || patched["externalId"] != "ext-002" {
		t.Fatalf("patch externalId: %d %v", code, patched)
	}
	if code, patched := scimReq(t, "PATCH", base+"/Users/"+id, patchOps(
		map[string]any{"op": "remove", "path": "externalId"},
	)); code != 200 {
		t.Fatalf("remove externalId: %d %v", code, patched)
	}
	if _, got := scimReq(t, "GET", base+"/Users/"+id, nil); got["externalId"] != nil {
		t.Fatalf("externalId not removed: %v", got)
	}

	// PUT replaces wholesale, so an absent externalId clears it.
	scimReq(t, "PATCH", base+"/Users/"+id, patchOps(
		map[string]any{"op": "replace", "path": "externalId", "value": "ext-003"}))
	if code, put := scimReq(t, "PUT", base+"/Users/"+id, map[string]any{
		"userName": "ext.user@entraemulator.dev", "displayName": "Ext",
	}); code != 200 || put["externalId"] != nil {
		t.Fatalf("PUT should clear externalId: %d %v", code, put)
	}

	// Deleting the user drops the mapping, so a recycled id cannot inherit it.
	newID, _ := mkUser(t, base, map[string]any{"userName": "ext2@entraemulator.dev", "externalId": "ext-004"})

	// Positive control on THIS key before deleting. Asserting only that the
	// post-delete count is 0 would pass just as well if the filter never
	// matched ext-004 at all — the assertion has to be able to fail.
	_, before := scimReq(t, "GET", base+"/Users?filter="+url.QueryEscape(`externalId eq "ext-004"`), nil)
	if int(before["totalResults"].(float64)) != 1 {
		t.Fatalf("externalId filter does not match ext-004 even before delete: %v", before)
	}
	if code, _ := scimReq(t, "DELETE", base+"/Users/"+newID, nil); code != 204 {
		t.Fatalf("delete user: %d", code)
	}
	_, gone := scimReq(t, "GET", base+"/Users?filter="+url.QueryEscape(`externalId eq "ext-004"`), nil)
	if int(gone["totalResults"].(float64)) != 0 {
		t.Fatalf("externalId mapping outlived its user: %v", gone)
	}
}

func TestSCIMAttributeProjection(t *testing.T) {
	hts, _, _ := newTestServer(t)
	base := hts.URL + "/scim/v2"

	id, _ := mkUser(t, base, map[string]any{
		"userName": "proj@entraemulator.dev", "displayName": "Proj",
		"name": map[string]any{"givenName": "Pro", "familyName": "Jection"},
	})

	// attributes= returns only what was asked for, plus the always-returned set.
	_, only := scimReq(t, "GET", base+"/Users/"+id+"?attributes=userName", nil)
	if only["userName"] == nil {
		t.Fatalf("requested attribute missing: %v", only)
	}
	if only["displayName"] != nil {
		t.Fatalf("unrequested attribute returned: %v", only)
	}
	for _, always := range []string{"id", "schemas", "meta"} {
		if only[always] == nil {
			t.Fatalf("always-returned %q was projected away: %v", always, only)
		}
	}

	// excludedAttributes= is the inverse, and must not drop the always-returned set.
	_, without := scimReq(t, "GET", base+"/Users/"+id+"?excludedAttributes=displayName", nil)
	if without["displayName"] != nil {
		t.Fatalf("excluded attribute still present: %v", without)
	}
	if without["userName"] == nil || without["id"] == nil {
		t.Fatalf("exclusion removed too much: %v", without)
	}

	// Sub-attribute paths address a single leaf.
	_, leaf := scimReq(t, "GET", base+"/Users/"+id+"?attributes=name.givenName", nil)
	nm, ok := leaf["name"].(map[string]any)
	if !ok || nm["givenName"] == nil {
		t.Fatalf("sub-attribute not returned: %v", leaf)
	}
	if nm["familyName"] != nil {
		t.Fatalf("sibling sub-attribute leaked: %v", nm)
	}

	// Excluding a sub-attribute removes that leaf and keeps its siblings.
	_, exLeaf := scimReq(t, "GET", base+"/Users/"+id+"?excludedAttributes=name.givenName", nil)
	exNm, ok := exLeaf["name"].(map[string]any)
	if !ok {
		t.Fatalf("excluding a leaf dropped the parent: %v", exLeaf)
	}
	if exNm["givenName"] != nil {
		t.Fatalf("excluded sub-attribute still present: %v", exNm)
	}
	if exNm["familyName"] == nil {
		t.Fatalf("excluding a leaf took its sibling: %v", exNm)
	}

	// Attribute names are case-insensitive on the wire.
	_, ci := scimReq(t, "GET", base+"/Users/"+id+"?attributes=USERNAME", nil)
	if ci["userName"] == nil {
		t.Fatalf("projection was case-sensitive: %v", ci)
	}

	// An unknown attribute name is ignored rather than fatal.
	if code, _ := scimReq(t, "GET", base+"/Users/"+id+"?attributes=nosuchattr", nil); code != 200 {
		t.Fatalf("unknown attribute name: %d", code)
	}

	// Projection applies to list responses too, not just single resources.
	_, list := scimReq(t, "GET", base+"/Users?attributes=userName", nil)
	for _, r := range list["Resources"].([]any) {
		m := r.(map[string]any)
		if m["displayName"] != nil {
			t.Fatalf("list projection leaked displayName: %v", m)
		}
	}
}

func TestSCIMSearchByPost(t *testing.T) {
	hts, _, _ := newTestServer(t)
	base := hts.URL + "/scim/v2"

	mkUser(t, base, map[string]any{"userName": "search@entraemulator.dev", "displayName": "Search"})

	// /Users/.search with a filter behaves like the GET equivalent.
	code, res := scimReq(t, "POST", base+"/Users/.search", map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:SearchRequest"},
		"filter":  `userName eq "search@entraemulator.dev"`,
	})
	if code != 200 || int(res["totalResults"].(float64)) != 1 {
		t.Fatalf("POST /Users/.search: %d %v", code, res)
	}

	// Projection travels in the body as well as the query string.
	_, projected := scimReq(t, "POST", base+"/Users/.search", map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:SearchRequest"},
		"filter":     `userName eq "search@entraemulator.dev"`,
		"attributes": []string{"userName"},
	})
	for _, r := range projected["Resources"].([]any) {
		if r.(map[string]any)["displayName"] != nil {
			t.Fatalf("search projection ignored: %v", r)
		}
	}

	if code, g := scimReq(t, "POST", base+"/Groups/.search", map[string]any{}); code != 200 {
		t.Fatalf("POST /Groups/.search: %d %v", code, g)
	}

	// The root search spans both resource types.
	code, all := scimReq(t, "POST", base+"/.search", map[string]any{})
	if code != 200 {
		t.Fatalf("POST /.search: %d %v", code, all)
	}
	kinds := map[string]bool{}
	for _, r := range all["Resources"].([]any) {
		meta := r.(map[string]any)["meta"].(map[string]any)
		kinds[meta["resourceType"].(string)] = true
	}
	if !kinds["User"] || !kinds["Group"] {
		t.Fatalf("root search did not span resource types: %v", kinds)
	}

	// startIndex / count travel in the body and page the result, while
	// totalResults keeps reporting the unpaged size.
	code, paged := scimReq(t, "POST", base+"/.search", map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:SearchRequest"},
		"count":   1, "startIndex": 1,
	})
	if code != 200 {
		t.Fatalf("paged search: %d %v", code, paged)
	}
	if got := len(paged["Resources"].([]any)); got != 1 {
		t.Fatalf("count=1 returned %d resources", got)
	}
	if int(paged["totalResults"].(float64)) < 2 {
		t.Fatalf("totalResults should count the unpaged set: %v", paged["totalResults"])
	}

	// A malformed body is a SCIM 400, not a panic or a silent full listing.
	if code, _ := scimReqRaw(t, "POST", base+"/.search", "{not json"); code != 400 {
		t.Fatalf("malformed search body: want 400, got %d", code)
	}
}

func TestSCIMPatchAttributes(t *testing.T) {
	hts, _, _ := newTestServer(t)
	base := hts.URL + "/scim/v2"

	id, _ := mkUser(t, base, map[string]any{
		"userName": "patch@entraemulator.dev", "displayName": "Patch",
		"name": map[string]any{"givenName": "Pa", "familyName": "Tch"},
	})

	// Whole complex object: previously silently ignored.
	_, res := scimReq(t, "PATCH", base+"/Users/"+id, patchOps(map[string]any{
		"op": "replace", "path": "name",
		"value": map[string]any{"givenName": "New", "familyName": "Name"},
	}))
	nm, _ := res["name"].(map[string]any)
	if nm["givenName"] != "New" || nm["familyName"] != "Name" {
		t.Fatalf("patch name object: %v", res["name"])
	}

	// Multi-valued emails, also previously ignored.
	_, res = scimReq(t, "PATCH", base+"/Users/"+id, patchOps(map[string]any{
		"op": "replace", "path": "emails",
		"value": []map[string]any{{"value": "new@entraemulator.dev", "primary": true}},
	}))
	emails, _ := res["emails"].([]any)
	if len(emails) != 1 || emails[0].(map[string]any)["value"] != "new@entraemulator.dev" {
		t.Fatalf("patch emails: %v", res["emails"])
	}

	// remove must actually clear, and the attribute must disappear.
	for _, path := range []string{"emails", "name", "displayName"} {
		if code, _ := scimReq(t, "PATCH", base+"/Users/"+id, patchOps(
			map[string]any{"op": "remove", "path": path})); code != 200 {
			t.Fatalf("remove %s: %d", path, code)
		}
	}
	_, cleared := scimReq(t, "GET", base+"/Users/"+id, nil)
	for _, path := range []string{"emails", "name", "displayName"} {
		if cleared[path] != nil {
			t.Fatalf("remove %s left it present: %v", path, cleared[path])
		}
	}

	// userName is required, so removing it must not orphan the resource.
	scimReq(t, "PATCH", base+"/Users/"+id, patchOps(map[string]any{"op": "remove", "path": "userName"}))
	if _, still := scimReq(t, "GET", base+"/Users/"+id, nil); still["userName"] != "patch@entraemulator.dev" {
		t.Fatalf("removing required userName was honoured: %v", still)
	}
}

// TestSCIMUnknownEndpointIsSCIMError pins that a stray path answers in SCIM's
// own error shape. The Go mux's plain-text 404 is unparseable to a SCIM client.
func TestSCIMUnknownEndpointIsSCIMError(t *testing.T) {
	hts, _, _ := newTestServer(t)
	code, res := scimReq(t, "GET", hts.URL+"/scim/v2/NoSuchThing", nil)
	if code != 404 {
		t.Fatalf("unknown endpoint: want 404, got %d", code)
	}
	schemas, _ := res["schemas"].([]any)
	if len(schemas) == 0 || schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" {
		t.Fatalf("404 was not a SCIM Error resource: %v", res)
	}
}

// patchOps wraps operations in a PatchOp envelope.
func patchOps(ops ...map[string]any) map[string]any {
	return map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": ops,
	}
}

// TestSCIMEmittedURLsResolve follows every URL the SCIM layer hands a client,
// rather than asserting the string looks right.
//
// A resource that advertises meta.location, or a member that advertises $ref,
// is telling the client "fetch me here". Checking the *shape* of that string
// passes even when the route behind it does not exist — which is exactly how
// /ResourceTypes/{id} and /Schemas/{id} stayed 404 while the collections
// happily advertised them. One package emitting a URL another package owns is
// the sharp edge; the only test that catches it is one that follows the link.
func TestSCIMEmittedURLsResolve(t *testing.T) {
	hts, _, _ := newTestServer(t)
	base := hts.URL + "/scim/v2"

	uid, _ := mkUser(t, base, map[string]any{
		"userName": "linked@entraemulator.dev", "displayName": "Linked",
	})
	code, grp := scimReq(t, "POST", base+"/Groups", map[string]any{
		"displayName": "Linked Group",
		"members":     []map[string]any{{"value": uid}},
	})
	if code != 201 {
		t.Fatalf("create group: %d %v", code, grp)
	}

	// Collect every URL the server emitted, from every discovery and resource
	// endpoint, then fetch each one.
	seen := map[string]string{} // url -> where it came from

	collect := func(where string, res map[string]any) {
		if meta, ok := res["meta"].(map[string]any); ok {
			if loc, ok := meta["location"].(string); ok && loc != "" {
				seen[loc] = where + " meta.location"
			}
		}
		if members, ok := res["members"].([]any); ok {
			for _, m := range members {
				if mm, ok := m.(map[string]any); ok {
					if ref, ok := mm["$ref"].(string); ok && ref != "" {
						seen[ref] = where + " members.$ref"
					}
				}
			}
		}
	}

	for _, path := range []string{"/Users", "/Groups", "/ResourceTypes", "/Schemas"} {
		code, list := scimReq(t, "GET", base+path, nil)
		if code != 200 {
			t.Fatalf("GET %s: %d", path, code)
		}
		for _, r := range list["Resources"].([]any) {
			if m, ok := r.(map[string]any); ok {
				collect(path, m)
			}
		}
	}
	if len(seen) == 0 {
		t.Fatal("no URLs were emitted at all — this test would pass vacuously")
	}

	for u, where := range seen {
		// The emitted form is what a client follows: unescaped, absolute, and
		// carrying whatever prefix the request arrived on.
		if !strings.HasPrefix(u, hts.URL+"/scim/v2/") {
			t.Errorf("%s emitted %q, which does not carry the request's /scim prefix", where, u)
			continue
		}
		code, body := scimReq(t, "GET", u, nil)
		if code != 200 {
			t.Errorf("%s emitted %q which returns %d", where, u, code)
			continue
		}
		if body["id"] == nil {
			t.Errorf("%s emitted %q which resolved but returned no resource: %v", where, u, body)
		}
	}
	t.Logf("followed %d emitted URLs", len(seen))
}
