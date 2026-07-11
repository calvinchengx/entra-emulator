package server

import (
	"net/url"
	"testing"
)

// TestGraphWriteErrorPaths covers the not-found and bad-request branches of the
// Graph write handlers (roadmap #18) that the happy-path tests don't reach.
func TestGraphWriteErrorPaths(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)
	missing := "00000000-0000-0000-0000-0000000000ff"

	// Missing-target updates/deletes → 404.
	for _, tc := range []struct{ method, path string }{
		{"PATCH", "/graph/v1.0/users/" + missing},
		{"DELETE", "/graph/v1.0/users/" + missing},
		{"PATCH", "/graph/v1.0/groups/" + missing},
		{"DELETE", "/graph/v1.0/groups/" + missing},
		{"PATCH", "/graph/v1.0/applications/" + missing},
		{"DELETE", "/graph/v1.0/applications/" + missing},
	} {
		if code, _ := graphSend(t, tc.method, hts.URL, tc.path, app, map[string]any{"displayName": "x"}); code != 404 {
			t.Fatalf("%s %s: want 404, got %d", tc.method, tc.path, code)
		}
	}

	// Missing required fields → 400.
	for _, path := range []string{"/graph/v1.0/users", "/graph/v1.0/groups", "/graph/v1.0/applications"} {
		if code, _ := graphSend(t, "POST", hts.URL, path, app, map[string]any{}); code != 400 {
			t.Fatalf("POST %s empty body: want 400, got %d", path, code)
		}
	}

	// $ref member add to a missing group → 404; missing @odata.id → 400.
	if code, _ := graphSend(t, "POST", hts.URL, "/graph/v1.0/groups/"+missing+"/members/$ref", app, map[string]any{
		"@odata.id": hts.URL + "/graph/v1.0/directoryObjects/" + aliceID,
	}); code != 404 {
		t.Fatalf("add member to missing group: want 404, got %d", code)
	}
	// Create a real group, then a bad $ref body → 400.
	_, gr := graphSend(t, "POST", hts.URL, "/graph/v1.0/groups", app, map[string]any{"displayName": "Temp"})
	gid := gr["id"].(string)
	if code, _ := graphSend(t, "POST", hts.URL, "/graph/v1.0/groups/"+gid+"/members/$ref", app, map[string]any{}); code != 400 {
		t.Fatalf("empty $ref body: want 400, got %d", code)
	}

	// Unauthenticated write → 401.
	if code, _ := graphSend(t, "POST", hts.URL, "/graph/v1.0/users", "", map[string]any{"displayName": "x"}); code != 401 {
		t.Fatalf("no token write: want 401, got %d", code)
	}
}

// TestGraphReadNotFound covers the 404 branch of the read handlers (#19).
func TestGraphReadNotFound(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)
	missing := "00000000-0000-0000-0000-0000000000ff"

	if code, _ := graphGet(t, hts.URL, "/graph/v1.0/servicePrincipals/"+missing, app); code != 404 {
		t.Fatalf("unknown service principal: want 404, got %d", code)
	}
	if code, _ := graphGet(t, hts.URL, "/graph/v1.0/users/"+missing, app); code != 404 {
		t.Fatalf("unknown user: want 404, got %d", code)
	}
}

// TestGraphODataBoolAndNullFilter covers the literal-value branches of $filter
// (bool and null) plus $select on a single entity (#17).
func TestGraphODataBoolAndNullFilter(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)

	// accountEnabled eq true → all seeded users (both enabled).
	code, resp := graphGet(t, hts.URL, "/graph/v1.0/users?"+url.Values{
		"$filter": {"accountEnabled eq true"}, "$count": {"true"},
	}.Encode(), app)
	if code != 200 || int(resp["@odata.count"].(float64)) < 2 {
		t.Fatalf("accountEnabled eq true: %d %v", code, resp)
	}

	// accountEnabled eq false → none.
	code, resp = graphGet(t, hts.URL, "/graph/v1.0/users?"+url.Values{
		"$filter": {"accountEnabled eq false"},
	}.Encode(), app)
	if code != 200 || len(resp["value"].([]any)) != 0 {
		t.Fatalf("accountEnabled eq false: %d %v", code, resp)
	}

	// givenName ne null → users that have a given name.
	code, resp = graphGet(t, hts.URL, "/graph/v1.0/users?"+url.Values{
		"$filter": {"givenName ne null"},
	}.Encode(), app)
	if code != 200 {
		t.Fatalf("ne null filter: %d %v", code, resp)
	}

	// $select on a single entity (/me path via users/{id}) keeps id + selected.
	code, one := graphGet(t, hts.URL, "/graph/v1.0/users/"+aliceID+"?"+url.Values{"$select": {"displayName"}}.Encode(), app)
	if code != 200 {
		t.Fatalf("single-entity select: %d %v", code, one)
	}
	if _, ok := one["userPrincipalName"]; ok {
		t.Fatalf("single-entity $select should drop userPrincipalName: %v", one)
	}
	if _, ok := one["id"]; !ok {
		t.Fatalf("single-entity $select must keep id: %v", one)
	}
}
