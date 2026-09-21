package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Microsoft documents Graph path resource names as case-insensitive and entity
// ids as case-sensitive (https://learn.microsoft.com/graph/call-api). These tests
// hold the real server stack to both halves.

func TestGraphResourceNamesAreCaseInsensitiveAndIDsAreNot(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)

	same := func(canonical, mixed string) {
		t.Helper()
		st1, want := graphGet(t, hts.URL, canonical, app)
		st2, got := graphGet(t, hts.URL, mixed, app)
		if st1 != 200 || st2 != 200 {
			t.Fatalf("%s = %d, %s = %d", canonical, st1, mixed, st2)
		}
		if len(got) == 0 || len(got) != len(want) || got["@odata.context"] != want["@odata.context"] {
			t.Errorf("%s answered differently from %s:\n got  %v\n want %v", mixed, canonical, got, want)
		}
	}
	same("/graph/v1.0/users", "/graph/v1.0/USERS")
	same("/graph/v1.0/users/"+aliceID, "/graph/V1.0/Users/"+aliceID)
	same("/graph/v1.0/users/"+aliceID+"/memberOf", "/graph/v1.0/users/"+aliceID+"/MEMBEROF")
	same("/graph/v1.0/servicePrincipals", "/graph/v1.0/serviceprincipals")

	// The alternate-key form: resource and key names fold, the value does not.
	same("/graph/v1.0/servicePrincipals(appId='"+spaID+"')",
		"/graph/v1.0/SERVICEPRINCIPALS(APPID='"+spaID+"')")

	// IDs are case-sensitive, so an upper-cased id is a different id.
	if st, body := graphGet(t, hts.URL, "/graph/v1.0/users/"+strings.ToUpper(aliceID), app); st != 404 {
		t.Errorf("an id in the wrong case: got %d %v, want 404", st, body)
	}
}

// The spelling this change replaced a special case for.
func TestGrantsAreServedUnderAnyCasing(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)

	st, created := graphSend(t, "POST", hts.URL, "/graph/v1.0/oAuth2PermissionGrants", app, map[string]any{
		"clientId": spaID, "resourceId": daemonID, "consentType": "AllPrincipals", "scope": "Tasks.Read",
	})
	if st != 201 {
		t.Fatalf("POST under the capital-A spelling: %d %v", st, created)
	}
	id := created["id"].(string)

	_, list := graphGet(t, hts.URL, "/graph/v1.0/oauth2permissiongrants", app)
	if !containsID(list["value"], id) {
		t.Fatalf("the grant is not listed under the all-lowercase spelling: %v", list)
	}
	if st, body := graphSend(t, "DELETE", hts.URL, "/graph/v1.0/OAUTH2PERMISSIONGRANTS/"+id, app, nil); st != 204 {
		t.Fatalf("DELETE under the all-caps spelling: %d %v", st, body)
	}
	_, list = graphGet(t, hts.URL, "/graph/v1.0/oauth2PermissionGrants", app)
	if containsID(list["value"], id) {
		t.Fatalf("the grant survived its delete: %v", list)
	}
}

func containsID(v any, id string) bool {
	rows, _ := v.([]any)
	for _, r := range rows {
		if m, ok := r.(map[string]any); ok && m["id"] == id {
			return true
		}
	}
	return false
}

// The permission gate reads the request path and switches on its first segment
// case-sensitively, so a handler that ran on `/USERS` would find no requirement
// and skip the gate. Folding before the handler runs is what prevents that; this
// is the test that says so, and it would fail if the fold moved after the gate.
func TestCaseFoldingDoesNotBypassThePermissionGate(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	cfg.GraphPermissions = true // shared with the live handlers

	none := forgeGraphToken(t, hts.URL, "", nil, nil)
	for _, path := range []string{
		"/graph/v1.0/users", // the control: the canonical spelling is denied
		"/graph/v1.0/USERS",
		"/graph/V1.0/Users/" + aliceID,
		"/graph/v1.0/GROUPS",
		"/graph/v1.0/OAUTH2PERMISSIONGRANTS",
	} {
		if st, body := graphGet(t, hts.URL, path, none); st != http.StatusForbidden {
			t.Errorf("%s with no roles: got %d %v, want 403", path, st, body)
		}
	}

	// And the gate still opens for a token that has the role, at any casing.
	ok := forgeGraphToken(t, hts.URL, "", nil, []string{"User.Read.All"})
	if st, body := graphGet(t, hts.URL, "/graph/v1.0/USERS", ok); st != http.StatusOK {
		t.Errorf("USERS with User.Read.All: got %d %v, want 200", st, body)
	}
}

// The recorder wraps the whole server in-process (Listen), and has to record the
// spelling Microsoft's OpenAPI uses, or the conformance checker sees a route
// nobody documents.
func TestRecorderWritesTheCanonicalPathForAMixedCaseRequest(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)

	file := t.TempDir() + "/responses.jsonl"
	rec := newRecorder(file)
	t.Cleanup(func() { _ = rec.Close() })
	front := httptest.NewServer(record(rec, hts.Config.Handler))
	t.Cleanup(front.Close)

	if st, body := graphGet(t, front.URL, "/graph/V1.0/USERS/"+aliceID, app); st != 200 {
		t.Fatalf("mixed-case request: %d %v", st, body)
	}
	got := readRecording(t, file)
	if len(got) != 1 {
		t.Fatalf("want one recorded response, got %+v", got)
	}
	if want := "/v1.0/users/" + aliceID; got[0].Path != want {
		t.Errorf("recorded path = %q, want %q", got[0].Path, want)
	}
}

// Query option names are case-insensitive too; their values are not.
func TestGraphQueryOptionNamesAreCaseInsensitive(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)

	rows := func(path string) ([]any, map[string]any) {
		t.Helper()
		st, body := graphGet(t, hts.URL, path, app)
		if st != 200 {
			t.Fatalf("%s = %d %v", path, st, body)
		}
		v, _ := body["value"].([]any)
		return v, body
	}

	// $top: the canonical answer is a single row, so a folded option must be too.
	if v, _ := rows("/graph/v1.0/users?$top=1"); len(v) != 1 {
		t.Fatalf("control: $top=1 returned %d rows", len(v))
	}
	if v, _ := rows("/graph/v1.0/users?$TOP=1"); len(v) != 1 {
		t.Errorf("$TOP=1 returned %d rows, want 1", len(v))
	}

	// $select projects to the named property alone.
	v, _ := rows("/graph/v1.0/users?$Select=displayName")
	if len(v) == 0 {
		t.Fatal("no users")
	}
	for _, row := range v {
		if m := row.(map[string]any); len(m) != 1 || m["displayName"] == nil {
			t.Errorf("$Select=displayName returned %v, want displayName alone", m)
		}
	}

	// $count and the paging link, which is rebuilt from the query.
	_, body := rows("/graph/v1.0/users?$COUNT=true&$Top=1")
	if body["@odata.count"] == nil {
		t.Errorf("$COUNT=true did not produce @odata.count: %v", body)
	}
	next, _ := body["@odata.nextLink"].(string)
	if next == "" || strings.Contains(next, "TOP") || !strings.Contains(strings.ToLower(next), "top=1") {
		t.Errorf("nextLink should carry the canonical, lower-case $top: %q", next)
	}

	// A value keeps its case: $filter still compares the literal exactly.
	if v, _ := rows("/graph/v1.0/users?$FILTER=displayName%20eq%20%27ALICE%27"); len(v) != 0 {
		t.Errorf("a $filter literal was case-folded: matched %d rows for 'ALICE'", len(v))
	}
}

func TestRecorderWritesTheCanonicalQueryToo(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)
	file := t.TempDir() + "/responses.jsonl"
	rec := newRecorder(file)
	t.Cleanup(func() { _ = rec.Close() })
	front := httptest.NewServer(record(rec, hts.Config.Handler))
	t.Cleanup(front.Close)

	graphGet(t, front.URL, "/graph/v1.0/USERS?$TOP=1&$Select=id", app)
	got := readRecording(t, file)
	if len(got) != 1 || got[0].Query != "$top=1&$select=id" {
		t.Errorf("recorded %+v, want query $top=1&$select=id", got)
	}
}

// Property names inside $select and $filter are case-insensitive; the literal in
// a $filter and the echo of the request are not rewritten.
func TestGraphPropertyNamesInSelectAndFilterAreCaseInsensitive(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)

	// $select on a collection: the row is keyed by the property's own name.
	_, coll := graphGet(t, hts.URL, "/graph/v1.0/users?$select=DISPLAYNAME", app)
	rows, _ := coll["value"].([]any)
	if len(rows) == 0 {
		t.Fatalf("no users: %v", coll)
	}
	for _, row := range rows {
		m := row.(map[string]any)
		if _, ok := m["displayName"]; !ok || len(m) != 1 {
			t.Errorf("$select=DISPLAYNAME returned %v, want displayName alone under its own spelling", m)
		}
	}

	// $select on one entity, mixed case, several properties.
	_, one := graphGet(t, hts.URL, "/graph/v1.0/users/"+aliceID+"?$select=DisplayName,USERPRINCIPALNAME", app)
	for _, k := range []string{"displayName", "userPrincipalName"} {
		if one[k] == nil {
			t.Errorf("entity is missing %s: %v", k, one)
		}
	}
	// The context echoes what the caller sent. Whether Graph normalises it has not
	// been measured against a tenant, and the emulator already echoes an unknown
	// property verbatim, so this stays as it is rather than guessing.
	if got := one["@odata.context"]; !strings.Contains(got.(string), "users(DisplayName,USERPRINCIPALNAME)") {
		t.Errorf("@odata.context = %v, want the select echoed as sent", got)
	}

	// $filter: the property name folds, the literal does not.
	filterCount := func(expr string) int {
		_, body := graphGet(t, hts.URL, "/graph/v1.0/users?$filter="+strings.ReplaceAll(expr, " ", "%20"), app)
		v, _ := body["value"].([]any)
		return len(v)
	}
	if n := filterCount("userPrincipalName eq 'alice@entraemulator.dev'"); n != 1 {
		t.Fatalf("control: the canonical filter matched %d rows, want 1", n)
	}
	if n := filterCount("USERPRINCIPALNAME eq 'alice@entraemulator.dev'"); n != 1 {
		t.Errorf("an upper-cased property name matched %d rows, want 1", n)
	}
	if n := filterCount("userPrincipalName eq 'ALICE@ENTRAEMULATOR.DEV'"); n != 0 {
		t.Errorf("a filter literal was compared without regard to case: %d rows", n)
	}

	// A property that only materialises when selected, named in capitals.
	_, csa := graphGet(t, hts.URL, "/graph/v1.0/users/"+aliceID+"?$select=CUSTOMSECURITYATTRIBUTES", app)
	if _, ok := csa["customSecurityAttributes"]; !ok {
		t.Errorf("$select=CUSTOMSECURITYATTRIBUTES did not materialise customSecurityAttributes: %v", csa)
	}

	// The role-assignment and grant filters read their fields by regexp.
	// Two grants that differ by client, so a filter that is ignored returns two
	// rows and is told apart from one that matched exactly one.
	for _, client := range []string{spaID, daemonID} {
		st, _ := graphSend(t, "POST", hts.URL, "/graph/v1.0/oauth2PermissionGrants", app, map[string]any{
			"clientId": client, "resourceId": daemonID, "consentType": "AllPrincipals", "scope": "Tasks.Read",
		})
		if st != 201 {
			t.Fatal("could not create a grant")
		}
	}
	_, grants := graphGet(t, hts.URL, "/graph/v1.0/oauth2PermissionGrants?$filter=CLIENTID%20eq%20%27"+spaID+"%27", app)
	if v, _ := grants["value"].([]any); len(v) != 1 {
		t.Errorf("CLIENTID filter matched %d grants, want 1: %v", len(v), grants)
	}
	_, none := graphGet(t, hts.URL, "/graph/v1.0/oauth2PermissionGrants?$filter=clientId%20eq%20%27"+strings.ToUpper(spaID)+"%27", app)
	if v, _ := none["value"].([]any); len(v) != 0 {
		t.Errorf("a grant filter literal was case-folded: %v", none)
	}
}
