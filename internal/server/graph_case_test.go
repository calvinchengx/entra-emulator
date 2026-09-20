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
