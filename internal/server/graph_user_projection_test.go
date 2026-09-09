package server

import (
	"net/http"
	"testing"
)

// Graph's DEFAULT projection for a user is narrower than the user resource's
// property set. This emulator returned accountEnabled, userType and
// externalUserState unasked: real properties, but ones Entra withholds until
// they are selected.
//
// That direction is worse than a missing field. A missing field fails loudly at
// the caller; an extra one lets code read a property here and find it absent in
// production, so the failure arrives after they ship.
//
// Recorded in e2e/differential/testdata/fixtures/graph-user-shape.json.
var notInEntraDefaultUserProjection = []string{"accountEnabled", "userType", "externalUserState"}

func TestGraphUserDefaultProjectionWithholdsNonDefaultFields(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)

	// /me is deliberately absent: it requires a DELEGATED token and correctly
	// refuses the app-only one used here. It runs the same
	// defaultUserProjection call as the single-entity read.
	paths := map[string]string{
		"single entity": "/graph/v1.0/users/" + aliceID,
		"collection":    "/graph/v1.0/users",
	}
	for name, path := range paths {
		t.Run(name, func(t *testing.T) {
			code, body := graphGet(t, hts.URL, path, app)
			if code != http.StatusOK {
				t.Fatalf("%s: %d %v", path, code, body)
			}
			entity := body
			if vals, ok := body["value"].([]any); ok {
				if len(vals) == 0 {
					t.Fatalf("%s: empty collection", path)
				}
				entity, _ = vals[0].(map[string]any)
			}
			for _, f := range notInEntraDefaultUserProjection {
				if _, present := entity[f]; present {
					t.Errorf("%s: %q returned unasked; Entra withholds it from the default projection", path, f)
				}
			}
			// The default projection is not empty: the fields Entra DOES return
			// must still be there, or this would "pass" by returning nothing.
			for _, f := range []string{"id", "displayName", "userPrincipalName"} {
				if _, present := entity[f]; !present {
					t.Errorf("%s: default projection lost %q", path, f)
				}
			}
		})
	}
}

// The withheld fields are properties, not secrets: selecting them returns them.
// A "fix" that dropped them from the shape entirely would pass the test above
// and break every caller that legitimately asks.
func TestGraphUserNonDefaultFieldsAreReachableBySelect(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)

	code, body := graphGet(t, hts.URL,
		"/graph/v1.0/users/"+aliceID+"?$select=accountEnabled,userType,externalUserState", app)
	if code != http.StatusOK {
		t.Fatalf("status %d: %v", code, body)
	}
	for _, f := range []string{"accountEnabled", "userType"} {
		if _, present := body[f]; !present {
			t.Errorf("%q not reachable via $select: %v", f, body)
		}
	}
}

// $filter addresses the resource's properties whether or not they are
// projected. Narrowing the shape before filtering made
// `$filter=accountEnabled eq true` match nothing, which is the bug introduced
// by the first attempt at this fix and the reason projection runs last.
func TestGraphUserFilterSeesNonProjectedFields(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)

	code, body := graphGet(t, hts.URL, "/graph/v1.0/users?$filter=accountEnabled%20eq%20true&$count=true", app)
	if code != http.StatusOK {
		t.Fatalf("status %d: %v", code, body)
	}
	vals, _ := body["value"].([]any)
	if len(vals) == 0 {
		t.Fatalf("filter on a non-projected property matched nothing: %v", body)
	}
	// …and the matched entities are still projected.
	if first, ok := vals[0].(map[string]any); ok {
		if _, present := first["accountEnabled"]; present {
			t.Errorf("filtered result leaked the non-default field: %v", first)
		}
	}
}
