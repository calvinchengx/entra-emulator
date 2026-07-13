package server

import (
	"encoding/json"
	"testing"
)

const globalAdminTemplateID = "62e90394-69f5-4237-9190-012177145e10"

func widsOf(claims map[string]any) []string {
	raw, _ := claims["wids"].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// TestDirectoryRoleAssignmentDrivesWids proves a tenant-wide role assignment
// surfaces in the wids claim when the app opts into directory-role claims, and
// exercises roleDefinitions + roleAssignments CRUD.
func TestDirectoryRoleAssignmentDrivesWids(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)

	// Built-in role definitions are served with template GUIDs.
	st, defs := graphGet(t, hts.URL, "/graph/v1.0/roleManagement/directory/roleDefinitions", app)
	if st != 200 || len(defs["value"].([]any)) < 6 {
		t.Fatalf("roleDefinitions: %d %v", st, defs)
	}
	st, ga := graphGet(t, hts.URL, "/graph/v1.0/roleManagement/directory/roleDefinitions/"+globalAdminTemplateID, app)
	if st != 200 || ga["displayName"] != "Global Administrator" || ga["templateId"] != globalAdminTemplateID {
		t.Fatalf("GA role definition: %d %v", st, ga)
	}

	// Opt the SPA into directory-role claims.
	if st, _ := patchJSON(t, hts.URL+"/admin/api/apps/"+spaID, map[string]any{"groupMembershipClaims": "All"}); st != 200 {
		t.Fatalf("set groupMembershipClaims: %d", st)
	}

	// Baseline: Alice has no role → no wids.
	base := decodeJWTPayload(t, ropcAccessToken(t, hts.URL, spaID, "api://"+spaID+"/access_as_user"))
	if len(widsOf(base)) != 0 {
		t.Fatalf("baseline wids should be empty: %v", base["wids"])
	}

	// Assign Global Administrator to Alice, tenant-wide.
	st, assigned := graphSend(t, "POST", hts.URL, "/graph/v1.0/roleManagement/directory/roleAssignments", app, map[string]any{
		"roleDefinitionId": globalAdminTemplateID, "principalId": aliceID, "directoryScopeId": "/",
	})
	if st != 201 || assigned["id"] == nil {
		t.Fatalf("assign role: %d %v", st, assigned)
	}

	// Now wids carries the GA template GUID.
	got := decodeJWTPayload(t, ropcAccessToken(t, hts.URL, spaID, "api://"+spaID+"/access_as_user"))
	w := widsOf(got)
	if len(w) != 1 || w[0] != globalAdminTemplateID {
		t.Fatalf("wids after assignment: want [%s], got %v", globalAdminTemplateID, w)
	}

	// $filter by principalId returns the assignment.
	_, filtered := graphGet(t, hts.URL, "/graph/v1.0/roleManagement/directory/roleAssignments?$filter=principalId+eq+'"+aliceID+"'", app)
	if len(filtered["value"].([]any)) != 1 {
		t.Fatalf("filter roleAssignments by principal: %v", filtered["value"])
	}

	// Remove the assignment → wids empties again.
	aid := assigned["id"].(string)
	if st, _ := graphSend(t, "DELETE", hts.URL, "/graph/v1.0/roleManagement/directory/roleAssignments/"+aid, app, nil); st != 204 {
		t.Fatalf("delete assignment: %d", st)
	}
	after := decodeJWTPayload(t, ropcAccessToken(t, hts.URL, spaID, "api://"+spaID+"/access_as_user"))
	if len(widsOf(after)) != 0 {
		t.Fatalf("wids after removal should be empty: %v", after["wids"])
	}
}

// TestDirectoryRoleScopedAssignmentNoWids proves an admin-unit-scoped assignment
// (directoryScopeId != "/") does not surface in wids.
func TestDirectoryRoleScopedAssignmentNoWids(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)
	patchJSON(t, hts.URL+"/admin/api/apps/"+spaID, map[string]any{"groupMembershipClaims": "DirectoryRole"})

	st, _ := graphSend(t, "POST", hts.URL, "/graph/v1.0/roleManagement/directory/roleAssignments", app, map[string]any{
		"roleDefinitionId": globalAdminTemplateID, "principalId": aliceID,
		"directoryScopeId": "/administrativeUnits/00000000-0000-0000-0000-0000000000aa",
	})
	if st != 201 {
		t.Fatalf("scoped assign: %d", st)
	}
	claims := decodeJWTPayload(t, ropcAccessToken(t, hts.URL, spaID, "api://"+spaID+"/access_as_user"))
	if raw, _ := json.Marshal(claims["wids"]); len(widsOf(claims)) != 0 {
		t.Fatalf("scoped assignment must not appear in wids, got %s", raw)
	}
}
