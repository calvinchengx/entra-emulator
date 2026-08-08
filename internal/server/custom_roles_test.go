package server

import (
	"net/http"
	"testing"
)

// TestCustomRoleDefinitions covers tenant-authored directory roles: they list
// beside the built-ins, are assignable, are patchable/deletable while built-ins
// are protected — and, the subtle one, they must NEVER reach a token's `wids`
// claim, which real Entra reserves for built-in role TEMPLATE GUIDs.
func TestCustomRoleDefinitions(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)
	base := hts.URL + "/graph/v1.0/roleManagement/directory"

	// Create a custom role.
	code, created := postJSONAuth(t, base+"/roleDefinitions", app, map[string]any{
		"displayName":     "Widget Operator",
		"description":     "Can operate widgets.",
		"rolePermissions": []string{"microsoft.directory/widgets/read"},
	})
	if code != http.StatusCreated {
		t.Fatalf("create custom role: %d %v", code, created)
	}
	roleID, _ := created["id"].(string)
	if created["isBuiltIn"] != false {
		t.Errorf("custom role must report isBuiltIn=false: %v", created)
	}
	if _, hasTemplate := created["templateId"]; hasTemplate {
		t.Errorf("custom roles have no templateId (that is a built-in concept): %v", created)
	}

	t.Run("lists beside the built-ins and is individually readable", func(t *testing.T) {
		status, list := graphGet(t, hts.URL, "/graph/v1.0/roleManagement/directory/roleDefinitions", app)
		if status != http.StatusOK {
			t.Fatalf("list: %d", status)
		}
		vals, _ := list["value"].([]any)
		var sawCustom, sawBuiltIn bool
		for _, v := range vals {
			m, _ := v.(map[string]any)
			if m["id"] == roleID {
				sawCustom = true
			}
			if m["isBuiltIn"] == true {
				sawBuiltIn = true
			}
		}
		if !sawCustom || !sawBuiltIn {
			t.Fatalf("list must contain both custom and built-in roles (custom=%v builtin=%v)", sawCustom, sawBuiltIn)
		}
		if status, one := graphGet(t, hts.URL, "/graph/v1.0/roleManagement/directory/roleDefinitions/"+roleID, app); status != 200 || one["id"] != roleID {
			t.Fatalf("get custom role: %d %v", status, one)
		}
	})

	t.Run("is assignable", func(t *testing.T) {
		code, assigned := postJSONAuth(t, base+"/roleAssignments", app, map[string]any{
			"roleDefinitionId": roleID, "principalId": aliceID, "directoryScopeId": "/",
		})
		if code != http.StatusCreated {
			t.Fatalf("assign custom role: %d %v", code, assigned)
		}
	})

	// The point of the previous step: Alice now holds a tenant-wide assignment
	// of a CUSTOM role. Real Entra puts only built-in template GUIDs in wids, so
	// this assignment must not surface there — while a built-in one still does,
	// which is what makes this assertion meaningful rather than vacuous.
	t.Run("never appears in wids, while a built-in still does", func(t *testing.T) {
		// Opt the SPA into directory-role claims, or wids is never emitted at all.
		if st, _ := patchJSON(t, hts.URL+"/admin/api/apps/"+spaID, map[string]any{"groupMembershipClaims": "All"}); st != 200 {
			t.Fatalf("set groupMembershipClaims: %d", st)
		}
		scope := "api://" + spaID + "/access_as_user"

		// Alice holds ONLY the custom role right now → wids must be empty.
		claims := decodeJWTPayload(t, ropcAccessToken(t, hts.URL, spaID, scope))
		if w := widsOf(claims); len(w) != 0 {
			t.Fatalf("a custom role must not produce wids, got %v", w)
		}

		// Give her a built-in one too: now wids appears, and carries ONLY the
		// built-in template GUID — proving the claim is live and the custom role
		// is being filtered out rather than the whole mechanism being off.
		st, assigned := graphSend(t, "POST", hts.URL, "/graph/v1.0/roleManagement/directory/roleAssignments", app, map[string]any{
			"roleDefinitionId": globalAdminTemplateID, "principalId": aliceID, "directoryScopeId": "/",
		})
		if st != 201 {
			t.Fatalf("assign built-in role: %d %v", st, assigned)
		}
		w := widsOf(decodeJWTPayload(t, ropcAccessToken(t, hts.URL, spaID, scope)))
		if len(w) != 1 || w[0] != globalAdminTemplateID {
			t.Fatalf("wids should carry exactly the built-in template GUID, got %v", w)
		}
	})

	t.Run("built-ins are protected from modification", func(t *testing.T) {
		const globalAdmin = "62e90394-69f5-4237-9190-012177145e10"
		if code := deleteAuthStatus(t, base+"/roleDefinitions/"+globalAdmin, app); code != http.StatusForbidden {
			t.Errorf("deleting a built-in: want 403, got %d", code)
		}
	})

	t.Run("delete removes the role and its assignments", func(t *testing.T) {
		if code := deleteAuthStatus(t, base+"/roleDefinitions/"+roleID, app); code != http.StatusNoContent {
			t.Fatalf("delete custom role: %d", code)
		}
		if status, _ := graphGet(t, hts.URL, "/graph/v1.0/roleManagement/directory/roleDefinitions/"+roleID, app); status != http.StatusNotFound {
			t.Errorf("deleted role should 404, got %d", status)
		}
		// The assignment went with it, so it can no longer grant anything.
		status, list := graphGet(t, hts.URL, "/graph/v1.0/roleManagement/directory/roleAssignments", app)
		if status != http.StatusOK {
			t.Fatalf("list assignments: %d", status)
		}
		for _, v := range list["value"].([]any) {
			if m, _ := v.(map[string]any); m["roleDefinitionId"] == roleID {
				t.Fatalf("assignment survived its role definition: %v", m)
			}
		}
	})
}

// deleteAuthStatus issues an authenticated DELETE and returns the status.
func deleteAuthStatus(t *testing.T, url, bearer string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodDelete, url, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}
