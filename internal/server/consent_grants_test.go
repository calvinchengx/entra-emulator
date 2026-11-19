package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// ropcAccessToken gets a delegated access token for Alice via ROPC.
func ropcAccessToken(t *testing.T, hts, clientID, scope string) string {
	t.Helper()
	_, body := postForm(t, http.DefaultClient, hts+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type": {"password"}, "client_id": {clientID},
		"username": {"alice@entraemulator.dev"}, "password": {store.SeedPassword},
		"scope": {scope},
	})
	tok, _ := body["access_token"].(string)
	if tok == "" {
		t.Fatalf("no access token for scope %q: %v", scope, body)
	}
	return tok
}

// appTokenForResource mints a client-credentials token for a specific resource.
func appTokenForResource(t *testing.T, hts, resource string) map[string]any {
	t.Helper()
	_, cc := postForm(t, http.DefaultClient, hts+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type": {"client_credentials"}, "client_id": {daemonID},
		"client_secret": {store.SeedDaemonSecret}, "scope": {resource + "/.default"},
	})
	tok, _ := cc["access_token"].(string)
	if tok == "" {
		t.Fatalf("no app token for %q: %v", resource, cc)
	}
	return decodeJWTPayload(t, tok)
}

func rolesOf(claims map[string]any) []string {
	raw, _ := claims["roles"].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// TestAppRoleAssignmentDrivesRolesClaim proves stored appRoleAssignments are
// authoritative for the app-only roles claim, overriding the auto-grant.
func TestAppRoleAssignmentDrivesRolesClaim(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)
	resource := "api://" + daemonID

	// Baseline: no assignments → auto-grant yields the daemon's Tasks.Read.All.
	if got := rolesOf(appTokenForResource(t, hts.URL, resource)); len(got) != 1 || got[0] != "Tasks.Read.All" {
		t.Fatalf("baseline roles: want [Tasks.Read.All], got %v", got)
	}

	// Find the Tasks.Read.All app-role id on the daemon app.
	_, adminApp := getJSON(t, hts.URL+"/admin/api/apps/"+daemonID)
	roleID := ""
	for _, r := range adminApp["appRoles"].([]any) {
		if m, _ := r.(map[string]any); m["value"] == "Tasks.Read.All" {
			roleID, _ = m["id"].(string)
		}
	}
	if roleID == "" {
		t.Fatalf("could not find Tasks.Read.All role id: %v", adminApp["appRoles"])
	}

	// A default (zero-GUID) assignment makes stored grants authoritative and
	// carries no specific role → the roles claim empties.
	st, def := graphSend(t, "POST", hts.URL, "/graph/v1.0/servicePrincipals/"+daemonID+"/appRoleAssignedTo", app, map[string]any{
		"principalId": daemonID, "resourceId": daemonID, "appRoleId": store.ZeroGUID,
	})
	if st != 201 {
		t.Fatalf("create default assignment: %d %v", st, def)
	}
	if got := rolesOf(appTokenForResource(t, hts.URL, resource)); len(got) != 0 {
		t.Fatalf("after default assignment: want no roles, got %v", got)
	}

	// Assigning the real role restores it in the claim.
	st, _ = graphSend(t, "POST", hts.URL, "/graph/v1.0/servicePrincipals/"+daemonID+"/appRoleAssignedTo", app, map[string]any{
		"principalId": daemonID, "resourceId": daemonID, "appRoleId": roleID,
	})
	if st != 201 {
		t.Fatalf("create role assignment: %d", st)
	}
	if got := rolesOf(appTokenForResource(t, hts.URL, resource)); len(got) != 1 || got[0] != "Tasks.Read.All" {
		t.Fatalf("after role assignment: want [Tasks.Read.All], got %v", got)
	}

	// The assignment is listed on the resource SP.
	_, listed := graphGet(t, hts.URL, "/graph/v1.0/servicePrincipals/"+daemonID+"/appRoleAssignedTo", app)
	if len(listed["value"].([]any)) != 2 {
		t.Fatalf("appRoleAssignedTo should list 2 assignments: %v", listed)
	}
}

// ropcTokens runs ROPC for Alice and returns the decoded access and ID tokens.
func ropcTokens(t *testing.T, hts, clientID, scope string) (access, id map[string]any) {
	t.Helper()
	return ropcTokensAs(t, hts, "alice@entraemulator.dev", clientID, scope)
}

// ropcTokensAs runs ROPC for a seeded user and returns the decoded tokens.
func ropcTokensAs(t *testing.T, hts, username, clientID, scope string) (access, id map[string]any) {
	t.Helper()
	_, body := postForm(t, http.DefaultClient, hts+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type": {"password"}, "client_id": {clientID},
		"username": {username}, "password": {store.SeedPassword},
		"scope": {scope},
	})
	at, _ := body["access_token"].(string)
	it, _ := body["id_token"].(string)
	if at == "" || it == "" {
		t.Fatalf("want access and ID tokens for scope %q: %v", scope, body)
	}
	return decodeJWTPayload(t, at), decodeJWTPayload(t, it)
}

// TestUserAppRoleAssignmentDrivesRolesClaim proves app roles assigned to a
// user land in the roles claim of that user's tokens: the access token for the
// resource app and the ID token for the client app. No auto-grant applies.
func TestUserAppRoleAssignmentDrivesRolesClaim(t *testing.T) {
	hts, _, st := newTestServer(t)
	app := appGraphToken(t, hts.URL)
	scope := "openid api://" + spaID + "/access_as_user"

	roleID := store.NewGUID()
	if err := st.AddRole(&store.AppRole{
		ID: roleID, AppID: spaID, Value: "Tasks.Admin", AllowedMemberTypes: "User", IsEnabled: true,
	}); err != nil {
		t.Fatalf("add role: %v", err)
	}

	// Baseline: the app declares a user role but Alice holds no assignment →
	// no roles claim on either token (users are never auto-granted).
	access, id := ropcTokens(t, hts.URL, spaID, scope)
	if _, ok := access["roles"]; ok {
		t.Fatalf("baseline access token: want no roles claim, got %v", access["roles"])
	}
	if _, ok := id["roles"]; ok {
		t.Fatalf("baseline ID token: want no roles claim, got %v", id["roles"])
	}

	assign := func(appRoleID string) {
		t.Helper()
		code, body := graphSend(t, "POST", hts.URL, "/graph/v1.0/servicePrincipals/"+spaID+"/appRoleAssignedTo", app, map[string]any{
			"principalId": aliceID, "resourceId": spaID, "appRoleId": appRoleID,
		})
		if code != 201 || body["principalType"] != "User" {
			t.Fatalf("assign %s: %d %v", appRoleID, code, body)
		}
	}

	// The default assignment grants access but carries no role value.
	assign(store.ZeroGUID)
	access, _ = ropcTokens(t, hts.URL, spaID, scope)
	if _, ok := access["roles"]; ok {
		t.Fatalf("after default assignment: want no roles claim, got %v", access["roles"])
	}

	// A specific role assignment → roles on the access token (resource = SPA)
	// and on the ID token (client = SPA). A single role is still a one-element
	// JSON array, never a bare string: Entra documents roles as an array.
	assign(roleID)
	access, id = ropcTokens(t, hts.URL, spaID, scope)
	for name, claims := range map[string]map[string]any{"access": access, "ID": id} {
		raw, ok := claims["roles"].([]any)
		if !ok {
			t.Fatalf("%s token roles: want a JSON array, got %T %v", name, claims["roles"], claims["roles"])
		}
		if len(raw) != 1 || raw[0] != "Tasks.Admin" {
			t.Fatalf("%s token roles: want [Tasks.Admin], got %v", name, raw)
		}
	}

	// Multiple roles → a JSON array of every assigned value, sorted, with a
	// duplicate assignment of the same role collapsed to one entry.
	secondRoleID := store.NewGUID()
	if err := st.AddRole(&store.AppRole{
		ID: secondRoleID, AppID: spaID, Value: "Reports.Read", AllowedMemberTypes: "User", IsEnabled: true,
	}); err != nil {
		t.Fatalf("add second role: %v", err)
	}
	assign(secondRoleID)
	assign(roleID) // duplicate
	access, id = ropcTokens(t, hts.URL, spaID, scope)
	for name, claims := range map[string]map[string]any{"access": access, "ID": id} {
		raw, ok := claims["roles"].([]any)
		if !ok {
			t.Fatalf("%s token roles: want a JSON array, got %T %v", name, claims["roles"], claims["roles"])
		}
		if len(raw) != 2 || raw[0] != "Reports.Read" || raw[1] != "Tasks.Admin" {
			t.Fatalf("%s token roles: want [Reports.Read Tasks.Admin], got %v", name, raw)
		}
	}

	// A Graph-audience token is for another resource: the SPA's roles stay out.
	access, _ = ropcTokens(t, hts.URL, spaID, "openid User.Read")
	if _, ok := access["roles"]; ok {
		t.Fatalf("Graph access token: want no roles claim, got %v", access["roles"])
	}
}

// TestGroupAppRoleAssignmentDrivesRolesClaim proves an app role assigned to a
// group reaches the roles claim of the group's members, and only theirs.
func TestGroupAppRoleAssignmentDrivesRolesClaim(t *testing.T) {
	hts, _, st := newTestServer(t)
	app := appGraphToken(t, hts.URL)
	scope := "openid api://" + spaID + "/access_as_user"
	const bob = "bob@entraemulator.dev"

	adminRole, readRole := store.NewGUID(), store.NewGUID()
	for id, value := range map[string]string{adminRole: "Tasks.Admin", readRole: "Reports.Read"} {
		if err := st.AddRole(&store.AppRole{
			ID: id, AppID: spaID, Value: value, AllowedMemberTypes: "User", IsEnabled: true,
		}); err != nil {
			t.Fatalf("add role %s: %v", value, err)
		}
	}
	// A group with Alice only (the seeded Engineering group also holds Bob).
	groupID := store.NewGUID()
	if err := st.CreateGroup(&store.Group{ID: groupID, TenantID: tenant, DisplayName: "Task Admins"}); err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := st.AddGroupMember(groupID, aliceID); err != nil {
		t.Fatalf("add member: %v", err)
	}

	assign := func(principalID, appRoleID string) map[string]any {
		t.Helper()
		code, body := graphSend(t, "POST", hts.URL, "/graph/v1.0/servicePrincipals/"+spaID+"/appRoleAssignedTo", app, map[string]any{
			"principalId": principalID, "resourceId": spaID, "appRoleId": appRoleID,
		})
		if code != 201 {
			t.Fatalf("assign %s to %s: %d %v", appRoleID, principalID, code, body)
		}
		return body
	}
	wantRoles := func(label, username string, want ...string) {
		t.Helper()
		access, id := ropcTokensAs(t, hts.URL, username, spaID, scope)
		for name, claims := range map[string]map[string]any{"access": access, "ID": id} {
			if len(want) == 0 {
				if _, ok := claims["roles"]; ok {
					t.Fatalf("%s: %s token: want no roles claim, got %v", label, name, claims["roles"])
				}
				continue
			}
			if got := rolesOf(claims); strings.Join(got, ",") != strings.Join(want, ",") {
				t.Fatalf("%s: %s token roles: want %v, got %v", label, name, want, claims["roles"])
			}
		}
	}

	// A group principal is inferred as Group and named in the response.
	if body := assign(groupID, adminRole); body["principalType"] != "Group" || body["principalDisplayName"] != "Task Admins" {
		t.Fatalf("group assignment shape: %v", body)
	}
	wantRoles("member", "alice@entraemulator.dev", "Tasks.Admin")
	wantRoles("non-member", bob)

	// The role follows membership: leaving the group drops it.
	if err := st.RemoveGroupMember(groupID, aliceID); err != nil {
		t.Fatalf("remove member: %v", err)
	}
	wantRoles("after leaving", "alice@entraemulator.dev")

	// Group and direct assignments combine, and overlap appears once.
	if err := st.AddGroupMember(groupID, aliceID); err != nil {
		t.Fatalf("re-add member: %v", err)
	}
	assign(aliceID, adminRole)
	assign(aliceID, readRole)
	wantRoles("group + direct", "alice@entraemulator.dev", "Reports.Read", "Tasks.Admin")
}

// TestOAuth2PermissionGrantShapesScp proves delegated grants filter the scp
// claim, and exercises grant CRUD + $filter.
func TestOAuth2PermissionGrantShapesScp(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)
	resScope := "api://" + spaID + "/access_as_user"

	// Baseline: auto-consent → scp carries the requested scope.
	claims := decodeJWTPayload(t, ropcAccessToken(t, hts.URL, spaID, resScope))
	if claims["scp"] != "access_as_user" {
		t.Fatalf("baseline scp: want access_as_user, got %v", claims["scp"])
	}

	// A Principal grant for a DIFFERENT scope makes grants authoritative, so the
	// requested access_as_user is no longer consented → scp empties.
	st, created := graphSend(t, "POST", hts.URL, "/graph/v1.0/oauth2PermissionGrants", app, map[string]any{
		"clientId": spaID, "consentType": "Principal", "resourceId": spaID,
		"principalId": aliceID, "scope": "User.Read",
	})
	if st != 201 || created["id"] == nil {
		t.Fatalf("create grant: %d %v", st, created)
	}
	claims = decodeJWTPayload(t, ropcAccessToken(t, hts.URL, spaID, resScope))
	if strings.TrimSpace(claims["scp"].(string)) != "" {
		t.Fatalf("after non-matching grant: want empty scp, got %v", claims["scp"])
	}

	// An AllPrincipals grant that includes access_as_user restores it.
	st, _ = graphSend(t, "POST", hts.URL, "/graph/v1.0/oauth2PermissionGrants", app, map[string]any{
		"clientId": spaID, "consentType": "AllPrincipals", "resourceId": spaID, "scope": "access_as_user",
	})
	if st != 201 {
		t.Fatalf("create allprincipals grant: %d", st)
	}
	claims = decodeJWTPayload(t, ropcAccessToken(t, hts.URL, spaID, resScope))
	if claims["scp"] != "access_as_user" {
		t.Fatalf("after matching grant: want access_as_user, got %v", claims["scp"])
	}

	// $filter by clientId returns both grants; SP-nav returns them too.
	_, filtered := graphGet(t, hts.URL, "/graph/v1.0/oauth2PermissionGrants?$filter="+url.QueryEscape("clientId eq '"+spaID+"'"), app)
	if len(filtered["value"].([]any)) != 2 {
		t.Fatalf("filter by clientId: want 2, got %v", filtered["value"])
	}
	_, nav := graphGet(t, hts.URL, "/graph/v1.0/servicePrincipals/"+spaID+"/oauth2PermissionGrants", app)
	if len(nav["value"].([]any)) != 2 {
		t.Fatalf("SP oauth2PermissionGrants nav: want 2, got %v", nav["value"])
	}

	// Delete one grant → 204, one remains.
	gid := created["id"].(string)
	if st, _ = graphSend(t, "DELETE", hts.URL, "/graph/v1.0/oauth2PermissionGrants/"+gid, app, nil); st != 204 {
		t.Fatalf("delete grant: %d", st)
	}
	_, after := graphGet(t, hts.URL, "/graph/v1.0/servicePrincipals/"+spaID+"/oauth2PermissionGrants", app)
	if len(after["value"].([]any)) != 1 {
		t.Fatalf("after delete: want 1 grant, got %v", after["value"])
	}
}
