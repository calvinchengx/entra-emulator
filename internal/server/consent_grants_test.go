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
