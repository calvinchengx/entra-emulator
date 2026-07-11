package server

import (
	"net/url"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// findByAppID scans an OData value list for the entity with a matching appId.
func findByAppID(vals []any, appID string) map[string]any {
	for _, v := range vals {
		m, _ := v.(map[string]any)
		if m["appId"] == appID {
			return m
		}
	}
	return nil
}

// TestGraphApplicationsRead proves the /applications read surface (#19).
func TestGraphApplicationsRead(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)

	// List includes the seeded SPA with its exposed delegated scope.
	status, list := graphGet(t, hts.URL, "/graph/v1.0/applications", app)
	if status != 200 {
		t.Fatalf("list applications: %d %v", status, list)
	}
	spa := findByAppID(list["value"].([]any), store.SeedAppSPAID)
	if spa == nil {
		t.Fatalf("seeded SPA missing from /applications: %v", list)
	}
	api, _ := spa["api"].(map[string]any)
	scopes, _ := api["oauth2PermissionScopes"].([]any)
	if !hasScopeValue(scopes, "access_as_user") {
		t.Fatalf("SPA missing access_as_user scope: %v", api)
	}

	// Get the seeded daemon by (conflated) object id == appId; it has an app role.
	status, daemon := graphGet(t, hts.URL, "/graph/v1.0/applications/"+daemonID, app)
	if status != 200 || daemon["appId"] != daemonID {
		t.Fatalf("get daemon application: %d %v", status, daemon)
	}
	roles, _ := daemon["appRoles"].([]any)
	if !hasRoleValue(roles, "Tasks.Read.All") {
		t.Fatalf("daemon missing Tasks.Read.All role: %v", roles)
	}

	// $filter=appId eq '...' narrows to one.
	status, filtered := graphGet(t, hts.URL, "/graph/v1.0/applications?"+url.Values{
		"$filter": {"appId eq '" + daemonID + "'"},
	}.Encode(), app)
	if status != 200 || len(filtered["value"].([]any)) != 1 {
		t.Fatalf("$filter appId eq daemon: %d %v", status, filtered)
	}

	// Unknown id → 404.
	if st, _ := graphGet(t, hts.URL, "/graph/v1.0/applications/"+store.NewGUID(), app); st != 404 {
		t.Fatalf("unknown application: want 404, got %d", st)
	}
}

// TestGraphServicePrincipalsRead proves the /servicePrincipals read surface (#19).
func TestGraphServicePrincipalsRead(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)

	status, list := graphGet(t, hts.URL, "/graph/v1.0/servicePrincipals?"+url.Values{"$count": {"true"}}.Encode(), app)
	if status != 200 {
		t.Fatalf("list servicePrincipals: %d %v", status, list)
	}
	if _, ok := list["@odata.count"].(float64); !ok {
		t.Fatalf("$count missing @odata.count: %v", list)
	}
	sp := findByAppID(list["value"].([]any), store.SeedAppSPAID)
	if sp == nil || sp["servicePrincipalType"] != "Application" {
		t.Fatalf("seeded SPA service principal missing/mistyped: %v", sp)
	}

	// Get by id; SP names include the id.
	status, one := graphGet(t, hts.URL, "/graph/v1.0/servicePrincipals/"+daemonID, app)
	if status != 200 || one["appId"] != daemonID {
		t.Fatalf("get service principal: %d %v", status, one)
	}
	names, _ := one["servicePrincipalNames"].([]any)
	found := false
	for _, n := range names {
		if n == daemonID {
			found = true
		}
	}
	if !found {
		t.Fatalf("servicePrincipalNames missing id: %v", names)
	}
}

func hasScopeValue(scopes []any, want string) bool {
	for _, s := range scopes {
		m, _ := s.(map[string]any)
		if m["value"] == want {
			return true
		}
	}
	return false
}

func hasRoleValue(roles []any, want string) bool {
	for _, r := range roles {
		m, _ := r.(map[string]any)
		if m["value"] == want {
			return true
		}
	}
	return false
}
