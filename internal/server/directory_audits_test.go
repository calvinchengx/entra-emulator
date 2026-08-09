package server

import (
	"net/http"
	"testing"
)

// auditsFor pulls the directory audit log and indexes it by activity.
func auditsFor(t *testing.T, hts, bearer string) map[string]map[string]any {
	t.Helper()
	status, logs := graphGet(t, hts, "/graph/v1.0/auditLogs/directoryAudits", bearer)
	if status != http.StatusOK {
		t.Fatalf("directoryAudits: %d %v", status, logs)
	}
	out := map[string]map[string]any{}
	for _, v := range logs["value"].([]any) {
		m, _ := v.(map[string]any)
		if a, _ := m["activityDisplayName"].(string); a != "" {
			out[a] = m
		}
	}
	return out
}

// TestDirectoryAuditLogs covers Graph's auditLogs/directoryAudits over a real
// mutation journal. Sign-in logs record who authenticated; these record what
// CHANGED and who changed it — so the test performs real mutations and asserts
// they appear, attributed, rather than checking an empty collection responds.
func TestDirectoryAuditLogs(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)

	// Nothing has been mutated through Graph yet.
	if len(auditsFor(t, hts.URL, app)) != 0 {
		t.Fatal("the journal should start empty")
	}

	// Perform real changes across three categories.
	code, user := postJSONAuth(t, hts.URL+"/graph/v1.0/users", app, map[string]any{
		"accountEnabled": true, "displayName": "Audit Target",
		"userPrincipalName": "audit-target@entraemulator.dev",
		"mailNickname":      "audittarget",
		"passwordProfile":   map[string]any{"password": "Aud1t!Passw0rd"},
	})
	if code != http.StatusCreated {
		t.Fatalf("create user: %d %v", code, user)
	}
	userID, _ := user["id"].(string)

	code, grp := postJSONAuth(t, hts.URL+"/graph/v1.0/groups", app, map[string]any{
		"displayName": "Audit Group", "mailEnabled": false,
		"mailNickname": "auditgroup", "securityEnabled": true,
	})
	if code != http.StatusCreated {
		t.Fatalf("create group: %d %v", code, grp)
	}
	groupID, _ := grp["id"].(string)

	if code, _ := postJSONAuth(t, hts.URL+"/graph/v1.0/groups/"+groupID+"/members/$ref", app,
		map[string]any{"@odata.id": hts.URL + "/graph/v1.0/directoryObjects/" + userID}); code != http.StatusNoContent {
		t.Fatalf("add member: %d", code)
	}

	audits := auditsFor(t, hts.URL, app)

	t.Run("every mutation is journaled with its category", func(t *testing.T) {
		for activity, wantCategory := range map[string]string{
			"Add user":            "UserManagement",
			"Add group":           "GroupManagement",
			"Add member to group": "GroupManagement",
		} {
			e, ok := audits[activity]
			if !ok {
				t.Fatalf("%q missing from the journal: %v", activity, keysOf(audits))
			}
			if e["category"] != wantCategory {
				t.Errorf("%q category = %v, want %s", activity, e["category"], wantCategory)
			}
			if e["result"] != "success" {
				t.Errorf("%q result = %v", activity, e["result"])
			}
		}
	})

	t.Run("the change is attributed to the caller", func(t *testing.T) {
		e := audits["Add user"]
		by, _ := e["initiatedBy"].(map[string]any)
		appBy, _ := by["app"].(map[string]any)
		if appBy["appId"] != daemonID {
			t.Fatalf("initiatedBy.app.appId = %v, want %s", appBy["appId"], daemonID)
		}
		// An app-only caller has no user — meaningful, not missing.
		if _, hasUser := by["user"]; hasUser {
			t.Errorf("an app-only caller must not report a user: %v", by)
		}
	})

	t.Run("the target names what changed", func(t *testing.T) {
		e := audits["Add user"]
		targets, _ := e["targetResources"].([]any)
		if len(targets) != 1 {
			t.Fatalf("targetResources: %v", e["targetResources"])
		}
		tr, _ := targets[0].(map[string]any)
		if tr["id"] != userID || tr["type"] != "User" || tr["displayName"] != "Audit Target" {
			t.Fatalf("target does not identify the created user: %v", tr)
		}
	})

	t.Run("deletes are journaled too, and rows are uniquely identified", func(t *testing.T) {
		if code := deleteAuthStatus(t, hts.URL+"/graph/v1.0/groups/"+groupID, app); code != http.StatusNoContent {
			t.Fatalf("delete group: %d", code)
		}
		after := auditsFor(t, hts.URL, app)
		if _, ok := after["Delete group"]; !ok {
			t.Fatalf("delete not journaled: %v", keysOf(after))
		}
		seen := map[string]bool{}
		for _, e := range after {
			id, _ := e["id"].(string)
			if id == "" || seen[id] {
				t.Fatalf("audit rows need unique ids, got %q", id)
			}
			seen[id] = true
		}
	})
}

func keysOf(m map[string]map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
