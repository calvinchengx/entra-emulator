package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

// graphSend issues an authenticated Graph write and returns status + body.
func graphSend(t *testing.T, method, origin, path, bearer string, body map[string]any) (int, map[string]any) {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, origin+path, reader)
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// TestGraphUserWrites proves create/update/delete of users through Graph (#18).
func TestGraphUserWrites(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)

	status, created := graphSend(t, "POST", hts.URL, "/graph/v1.0/users", app, map[string]any{
		"displayName":       "Carol Graph",
		"userPrincipalName": "carol@entraemulator.dev",
		"accountEnabled":    true,
		"passwordProfile":   map[string]any{"password": "S3cret!pass"},
	})
	if status != 201 {
		t.Fatalf("create user: %d %v", status, created)
	}
	id, _ := created["id"].(string)
	if id == "" || created["displayName"] != "Carol Graph" {
		t.Fatalf("bad created user: %v", created)
	}

	// Read back.
	st, got := graphGet(t, hts.URL, "/graph/v1.0/users/"+id, app)
	if st != 200 || got["userPrincipalName"] != "carol@entraemulator.dev" {
		t.Fatalf("get created user: %d %v", st, got)
	}

	// Duplicate UPN → 400 Request_BadRequest.
	status, dup := graphSend(t, "POST", hts.URL, "/graph/v1.0/users", app, map[string]any{
		"displayName": "Dup", "userPrincipalName": "carol@entraemulator.dev",
	})
	if status != 400 {
		t.Fatalf("duplicate UPN: want 400, got %d %v", status, dup)
	}

	// PATCH → 204, change reflected.
	status, _ = graphSend(t, "PATCH", hts.URL, "/graph/v1.0/users/"+id, app, map[string]any{
		"displayName": "Carol Renamed", "accountEnabled": false,
	})
	if status != 204 {
		t.Fatalf("patch user: %d", status)
	}
	_, got = graphGet(t, hts.URL, "/graph/v1.0/users/"+id, app)
	if got["displayName"] != "Carol Renamed" || got["accountEnabled"] != false {
		t.Fatalf("patch not reflected: %v", got)
	}

	// DELETE → 204, then 404.
	status, _ = graphSend(t, "DELETE", hts.URL, "/graph/v1.0/users/"+id, app, nil)
	if status != 204 {
		t.Fatalf("delete user: %d", status)
	}
	if st, _ = graphGet(t, hts.URL, "/graph/v1.0/users/"+id, app); st != 404 {
		t.Fatalf("deleted user GET: want 404, got %d", st)
	}
}

// TestGraphGroupAndMembershipWrites proves group CRUD + $ref membership (#18).
func TestGraphGroupAndMembershipWrites(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)

	status, gr := graphSend(t, "POST", hts.URL, "/graph/v1.0/groups", app, map[string]any{
		"displayName": "Marketing", "description": "Created via Graph",
	})
	if status != 201 {
		t.Fatalf("create group: %d %v", status, gr)
	}
	gid, _ := gr["id"].(string)

	// Add Alice via the $ref link body.
	status, _ = graphSend(t, "POST", hts.URL, "/graph/v1.0/groups/"+gid+"/members/$ref", app, map[string]any{
		"@odata.id": hts.URL + "/graph/v1.0/directoryObjects/" + aliceID,
	})
	if status != 204 {
		t.Fatalf("add member: %d", status)
	}
	st, members := graphGet(t, hts.URL, "/graph/v1.0/groups/"+gid+"/members", app)
	if st != 200 || len(members["value"].([]any)) != 1 {
		t.Fatalf("members after add: %d %v", st, members)
	}

	// Remove via $ref.
	status, _ = graphSend(t, "DELETE", hts.URL, "/graph/v1.0/groups/"+gid+"/members/"+aliceID+"/$ref", app, nil)
	if status != 204 {
		t.Fatalf("remove member: %d", status)
	}
	_, members = graphGet(t, hts.URL, "/graph/v1.0/groups/"+gid+"/members", app)
	if len(members["value"].([]any)) != 0 {
		t.Fatalf("members after remove: %v", members)
	}

	// PATCH + DELETE group.
	if status, _ = graphSend(t, "PATCH", hts.URL, "/graph/v1.0/groups/"+gid, app, map[string]any{"displayName": "Growth"}); status != 204 {
		t.Fatalf("patch group: %d", status)
	}
	if status, _ = graphSend(t, "DELETE", hts.URL, "/graph/v1.0/groups/"+gid, app, nil); status != 204 {
		t.Fatalf("delete group: %d", status)
	}
	if st, _ = graphGet(t, hts.URL, "/graph/v1.0/groups/"+gid, app); st != 404 {
		t.Fatalf("deleted group GET: want 404, got %d", st)
	}
}

// TestGraphApplicationWrites proves application CRUD through Graph (#18).
func TestGraphApplicationWrites(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)

	status, created := graphSend(t, "POST", hts.URL, "/graph/v1.0/applications", app, map[string]any{
		"displayName":    "Graph-created App",
		"identifierUris": []string{"api://graph-created"},
	})
	if status != 201 {
		t.Fatalf("create application: %d %v", status, created)
	}
	id, _ := created["id"].(string)
	if id == "" || created["appId"] != id {
		t.Fatalf("application id/appId: %v", created)
	}
	uris, _ := created["identifierUris"].([]any)
	if len(uris) != 1 || uris[0] != "api://graph-created" {
		t.Fatalf("identifierUris not set: %v", created)
	}

	// Verify through the admin API (read-back until #19 adds Graph reads).
	st, adminApp := getJSON(t, hts.URL+"/admin/api/apps/"+id)
	if st != 200 || adminApp["displayName"] != "Graph-created App" {
		t.Fatalf("admin read-back: %d %v", st, adminApp)
	}

	// PATCH → 204.
	if status, _ = graphSend(t, "PATCH", hts.URL, "/graph/v1.0/applications/"+id, app, map[string]any{"displayName": "Renamed App"}); status != 204 {
		t.Fatalf("patch application: %d", status)
	}
	if _, adminApp = getJSON(t, hts.URL+"/admin/api/apps/"+id); adminApp["displayName"] != "Renamed App" {
		t.Fatalf("patch not reflected: %v", adminApp["displayName"])
	}

	// DELETE → 204, then admin 404.
	if status, _ = graphSend(t, "DELETE", hts.URL, "/graph/v1.0/applications/"+id, app, nil); status != 204 {
		t.Fatalf("delete application: %d", status)
	}
	if st, _ = getJSON(t, hts.URL+"/admin/api/apps/"+id); st != 404 {
		t.Fatalf("deleted application admin GET: want 404, got %d", st)
	}
}
