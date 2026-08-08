package server

import (
	"net/http"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// TestAdministrativeUnits covers the directory container that scopes
// administration: CRUD, membership of both users and groups (each stamped with
// the right @odata.type), and the referential rules — a dangling member is
// refused, and deleting the unit takes its memberships with it.
func TestAdministrativeUnits(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)
	base := hts.URL + "/graph/v1.0/directory/administrativeUnits"

	code, created := postJSONAuth(t, base, app, map[string]any{
		"displayName": "West Region", "description": "Western offices",
	})
	if code != http.StatusCreated {
		t.Fatalf("create AU: %d %v", code, created)
	}
	auID, _ := created["id"].(string)
	if created["visibility"] != "Public" {
		t.Errorf("visibility should default to Public, got %v", created["visibility"])
	}

	t.Run("lists and reads back", func(t *testing.T) {
		status, list := graphGet(t, hts.URL, "/graph/v1.0/directory/administrativeUnits", app)
		if status != http.StatusOK {
			t.Fatalf("list: %d", status)
		}
		var found bool
		for _, v := range list["value"].([]any) {
			if m, _ := v.(map[string]any); m["id"] == auID {
				found = true
			}
		}
		if !found {
			t.Fatalf("created AU missing from list: %v", list)
		}
		if status, one := graphGet(t, hts.URL, "/graph/v1.0/directory/administrativeUnits/"+auID, app); status != 200 || one["displayName"] != "West Region" {
			t.Fatalf("get AU: %d %v", status, one)
		}
	})

	t.Run("holds users and groups, each typed", func(t *testing.T) {
		// A user…
		if code, body := postJSONAuth(t, base+"/"+auID+"/members/$ref", app, map[string]any{
			"@odata.id": hts.URL + "/graph/v1.0/users/" + aliceID,
		}); code != http.StatusNoContent {
			t.Fatalf("add user member: %d %v", code, body)
		}
		// …and a group.
		_, grp := postJSONAuth(t, hts.URL+"/graph/v1.0/groups", app, map[string]any{"displayName": "AU Group"})
		gid, _ := grp["id"].(string)
		if code, body := postJSONAuth(t, base+"/"+auID+"/members/$ref", app, map[string]any{
			"@odata.id": hts.URL + "/graph/v1.0/groups/" + gid,
		}); code != http.StatusNoContent {
			t.Fatalf("add group member: %d %v", code, body)
		}

		status, members := graphGet(t, hts.URL, "/graph/v1.0/directory/administrativeUnits/"+auID+"/members", app)
		if status != http.StatusOK {
			t.Fatalf("list members: %d", status)
		}
		types := map[string]bool{}
		for _, v := range members["value"].([]any) {
			m, _ := v.(map[string]any)
			types[m["@odata.type"].(string)] = true
		}
		if !types["#microsoft.graph.user"] || !types["#microsoft.graph.group"] {
			t.Fatalf("members must be typed as user and group: %v", members["value"])
		}
	})

	t.Run("a dangling member is refused", func(t *testing.T) {
		if code, _ := postJSONAuth(t, base+"/"+auID+"/members/$ref", app, map[string]any{
			"@odata.id": hts.URL + "/graph/v1.0/users/" + store.NewGUID(),
		}); code != http.StatusNotFound {
			t.Fatalf("nonexistent member: want 404, got %d", code)
		}
	})

	t.Run("membership can be removed", func(t *testing.T) {
		if code := deleteAuthStatus(t, base+"/"+auID+"/members/"+aliceID+"/$ref", app); code != http.StatusNoContent {
			t.Fatalf("remove member: %d", code)
		}
		_, members := graphGet(t, hts.URL, "/graph/v1.0/directory/administrativeUnits/"+auID+"/members", app)
		for _, v := range members["value"].([]any) {
			if m, _ := v.(map[string]any); m["id"] == aliceID {
				t.Fatalf("removed member is still listed: %v", members["value"])
			}
		}
	})

	t.Run("visibility is validated", func(t *testing.T) {
		if code, _ := postJSONAuth(t, base, app, map[string]any{
			"displayName": "Bad", "visibility": "Sideways",
		}); code != http.StatusBadRequest {
			t.Fatalf("invalid visibility: want 400, got %d", code)
		}
		code, hidden := postJSONAuth(t, base, app, map[string]any{
			"displayName": "Hidden Unit", "visibility": "HiddenMembership",
		})
		if code != http.StatusCreated || hidden["visibility"] != "HiddenMembership" {
			t.Fatalf("HiddenMembership: %d %v", code, hidden)
		}
	})

	t.Run("delete removes the unit and its memberships", func(t *testing.T) {
		if code := deleteAuthStatus(t, base+"/"+auID, app); code != http.StatusNoContent {
			t.Fatalf("delete AU: %d", code)
		}
		if status, _ := graphGet(t, hts.URL, "/graph/v1.0/directory/administrativeUnits/"+auID, app); status != http.StatusNotFound {
			t.Fatalf("deleted AU should 404, got %d", status)
		}
		// Members endpoint is gone with it, so no orphaned membership survives.
		if status, _ := graphGet(t, hts.URL, "/graph/v1.0/directory/administrativeUnits/"+auID+"/members", app); status != http.StatusNotFound {
			t.Fatalf("members of a deleted AU should 404, got %d", status)
		}
	})
}
