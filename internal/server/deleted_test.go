package server

import (
	"testing"
)

// deletedItemIDs extracts the id set from a deletedItems collection body.
func deletedItemIDs(coll map[string]any) map[string]bool {
	ids := map[string]bool{}
	if val, ok := coll["value"].([]any); ok {
		for _, v := range val {
			if m, ok := v.(map[string]any); ok {
				if id, ok := m["id"].(string); ok {
					ids[id] = true
				}
			}
		}
	}
	return ids
}

// TestRecycleBinUserRestore proves DELETE soft-deletes a user, the recycle bin
// lists it, and restore returns it live with its group memberships intact.
func TestRecycleBinUserRestore(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)

	// Create a user and a group, and make the user a member.
	_, u := graphSend(t, "POST", hts.URL, "/graph/v1.0/users", app, map[string]any{
		"displayName": "Dana Recycle", "userPrincipalName": "dana@entraemulator.dev",
		"accountEnabled": true,
	})
	uid, _ := u["id"].(string)
	_, gr := graphSend(t, "POST", hts.URL, "/graph/v1.0/groups", app, map[string]any{"displayName": "Recyclers"})
	gid, _ := gr["id"].(string)
	if st, _ := graphSend(t, "POST", hts.URL, "/graph/v1.0/groups/"+gid+"/members/$ref", app, map[string]any{
		"@odata.id": hts.URL + "/graph/v1.0/directoryObjects/" + uid,
	}); st != 204 {
		t.Fatalf("add member: %d", st)
	}

	// Soft-delete → gone from live collection.
	if st, _ := graphSend(t, "DELETE", hts.URL, "/graph/v1.0/users/"+uid, app, nil); st != 204 {
		t.Fatalf("delete user: %d", st)
	}
	if st, _ := graphGet(t, hts.URL, "/graph/v1.0/users/"+uid, app); st != 404 {
		t.Fatalf("deleted user still live: %d", st)
	}

	// Listed in the recycle bin, with a deletedDateTime and the user cast.
	st, coll := graphGet(t, hts.URL, "/graph/v1.0/directory/deletedItems/microsoft.graph.user", app)
	if st != 200 || !deletedItemIDs(coll)[uid] {
		t.Fatalf("deleted user not in recycle bin: %d %v", st, coll)
	}
	st, single := graphGet(t, hts.URL, "/graph/v1.0/directory/deletedItems/"+uid, app)
	if st != 200 || single["deletedDateTime"] == nil || single["@odata.type"] != "#microsoft.graph.user" {
		t.Fatalf("get deleted item: %d %v", st, single)
	}

	// Restore → live again, membership reattached.
	st, restored := graphSend(t, "POST", hts.URL, "/graph/v1.0/directory/deletedItems/"+uid+"/restore", app, nil)
	if st != 200 || restored["id"] != uid || restored["deletedDateTime"] != nil {
		t.Fatalf("restore: %d %v", st, restored)
	}
	if st, live := graphGet(t, hts.URL, "/graph/v1.0/users/"+uid, app); st != 200 || live["userPrincipalName"] != "dana@entraemulator.dev" {
		t.Fatalf("restored user not live: %d %v", st, live)
	}
	_, members := graphGet(t, hts.URL, "/graph/v1.0/groups/"+gid+"/members", app)
	if !deletedItemIDs(members)[uid] {
		t.Fatalf("membership not restored: %v", members)
	}

	// No longer in the recycle bin.
	_, coll = graphGet(t, hts.URL, "/graph/v1.0/directory/deletedItems/microsoft.graph.user", app)
	if deletedItemIDs(coll)[uid] {
		t.Fatalf("restored user still in recycle bin: %v", coll)
	}
}

// TestRecycleBinPermanentDelete proves DELETE on a recycle-bin item purges it
// so it can no longer be restored.
func TestRecycleBinPermanentDelete(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)

	_, u := graphSend(t, "POST", hts.URL, "/graph/v1.0/users", app, map[string]any{
		"displayName": "Temp", "userPrincipalName": "temp@entraemulator.dev",
	})
	uid, _ := u["id"].(string)
	graphSend(t, "DELETE", hts.URL, "/graph/v1.0/users/"+uid, app, nil)

	if st, _ := graphSend(t, "DELETE", hts.URL, "/graph/v1.0/directory/deletedItems/"+uid, app, nil); st != 204 {
		t.Fatalf("permanent delete: %d", st)
	}
	if st, _ := graphGet(t, hts.URL, "/graph/v1.0/directory/deletedItems/"+uid, app); st != 404 {
		t.Fatalf("purged item still present: %d", st)
	}
	if st, _ := graphSend(t, "POST", hts.URL, "/graph/v1.0/directory/deletedItems/"+uid+"/restore", app, nil); st != 404 {
		t.Fatalf("restore after purge: want 404, got %d", st)
	}
}

// TestRecycleBinRetention proves the 30-day window is enforced against the
// controllable clock: advancing past it purges the item.
func TestRecycleBinRetention(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)

	_, u := graphSend(t, "POST", hts.URL, "/graph/v1.0/users", app, map[string]any{
		"displayName": "Ephemeral", "userPrincipalName": "eph@entraemulator.dev",
	})
	uid, _ := u["id"].(string)
	graphSend(t, "DELETE", hts.URL, "/graph/v1.0/users/"+uid, app, nil)

	// Present before the window closes.
	_, coll := graphGet(t, hts.URL, "/graph/v1.0/directory/deletedItems/microsoft.graph.user", app)
	if !deletedItemIDs(coll)[uid] {
		t.Fatalf("item missing before retention window: %v", coll)
	}

	// Jump 31 days → purged. Mint a fresh token valid at the advanced clock
	// (the original bearer is now itself expired).
	setClock(t, hts.URL, map[string]any{"advanceSeconds": 31 * 24 * 60 * 60})
	app = appGraphToken(t, hts.URL)
	_, coll = graphGet(t, hts.URL, "/graph/v1.0/directory/deletedItems/microsoft.graph.user", app)
	if deletedItemIDs(coll)[uid] {
		t.Fatalf("item survived past 30-day retention: %v", coll)
	}
	if st, _ := graphSend(t, "POST", hts.URL, "/graph/v1.0/directory/deletedItems/"+uid+"/restore", app, nil); st != 404 {
		t.Fatalf("restore after expiry: want 404, got %d", st)
	}
}

// TestRecycleBinGroupAndApplication proves groups and applications also soft-
// delete and restore.
func TestRecycleBinGroupAndApplication(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)

	// Group.
	_, gr := graphSend(t, "POST", hts.URL, "/graph/v1.0/groups", app, map[string]any{"displayName": "Doomed"})
	gid, _ := gr["id"].(string)
	graphSend(t, "DELETE", hts.URL, "/graph/v1.0/groups/"+gid, app, nil)
	if st, _ := graphGet(t, hts.URL, "/graph/v1.0/groups/"+gid, app); st != 404 {
		t.Fatalf("group not soft-deleted: %d", st)
	}
	_, coll := graphGet(t, hts.URL, "/graph/v1.0/directory/deletedItems/microsoft.graph.group", app)
	if !deletedItemIDs(coll)[gid] {
		t.Fatalf("group not in recycle bin: %v", coll)
	}
	if st, _ := graphSend(t, "POST", hts.URL, "/graph/v1.0/directory/deletedItems/"+gid+"/restore", app, nil); st != 200 {
		t.Fatalf("restore group: %d", st)
	}
	if st, _ := graphGet(t, hts.URL, "/graph/v1.0/groups/"+gid, app); st != 200 {
		t.Fatalf("group not restored: %d", st)
	}

	// Application (with an identifier URI that must survive the round-trip).
	_, a := graphSend(t, "POST", hts.URL, "/graph/v1.0/applications", app, map[string]any{
		"displayName": "Doomed App", "identifierUris": []string{"api://doomed"},
	})
	aid, _ := a["id"].(string)
	graphSend(t, "DELETE", hts.URL, "/graph/v1.0/applications/"+aid, app, nil)
	_, coll = graphGet(t, hts.URL, "/graph/v1.0/directory/deletedItems/microsoft.graph.application", app)
	if !deletedItemIDs(coll)[aid] {
		t.Fatalf("app not in recycle bin: %v", coll)
	}
	if st, _ := graphSend(t, "POST", hts.URL, "/graph/v1.0/directory/deletedItems/"+aid+"/restore", app, nil); st != 200 {
		t.Fatalf("restore app: %d", st)
	}
	st, live := graphGet(t, hts.URL, "/graph/v1.0/applications/"+aid, app)
	uris, _ := live["identifierUris"].([]any)
	if st != 200 || len(uris) != 1 || uris[0] != "api://doomed" {
		t.Fatalf("app not restored with identifierUris: %d %v", st, live)
	}
}
