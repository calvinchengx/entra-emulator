package server

import (
	"testing"
)

// TestGraphMemberRefParity proves member $ref add accepts a UPN reference and
// returns 400 when the member already exists (Graph parity).
func TestGraphMemberRefParity(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)

	_, gr := graphSend(t, "POST", hts.URL, "/graph/v1.0/groups", app, map[string]any{"displayName": "RefParity"})
	gid := gr["id"].(string)

	// Add Alice by UPN via the @odata.id reference body.
	st, _ := graphSend(t, "POST", hts.URL, "/graph/v1.0/groups/"+gid+"/members/$ref", app, map[string]any{
		"@odata.id": hts.URL + "/graph/v1.0/users/alice@entraemulator.dev",
	})
	if st != 204 {
		t.Fatalf("add member by UPN: want 204, got %d", st)
	}
	_, members := graphGet(t, hts.URL, "/graph/v1.0/groups/"+gid+"/members", app)
	if !deletedItemIDs(members)[aliceID] {
		t.Fatalf("UPN ref did not resolve to Alice: %v", members)
	}

	// Adding the same member again → 400.
	st, body := graphSend(t, "POST", hts.URL, "/graph/v1.0/groups/"+gid+"/members/$ref", app, map[string]any{
		"@odata.id": hts.URL + "/graph/v1.0/users/" + aliceID,
	})
	if st != 400 {
		t.Fatalf("duplicate member: want 400, got %d %v", st, body)
	}
}

// TestGraphCreateUserIgnoresUnmodeledProps proves a full Entra create-user
// payload (mailNickname, passwordProfile.forceChangePasswordNextSignIn) is
// accepted rather than rejected.
func TestGraphCreateUserIgnoresUnmodeledProps(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)

	st, created := graphSend(t, "POST", hts.URL, "/graph/v1.0/users", app, map[string]any{
		"accountEnabled":    true,
		"displayName":       "Melva Prince",
		"mailNickname":      "mprince",
		"userPrincipalName": "mprince@entraemulator.dev",
		"passwordProfile": map[string]any{
			"forceChangePasswordNextSignIn": true,
			"password":                      "S3cret!pass",
		},
	})
	if st != 201 || created["displayName"] != "Melva Prince" {
		t.Fatalf("create with full Entra payload: %d %v", st, created)
	}
}
