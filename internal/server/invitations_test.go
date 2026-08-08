package server

import (
	"net/http"
	"strings"
	"testing"
)

// TestB2BGuestInvitations covers the invitation flow: inviting an external
// address creates a REAL guest user in the directory (Entra's `#EXT#` UPN,
// userType Guest, externalUserState PendingAcceptance), and redeeming the
// returned link flips the state to Accepted — the bit an app branches on.
func TestB2BGuestInvitations(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)

	code, inv := postJSONAuth(t, hts.URL+"/graph/v1.0/invitations", app, map[string]any{
		"invitedUserEmailAddress": "guest@contoso.com",
		"inviteRedirectUrl":       "https://localhost:3000/welcome",
		"invitedUserDisplayName":  "Guest Contoso",
	})
	if code != http.StatusCreated {
		t.Fatalf("create invitation: %d %v", code, inv)
	}
	if inv["status"] != "PendingAcceptance" {
		t.Errorf("status = %v, want PendingAcceptance", inv["status"])
	}
	redeemURL, _ := inv["inviteRedeemUrl"].(string)
	if redeemURL == "" {
		t.Fatalf("no inviteRedeemUrl: %v", inv)
	}
	invited, _ := inv["invitedUser"].(map[string]any)
	guestID, _ := invited["id"].(string)
	if guestID == "" {
		t.Fatalf("no invitedUser.id: %v", inv)
	}

	t.Run("creates a real directory user with Entra's external shape", func(t *testing.T) {
		status, u := graphGet(t, hts.URL, "/graph/v1.0/users/"+guestID, app)
		if status != http.StatusOK {
			t.Fatalf("get guest: %d %v", status, u)
		}
		if u["userType"] != "Guest" {
			t.Errorf("userType = %v, want Guest", u["userType"])
		}
		if u["externalUserState"] != "PendingAcceptance" {
			t.Errorf("externalUserState = %v, want PendingAcceptance", u["externalUserState"])
		}
		upn, _ := u["userPrincipalName"].(string)
		if !strings.Contains(upn, "#EXT#@") || !strings.HasPrefix(upn, "guest_contoso.com") {
			t.Errorf("guest UPN should be Entra's external form, got %q", upn)
		}
		if u["mail"] != "guest@contoso.com" {
			t.Errorf("mail = %v, want the invited address", u["mail"])
		}
	})

	t.Run("redeeming accepts the invitation and redirects to the app", func(t *testing.T) {
		client := noRedirectJar()
		resp, err := client.Get(redeemURL)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("redeem: want 302 to the inviting app, got %d", resp.StatusCode)
		}
		if loc := resp.Header.Get("Location"); loc != "https://localhost:3000/welcome" {
			t.Errorf("redirect target = %q", loc)
		}

		_, u := graphGet(t, hts.URL, "/graph/v1.0/users/"+guestID, app)
		if u["externalUserState"] != "Accepted" {
			t.Fatalf("externalUserState after redemption = %v, want Accepted", u["externalUserState"])
		}
	})

	// Open-redirect guard: the redemption target is bound to the invitation at
	// creation, so a `redirect` bolted onto the link must be ignored — not
	// followed. Before this was enforced, the link carried its own destination
	// and anyone could swap it for an arbitrary origin.
	t.Run("a redirect parameter on the link cannot retarget redemption", func(t *testing.T) {
		client := noRedirectJar()
		resp, err := client.Get(redeemURL + "&redirect=https://evil.example/steal")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if loc := resp.Header.Get("Location"); strings.Contains(loc, "evil.example") {
			t.Fatalf("redemption followed an attacker-supplied redirect: %q", loc)
		}
		if resp.StatusCode == http.StatusFound &&
			resp.Header.Get("Location") != "https://localhost:3000/welcome" {
			t.Errorf("redirect target = %q, want the invitation's own URL",
				resp.Header.Get("Location"))
		}
	})

	t.Run("ordinary members are not guests", func(t *testing.T) {
		// The seeded users must still report Member with no external state, or
		// the new fields would silently mislabel the whole directory.
		status, alice := graphGet(t, hts.URL, "/graph/v1.0/users/"+aliceID, app)
		if status != http.StatusOK {
			t.Fatalf("get alice: %d", status)
		}
		if alice["userType"] != "Member" {
			t.Errorf("seeded user userType = %v, want Member", alice["userType"])
		}
		if alice["externalUserState"] != nil {
			t.Errorf("a member should have null externalUserState, got %v", alice["externalUserState"])
		}
	})

	t.Run("validation", func(t *testing.T) {
		if code, _ := postJSONAuth(t, hts.URL+"/graph/v1.0/invitations", app, map[string]any{
			"invitedUserEmailAddress": "x@y.com",
		}); code != http.StatusBadRequest {
			t.Errorf("missing inviteRedirectUrl: want 400, got %d", code)
		}
		if code, _ := postJSONAuth(t, hts.URL+"/graph/v1.0/invitations", app, map[string]any{
			"invitedUserEmailAddress": "x@y.com", "inviteRedirectUrl": "https://localhost:3000",
			"invitedUserType": "Robot",
		}); code != http.StatusBadRequest {
			t.Errorf("bad invitedUserType: want 400, got %d", code)
		}
	})
}
