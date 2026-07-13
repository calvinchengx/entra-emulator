package server

import (
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// TestAuthenticationMethods proves the authentication/methods surface reflects
// a user's stored password and passkeys, and that a passkey can be deleted.
func TestAuthenticationMethods(t *testing.T) {
	hts, _, st := newTestServer(t)
	app := appGraphToken(t, hts.URL)

	// Seed a passkey for Alice directly in the store.
	cred := &store.WebAuthnCredential{
		ID: "cred-abc123", UserID: aliceID, PublicKey: []byte("cose"),
		AAGUID: make([]byte, 16), Name: "MacBook Touch ID", CreatedAt: st.Now(),
	}
	if err := st.AddWebAuthnCredential(cred); err != nil {
		t.Fatal(err)
	}

	// Aggregate methods: password (Alice is seeded with one) + the passkey.
	st1, methods := graphGet(t, hts.URL, "/graph/v1.0/users/"+aliceID+"/authentication/methods", app)
	vals, _ := methods["value"].([]any)
	if st1 != 200 || len(vals) != 2 {
		t.Fatalf("methods: %d %v", st1, methods)
	}
	types := map[string]bool{}
	for _, v := range vals {
		m := v.(map[string]any)
		types[m["@odata.type"].(string)] = true
	}
	if !types["#microsoft.graph.passwordAuthenticationMethod"] || !types["#microsoft.graph.fido2AuthenticationMethod"] {
		t.Fatalf("expected password + fido2 methods, got %v", types)
	}

	// Typed collections.
	_, pw := graphGet(t, hts.URL, "/graph/v1.0/users/"+aliceID+"/authentication/passwordMethods", app)
	if len(pw["value"].([]any)) != 1 {
		t.Fatalf("passwordMethods: %v", pw)
	}
	_, fido := graphGet(t, hts.URL, "/graph/v1.0/users/"+aliceID+"/authentication/fido2Methods", app)
	fvals := fido["value"].([]any)
	if len(fvals) != 1 || fvals[0].(map[string]any)["displayName"] != "MacBook Touch ID" {
		t.Fatalf("fido2Methods: %v", fido)
	}

	// Delete the passkey → 204, then it is gone.
	if code, _ := graphSend(t, "DELETE", hts.URL, "/graph/v1.0/users/"+aliceID+"/authentication/fido2Methods/cred-abc123", app, nil); code != 204 {
		t.Fatalf("delete fido2 method: %d", code)
	}
	_, fido = graphGet(t, hts.URL, "/graph/v1.0/users/"+aliceID+"/authentication/fido2Methods", app)
	if len(fido["value"].([]any)) != 0 {
		t.Fatalf("passkey not deleted: %v", fido)
	}

	// A user created without a password has no password method.
	_, u := graphSend(t, "POST", hts.URL, "/graph/v1.0/users", app, map[string]any{
		"displayName": "No Pw", "userPrincipalName": "nopw@entraemulator.dev",
	})
	uid := u["id"].(string)
	_, pw = graphGet(t, hts.URL, "/graph/v1.0/users/"+uid+"/authentication/passwordMethods", app)
	if len(pw["value"].([]any)) != 0 {
		t.Fatalf("passwordless user should have no password method: %v", pw)
	}
}

// TestAuthenticationMethodsMe proves /me/authentication/methods works with a
// delegated token.
func TestAuthenticationMethodsMe(t *testing.T) {
	hts, _, _ := newTestServer(t)
	body := driveAuthCode(t, hts, "verifier-authmethods-0123456789abcd")
	access := body["access_token"].(string)

	st, methods := graphGet(t, hts.URL, "/graph/v1.0/me/authentication/methods", access)
	if st != 200 {
		t.Fatalf("/me/authentication/methods: %d %v", st, methods)
	}
	// Alice has a seeded password method.
	if len(methods["value"].([]any)) < 1 {
		t.Fatalf("expected at least the password method: %v", methods)
	}
}
