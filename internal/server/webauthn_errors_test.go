package server

import "testing"

// TestWebAuthnErrorPaths covers the passkey ceremony handlers' rejection
// branches (unknown tenant, missing/unknown user, no ceremony in progress).
func TestWebAuthnErrorPaths(t *testing.T) {
	hts, _, _ := newTestServer(t)
	wa := hts.URL + "/" + tenant + "/webauthn"

	// register/begin: missing upn → 400.
	expect(t, "register begin no upn", postRaw(t, "POST", wa+"/register/begin", `{}`), 400)
	// register/begin: malformed body → 400.
	expect(t, "register begin malformed", postRaw(t, "POST", wa+"/register/begin", `{bad`), 400)
	// register/begin: unknown user → 404.
	if code, _ := postJSON(t, wa+"/register/begin", map[string]any{"upn": "nobody@entraemulator.dev"}); code != 404 {
		t.Fatalf("register begin unknown user: want 404, got %d", code)
	}
	// register/begin: valid seeded user → 200 (starts + stores a ceremony).
	if code, _ := postJSON(t, wa+"/register/begin", map[string]any{"upn": "alice@entraemulator.dev"}); code != 200 {
		t.Fatalf("register begin alice: want 200, got %d", code)
	}

	// Finish ceremonies with no ceremony cookie → 400.
	expect(t, "register finish no ceremony", postRaw(t, "POST", wa+"/register/finish", `{}`), 400)
	expect(t, "assert finish no ceremony", postRaw(t, "POST", wa+"/assert/finish", `{}`), 400)

	// assert/begin: malformed body → 400.
	expect(t, "assert begin malformed", postRaw(t, "POST", wa+"/assert/begin", `{bad`), 400)

	// Unknown tenant on any ceremony endpoint → 404.
	expect(t, "unknown tenant", postRaw(t, "POST",
		hts.URL+"/22222222-2222-2222-2222-222222222222/webauthn/register/begin", `{"upn":"x"}`), 404)
}
