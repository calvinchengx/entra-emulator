package server

import "testing"

// TestMeMemberRoutesAreDelegatedOnly holds /me/getMemberGroups and
// /me/getMemberObjects to the rule every other /me route already follows: an
// app-only token has no signed-in user, so it is refused as such. They used to
// take the token's empty subject to the user store and answer 404, which is a
// different, wrong story ("that user does not exist") for the same mistake.
func TestMeMemberRoutesAreDelegatedOnly(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)
	delegated := driveAuthCode(t, hts, "verifier-mememberof-0123456789abcd")["access_token"].(string)

	for _, action := range []string{"getMemberGroups", "getMemberObjects"} {
		path := "/graph/v1.0/me/" + action

		if st, body := graphSend(t, "POST", hts.URL, path, app, map[string]any{}); st != 403 {
			t.Errorf("app-only POST %s: got %d %v, want 403", path, st, body)
		}
		// The negative control: the same route with a delegated token succeeds,
		// so the 403 above is the guard and not a route that is simply broken.
		if st, body := graphSend(t, "POST", hts.URL, path, delegated, map[string]any{}); st != 200 {
			t.Errorf("delegated POST %s: got %d %v, want 200", path, st, body)
		}
	}
}
