package server

import (
	"net/http"
	"testing"
)

// TestGraphSignInLogs covers auditLogs/signIns over the emulator's real flow
// recorder. The point of the work behind it: a signIn row is worthless without
// the user, so the recorder now carries the identity each exchange resolved and
// this asserts it arrives — while app-only flows stay userless, which is
// correct rather than missing.
func TestGraphSignInLogs(t *testing.T) {
	hts, _, _ := newTestServer(t)

	// Generate real traffic: a delegated sign-in (ROPC resolves a user) and an
	// app-only exchange (no user by definition).
	_ = ropcAccessToken(t, hts.URL, spaID, "api://"+spaID+"/access_as_user")
	app := appGraphToken(t, hts.URL)

	status, logs := graphGet(t, hts.URL, "/graph/v1.0/auditLogs/signIns", app)
	if status != http.StatusOK {
		t.Fatalf("signIns: %d %v", status, logs)
	}
	rows, _ := logs["value"].([]any)
	if len(rows) == 0 {
		t.Fatal("no sign-ins recorded despite two real exchanges")
	}

	var delegated, appOnly map[string]any
	for _, v := range rows {
		m, _ := v.(map[string]any)
		switch m["clientAppUsed"] {
		case "Resource Owner Password Credential":
			delegated = m
		case "Client Credentials":
			appOnly = m
		}
	}

	t.Run("a delegated sign-in names the user", func(t *testing.T) {
		if delegated == nil {
			t.Fatalf("no ROPC sign-in row: %v", rows)
		}
		if delegated["userId"] != aliceID {
			t.Errorf("userId = %v, want %s", delegated["userId"], aliceID)
		}
		upn, _ := delegated["userPrincipalName"].(string)
		if upn == "" {
			t.Errorf("userPrincipalName missing — the recorder is not carrying identity")
		}
		if delegated["appId"] != spaID {
			t.Errorf("appId = %v, want %s", delegated["appId"], spaID)
		}
		st, _ := delegated["status"].(map[string]any)
		if st["errorCode"] != float64(0) {
			t.Errorf("a successful sign-in should carry errorCode 0, got %v", st)
		}
	})

	t.Run("an app-only exchange has no user, and that is correct", func(t *testing.T) {
		if appOnly == nil {
			t.Fatalf("no client-credentials row: %v", rows)
		}
		if appOnly["userId"] != nil {
			t.Errorf("client_credentials has no user; userId = %v", appOnly["userId"])
		}
		if appOnly["isInteractive"] != false {
			t.Errorf("a back-channel exchange is not interactive: %v", appOnly["isInteractive"])
		}
	})

	t.Run("a failure is recorded with its reason", func(t *testing.T) {
		// A bad secret: the exchange fails, and the log must say why.
		_, _ = postForm(t, http.DefaultClient, hts.URL+"/"+tenant+"/oauth2/v2.0/token", formValues(map[string]string{
			"grant_type": "client_credentials", "client_id": daemonID,
			"client_secret": "wrong-secret", "scope": "https://graph.microsoft.com/.default",
		}))
		_, logs := graphGet(t, hts.URL, "/graph/v1.0/auditLogs/signIns", app)
		var failed map[string]any
		for _, v := range logs["value"].([]any) {
			m, _ := v.(map[string]any)
			if st, _ := m["status"].(map[string]any); st["errorCode"] != float64(0) {
				failed = m
			}
		}
		if failed == nil {
			t.Fatalf("the failed exchange is missing from the sign-in log")
		}
		st, _ := failed["status"].(map[string]any)
		if st["failureReason"] == nil || st["failureReason"] == "" {
			t.Errorf("a failure must carry its reason: %v", st)
		}
	})

	t.Run("rows are individually identified", func(t *testing.T) {
		seen := map[string]bool{}
		for _, v := range rows {
			m, _ := v.(map[string]any)
			id, _ := m["id"].(string)
			if id == "" {
				t.Fatalf("a sign-in row has no id: %v", m)
			}
			if seen[id] {
				t.Fatalf("duplicate sign-in id %q — consumers cannot de-duplicate", id)
			}
			seen[id] = true
		}
	})
}

// formValues adapts a map to url.Values for the shared postForm helper.
func formValues(m map[string]string) map[string][]string {
	out := map[string][]string{}
	for k, v := range m {
		out[k] = []string{v}
	}
	return out
}
