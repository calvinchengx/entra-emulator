package server

import (
	"net/http"
	"net/url"
	"testing"
)

func auditList(t *testing.T, origin string) []map[string]any {
	t.Helper()
	code, body := getJSON(t, origin+"/admin/api/audit")
	if code != 200 {
		t.Fatalf("get audit: %d", code)
	}
	raw, _ := body["value"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, e := range raw {
		out = append(out, e.(map[string]any))
	}
	return out
}

func TestAuditRecordsTokenExchanges(t *testing.T) {
	hts, _, _ := newTestServer(t)
	tokenURL := hts.URL + "/" + tenant + "/oauth2/v2.0/token"

	// One failing exchange (wrong secret) then one succeeding.
	postForm(t, http.DefaultClient, tokenURL, url.Values{
		"grant_type": {"client_credentials"}, "client_id": {daemonID},
		"client_secret": {"wrong"}, "scope": {"https://graph.microsoft.com/.default"},
	})
	postForm(t, http.DefaultClient, tokenURL, url.Values{
		"grant_type": {"client_credentials"}, "client_id": {daemonID},
		"client_secret": {"daemon-app-secret"}, "scope": {"https://graph.microsoft.com/.default"},
	})

	events := auditList(t, hts.URL)
	if len(events) < 2 {
		t.Fatalf("expected >=2 audit events, got %d", len(events))
	}
	// Newest first: the successful call.
	ok := events[0]
	if ok["flow"] != "token" || ok["grantType"] != "client_credentials" ||
		ok["clientId"] != daemonID || ok["ok"] != true {
		t.Fatalf("latest event should be the successful token exchange: %v", ok)
	}
	// The prior failing call captured the concrete reason.
	bad := events[1]
	if bad["ok"] != false || bad["error"] != "invalid_client" {
		t.Fatalf("failing event should record invalid_client: %v", bad)
	}
	if reason, _ := bad["reason"].(string); reason == "" {
		t.Fatalf("failing event should carry an error_description reason: %v", bad)
	}
}

func TestAuditCapturesConcreteReason(t *testing.T) {
	hts, _, _ := newTestServer(t)

	// A bogus authorization_code redemption yields invalid_grant with a
	// concrete AADSTS reason — exactly the "why won't sign-in work" signal.
	postForm(t, http.DefaultClient, hts.URL+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {"not-a-real-code"},
		"redirect_uri": {redirect}, "client_id": {spaID},
	})

	var found bool
	for _, e := range auditList(t, hts.URL) {
		if e["flow"] == "token" && e["error"] == "invalid_grant" {
			if reason, _ := e["reason"].(string); reason != "" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("expected an invalid_grant token event carrying a reason")
	}
}

func TestAuditClear(t *testing.T) {
	hts, _, _ := newTestServer(t)
	// Generate one event.
	clientCreds(t, hts.URL)
	if len(auditList(t, hts.URL)) == 0 {
		t.Fatal("expected at least one event before clear")
	}
	deleteReq(t, hts.URL+"/admin/api/audit")
	if n := len(auditList(t, hts.URL)); n != 0 {
		t.Fatalf("audit should be empty after clear, got %d", n)
	}
}
