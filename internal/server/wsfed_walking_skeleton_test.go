package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// DISTILL walking skeleton for feature ws-fed.
//
// Gherkin: tests/acceptance/ws-fed/walking-skeleton.feature
// Scenario: Priya completes Tasks API WS-Fed sign-in on a clean emulator
//
// Enters through driving ports only (httptest emulator HTTP), matching
// saml_sso_test.go. Production packages already exist; GET /{tid}/wsfed is
// unrouted (404) and FederationMetadata is SAML-only. That is RED, not BROKEN.
// Do not add SCAFFOLD panic handlers into internal/identity — they would break Register.

const (
	testTasksAppID      = "55556666-7777-8888-9999-000011112222"
	testTasksAppIDURI   = "api://tasks-api"
	testTasksWSFedReply = "https://rp.example.test/signin-wsfed"
	testWSFedWctx       = "tasks-return-state-7"
)

func registerTasksAPI(t *testing.T, st *store.Store, tenantID string) *store.App {
	t.Helper()
	app := &store.App{
		ID: testTasksAppID, TenantID: tenantID,
		DisplayName: "Tasks API", AppIDURI: testTasksAppIDURI,
	}
	if err := st.CreateApp(app); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddRedirectURI(app.ID, testTasksWSFedReply, "wsfed-reply"); err != nil {
		t.Fatal(err)
	}
	return app
}

func wsfedChallengeURL(base, tenant string) string {
	q := url.Values{
		"wa":      {"wsignin1.0"},
		"wtrealm": {testTasksAppIDURI},
		"wreply":  {testTasksWSFedReply},
		"wctx":    {testWSFedWctx},
	}
	return base + "/" + tenant + "/wsfed?" + q.Encode()
}

// TestPriyaCompletesTasksAPIWSFedSignIn is the first (enabled) walking-skeleton
// scenario. Later scenarios in this file are t.Skip until this one is green.
func TestPriyaCompletesTasksAPIWSFedSignIn(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPI(t, st, cfg.TenantID)

	meta := fetchMetadata(t, hts.URL, cfg.TenantID)
	body := string(meta)
	if !strings.Contains(body, "RoleDescriptor") {
		t.Fatalf("FederationMetadata has no WS-Fed RoleDescriptor (document is SAML-only):\n%s", body)
	}
	wantSTS := hts.URL + "/" + cfg.TenantID + "/wsfed"
	if !strings.Contains(body, "PassiveRequestorEndpoint") || !strings.Contains(body, wantSTS) {
		t.Fatalf("FederationMetadata does not name PassiveRequestorEndpoint %s:\n%s", wantSTS, body)
	}
	if !strings.Contains(body, "SecurityTokenServiceEndpoint") {
		t.Fatalf("FederationMetadata omits SecurityTokenServiceEndpoint:\n%s", body)
	}
	if !strings.Contains(body, "IDPSSODescriptor") {
		t.Fatal("growing WS-Fed RoleDescriptor removed IDPSSODescriptor")
	}

	c := samlClient(t)
	resp, err := c.Get(wsfedChallengeURL(hts.URL, cfg.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, resp)
	if resp.StatusCode == http.StatusNotFound {
		t.Fatalf("GET /{tid}/wsfed wa=wsignin1.0 returned 404; the challenge must be login HTML")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /{tid}/wsfed returned %d, want 200 login HTML:\n%s", resp.StatusCode, page)
	}
	if strings.Contains(page, "wresult") || strings.Contains(page, "RequestSecurityTokenResponse") {
		t.Fatal("unauthenticated challenge posted a wresult; want login HTML")
	}
	if !strings.Contains(page, "LOCAL EMULATOR") || !strings.Contains(page, "Pick an account") {
		t.Fatalf("challenge is not the existing account picker:\n%s", page)
	}
	if !strings.Contains(page, "/"+cfg.TenantID+"/wsfed") {
		t.Fatalf("picker POST action is not /{tid}/wsfed:\n%s", page)
	}

	form := url.Values{
		"__ee_state": {firstMatch(t, stateFieldRe, page, "signed state")},
		"__ee_user":  {firstMatch(t, userFieldRe, page, "an account to pick")},
	}
	post, err := c.PostForm(hts.URL+"/"+cfg.TenantID+"/wsfed", form)
	if err != nil {
		t.Fatal(err)
	}
	out := readAll(t, post)
	if post.StatusCode != http.StatusOK {
		t.Fatalf("account choice returned %d:\n%s", post.StatusCode, out)
	}
	action := firstMatch(t, actionRe, out, "auto-POST form action")
	if action != testTasksWSFedReply {
		t.Fatalf("wresult POSTs to %q, want registered wsfed-reply %q", action, testTasksWSFedReply)
	}
	if !strings.Contains(out, `name="wa"`) || !strings.Contains(out, "wsignin1.0") {
		t.Fatalf("auto-POST missing wa=wsignin1.0:\n%s", out)
	}
	if !strings.Contains(out, `name="wresult"`) {
		t.Fatalf("auto-POST missing wresult:\n%s", out)
	}
	if !strings.Contains(out, testWSFedWctx) {
		t.Fatalf("auto-POST missing echoed wctx %q:\n%s", testWSFedWctx, out)
	}
	if !strings.Contains(out, "SAMLV2.0") && !strings.Contains(out, `Version="2.0"`) {
		t.Fatalf("wresult is not a SAML 2.0 assertion:\n%s", out)
	}
	if !strings.Contains(out, testTasksAppIDURI) {
		t.Fatalf("assertion Audience is not %s:\n%s", testTasksAppIDURI, out)
	}
}

func TestPriyaCompletesWSFedSignInAlongsideOIDCAndSAML(t *testing.T) {
	t.Skip("pending: enable after walking skeleton (environment with-pre-commit)")
}

func TestPriyaCompletesWSFedSignInAfterRegisteringReplyOnStaleDirectory(t *testing.T) {
	t.Skip("pending: enable after walking skeleton (environment with-stale-config)")
}

func TestUnmodifiedWsFederationCompletesSignIn(t *testing.T) {
	t.Skip("pending: KPI-1 e2e/wsfed stranger — see e2e/wsfed/README.md (DELIVER US-05)")
}

func TestUnknownWtrealmDoesNotIssueAToken(t *testing.T) {
	t.Skip("pending: US-06 refuse-unsafe")
}

func TestEmptyRealmIsRefused(t *testing.T) {
	t.Skip("pending: US-06 refuse-unsafe")
}

func TestUnregisteredWreplyDoesNotReceiveAToken(t *testing.T) {
	t.Skip("pending: US-07 refuse-unsafe")
}

func TestMissingWreplyDoesNotReceiveAToken(t *testing.T) {
	t.Skip("pending: US-07 refuse-unsafe")
}

func TestSAMLACSOnlyReplyIsRefused(t *testing.T) {
	t.Skip("pending: US-07 saml-acs-only wreply")
}

func TestWebOnlyReplyIsRefused(t *testing.T) {
	t.Skip("pending: US-07 web-only wreply")
}

func TestAnotherAppsReplyIsNotAccepted(t *testing.T) {
	t.Skip("pending: US-07 cross-app wreply")
}

func TestUnsolicitedWresultIsRefused(t *testing.T) {
	t.Skip("pending: US-08 unsolicited wresult")
}

func TestWSFedChallengeAndSuccessAppearInAudit(t *testing.T) {
	t.Skip("pending: Admin GET /admin/api/audit and Graph GET /{tid}/v1.0/auditLogs/signIns")
}

func TestRefusedChallengeIsRecordedWithReason(t *testing.T) {
	t.Skip("pending: refuse-unsafe audit Reason")
}

func TestExistingSAMLSignInStillCompletesAfterWSFedMetadataGrowth(t *testing.T) {
	t.Skip("pending: guardrail e2e/saml after FederationMetadata growth")
}

func TestExistingOIDCSignInStillCompletes(t *testing.T) {
	t.Skip("pending: guardrail existing OIDC e2e")
}

func TestPOSTAsWellAsGETCanStartSignIn(t *testing.T) {
	t.Skip("pending: US-02 POST /{tid}/wsfed")
}

func TestPasswordRequiredModeStaysTheExistingForm(t *testing.T) {
	t.Skip("pending: US-03 password-required chrome")
}
