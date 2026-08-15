package server

import (
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// DISTILL walking skeleton for feature ws-fed-sign-out.
//
// Gherkin: tests/acceptance/ws-fed-sign-out/walking-skeleton.feature
// Scenario: Priya signs Alice out of the Tasks API on a clean emulator
//
// Enters through driving ports only (httptest emulator HTTP), matching
// wsfed_walking_skeleton_test.go. Production packages already exist;
// handleWSFed ignores wa, so a live session on wsignout1.0 can mint wresult
// (DISCUSS D12 / ADR-006). That is RED, not BROKEN.
// Do not add SCAFFOLD panic handlers into handleWSFed — they would break Register.
//
// Return URL (DESIGN): https://rp.example.test/wsfed-signed-out
// Sign-in callback remains https://rp.example.test/signin-wsfed.

const testTasksWSFedSignOutReply = "https://rp.example.test/wsfed-signed-out"

func registerTasksAPIWithSignOutReturn(t *testing.T, st *store.Store, tenantID string) *store.App {
	t.Helper()
	app := registerTasksAPI(t, st, tenantID)
	if _, err := st.AddRedirectURI(app.ID, testTasksWSFedSignOutReply, "wsfed-reply"); err != nil {
		t.Fatal(err)
	}
	return app
}

func wsfedSignOutURL(base, tenant string) string {
	q := url.Values{
		"wa":      {"wsignout1.0"},
		"wtrealm": {testTasksAppIDURI},
		"wreply":  {testTasksWSFedSignOutReply},
	}
	return base + "/" + tenant + "/wsfed?" + q.Encode()
}

func sessionCookieValue(t *testing.T, c *http.Client, originStr string) string {
	t.Helper()
	origin, err := url.Parse(originStr)
	if err != nil {
		t.Fatal(err)
	}
	for _, ck := range c.Jar.Cookies(origin) {
		if ck.Name == "ee_session" {
			return ck.Value
		}
	}
	return ""
}

func completeTasksAPIWSFedSignInOn(t *testing.T, c *http.Client, base, tenant, wctx, userID string) string {
	t.Helper()
	q := url.Values{
		"wa":      {"wsignin1.0"},
		"wtrealm": {testTasksAppIDURI},
		"wreply":  {testTasksWSFedReply},
	}
	if wctx != "" {
		q.Set("wctx", wctx)
	}
	resp, err := c.Get(base + "/" + tenant + "/wsfed?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge returned %d:\n%s", resp.StatusCode, page)
	}
	if userID == "" {
		userID = firstMatch(t, userFieldRe, page, "an account to pick")
	}
	form := url.Values{
		"__ee_state": {firstMatch(t, stateFieldRe, page, "signed state")},
		"__ee_user":  {userID},
	}
	post, err := c.PostForm(base+"/"+tenant+"/wsfed", form)
	if err != nil {
		t.Fatal(err)
	}
	out := readAll(t, post)
	if post.StatusCode != http.StatusOK {
		t.Fatalf("account choice returned %d:\n%s", post.StatusCode, out)
	}
	if !strings.Contains(out, `name="wresult"`) {
		t.Fatalf("sign-in did not mint wresult:\n%s", out)
	}
	return out
}

func assertSignOutDidNotMint(t *testing.T, resp *http.Response, page string) {
	t.Helper()
	if strings.Contains(page, "wresult") || strings.Contains(page, "RequestSecurityTokenResponse") {
		t.Fatal("wa=wsignout1.0 minted a wresult; sign-out must never issue a token")
	}
	if m := actionRe.FindStringSubmatch(page); len(m) > 1 && (m[1] == testTasksWSFedReply || m[1] == testTasksWSFedSignOutReply) {
		t.Fatalf("sign-out POSTed a token to %q:\n%s", m[1], page)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("sign-out returned %d, want 302 to registered SignOutWreply:\n%s", resp.StatusCode, page)
	}
	if loc := resp.Header.Get("Location"); loc != testTasksWSFedSignOutReply {
		t.Fatalf("sign-out Location %q, want registered SignOutWreply %q", loc, testTasksWSFedSignOutReply)
	}
}

// TestPriyaSignsAliceOutOfTheTasksAPI is the first walking-skeleton scenario
// (environment: clean). WS-2, WS-3, and KPI-1 follow; KPI-1 is e2e/wsfed.
func TestPriyaSignsAliceOutOfTheTasksAPI(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPIWithSignOutReturn(t, st, cfg.TenantID)

	meta := fetchMetadata(t, hts.URL, cfg.TenantID)
	body := string(meta)
	if !strings.Contains(body, "RoleDescriptor") {
		t.Fatalf("FederationMetadata has no WS-Fed RoleDescriptor:\n%s", body)
	}
	wantSTS := hts.URL + "/" + cfg.TenantID + "/wsfed"
	if !strings.Contains(body, "PassiveRequestorEndpoint") || !strings.Contains(body, wantSTS) {
		t.Fatalf("FederationMetadata does not name PassiveRequestorEndpoint %s:\n%s", wantSTS, body)
	}

	c := samlClient(t)
	completeTasksAPIWSFedSignInOn(t, c, hts.URL, cfg.TenantID, testWSFedWctx, store.SeedUserAliceID)
	if sessionCookieValue(t, c, hts.URL) == "" {
		t.Fatal("expected an emulator session after WS-Fed sign-in")
	}

	resp, err := c.Get(wsfedSignOutURL(hts.URL, cfg.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, resp)
	assertSignOutDidNotMint(t, resp, page)

	if sessionCookieValue(t, c, hts.URL) != "" {
		t.Fatal("Alice's emulator session is still present after wa=wsignout1.0")
	}

	challenge, err := c.Get(wsfedChallengeURL(hts.URL, cfg.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	next := readAll(t, challenge)
	if challenge.StatusCode != http.StatusOK {
		t.Fatalf("next wsignin1.0 returned %d:\n%s", challenge.StatusCode, next)
	}
	if strings.Contains(next, "wresult") || strings.Contains(next, "RequestSecurityTokenResponse") {
		t.Fatal("next wsignin1.0 after sign-out minted a wresult; want Pick an account")
	}
	if !strings.Contains(next, "Pick an account") || !strings.Contains(next, "LOCAL EMULATOR") {
		t.Fatalf("next wsignin1.0 is not Pick an account:\n%s", next)
	}
	if !strings.Contains(next, "alice@entraemulator.dev") {
		t.Fatalf("Alice is not listed after sign-out:\n%s", next)
	}
}

func TestPriyaSignsAliceOutAlongsideOIDCAndSAML(t *testing.T) {
	t.Skip("pending: enable after walking skeleton (WS-2 with-pre-commit)")
	hts, cfg, st := newTestServer(t)
	registerSAMLApp(t, st, cfg.TenantID)
	registerTasksAPIWithSignOutReturn(t, st, cfg.TenantID)

	c := samlClient(t)
	completeTasksAPIWSFedSignInOn(t, c, hts.URL, cfg.TenantID, testWSFedWctx, store.SeedUserAliceID)
	resp, err := c.Get(wsfedSignOutURL(hts.URL, cfg.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, resp)
	assertSignOutDidNotMint(t, resp, page)
	if sessionCookieValue(t, c, hts.URL) != "" {
		t.Fatal("Alice's emulator session is still present after wa=wsignout1.0")
	}

	oidc := driveAuthCode(t, hts, "verifier-supercalifragilistic-0123456789")
	if oidc["id_token"] == nil || oidc["access_token"] == nil {
		t.Fatalf("OIDC sign-in did not complete on the same emulator: %v", oidc)
	}
	saml := signInOverSAML(t, &httptestServer{URL: hts.URL}, cfg.TenantID, "")
	if got := firstMatch(t, actionRe, saml, "SAML form action"); got != testSPACS {
		t.Fatalf("SAML form posts to %q, want the registered ACS %q", got, testSPACS)
	}
}

func TestPriyaSignsAliceOutAfterRegisteringDistinctReturnOnStaleDirectory(t *testing.T) {
	t.Skip("pending: enable after walking skeleton (WS-3 with-stale-config)")
	hts, cfg, st := newTestServer(t)
	registerTasksAPI(t, st, cfg.TenantID)

	code, _ := postJSON(t, hts.URL+"/admin/api/apps/"+testTasksAppID+"/redirectUris", map[string]any{
		"uri": testTasksWSFedSignOutReply, "type": "wsfed-reply",
	})
	if code != http.StatusCreated {
		t.Fatalf("registering sign-out wsfed-reply returned %d, want 201", code)
	}

	c := samlClient(t)
	completeTasksAPIWSFedSignInOn(t, c, hts.URL, cfg.TenantID, testWSFedWctx, store.SeedUserAliceID)
	resp, err := c.Get(wsfedSignOutURL(hts.URL, cfg.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, resp)
	assertSignOutDidNotMint(t, resp, page)
}

func TestUnmodifiedWsFederationCompletesSignOut(t *testing.T) {
	t.Skip("KPI-1 witness is e2e/wsfed (python3 e2e/run.py wsfed including SignOut); DELIVER extends e2e/wsfed — two wsfed-reply URIs, SignOutWreply ≠ CallbackPath")
}

func TestFederationMetadataStillNamesSignOutOnTheSignInEndpoint(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	body := fetchMetadata(t, hts.URL, cfg.TenantID)
	rd := parseFederationMetadata(t, body).FindElement("./RoleDescriptor")
	if rd == nil {
		t.Fatal("FederationMetadata has no WS-Fed RoleDescriptor")
	}
	wantSTS := hts.URL + "/" + cfg.TenantID + "/wsfed"
	passive := fedEndpointAddress(rd, "PassiveRequestorEndpoint")
	if passive != wantSTS {
		t.Fatalf("sign-out URL %q is not the PassiveRequestorEndpoint %s", passive, wantSTS)
	}
	if sts := fedEndpointAddress(rd, "SecurityTokenServiceEndpoint"); sts != passive {
		t.Fatalf("sign-in STS %q differs from advertised sign-out PassiveRequestorEndpoint %q", sts, passive)
	}
}

func TestSAMLAppsStillSeeTheirDescriptorAfterSignOutIsWitnessed(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	entity := parseFederationMetadata(t, fetchMetadata(t, hts.URL, cfg.TenantID))
	if entity.FindElement("./RoleDescriptor") == nil {
		t.Fatal("WS-Fed RoleDescriptor is missing")
	}
	idp := entity.FindElement("./IDPSSODescriptor")
	if idp == nil {
		t.Fatal("witnessing sign-out removed IDPSSODescriptor")
	}
	wantSSO := hts.URL + "/" + cfg.TenantID + "/saml2"
	var sso int
	for _, el := range idp.FindElements("./SingleSignOnService") {
		sso++
		if loc := el.SelectAttrValue("Location", ""); loc != wantSSO {
			t.Fatalf("SAML SSO Location %q, want %s", loc, wantSSO)
		}
	}
	if sso == 0 {
		t.Fatal("IDPSSODescriptor has no SingleSignOnService")
	}
}

func TestPriyaIsNotSentToASecondMetadataURLForSignOut(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	body := fetchMetadata(t, hts.URL, cfg.TenantID)
	if parseFederationMetadata(t, body).FindElement("./RoleDescriptor") == nil {
		t.Fatal("WS-Fed RoleDescriptor is not on the existing FederationMetadata URL")
	}
	if strings.Contains(string(body), "/wsfed/metadata") {
		t.Fatal("existing metadata document points Priya at /wsfed/metadata")
	}
	resp, err := http.Get(hts.URL + "/" + cfg.TenantID + "/wsfed/metadata")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /{tid}/wsfed/metadata returned %d, want 404 so MetadataAddress stays the existing URL", resp.StatusCode)
	}
}

func TestExistingSAMLSignInStillCompletesAfterWSFedSignOut(t *testing.T) {
	t.Skip("pending: enable after walking skeleton (US-05)")
	hts, cfg, st := newTestServer(t)
	registerSAMLApp(t, st, cfg.TenantID)
	registerTasksAPIWithSignOutReturn(t, st, cfg.TenantID)
	c := samlClient(t)
	completeTasksAPIWSFedSignInOn(t, c, hts.URL, cfg.TenantID, testWSFedWctx, store.SeedUserAliceID)
	resp, err := c.Get(wsfedSignOutURL(hts.URL, cfg.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	_ = readAll(t, resp)

	saml := signInOverSAML(t, &httptestServer{URL: hts.URL}, cfg.TenantID, "")
	if got := firstMatch(t, actionRe, saml, "SAML form action"); got != testSPACS {
		t.Fatalf("SAML form posts to %q, want the registered ACS %q", got, testSPACS)
	}
}

func TestExistingOIDCSignInStillCompletesAfterWSFedSignOut(t *testing.T) {
	t.Skip("pending: enable after walking skeleton (US-05)")
	hts, cfg, st := newTestServer(t)
	registerTasksAPIWithSignOutReturn(t, st, cfg.TenantID)
	c := samlClient(t)
	completeTasksAPIWSFedSignInOn(t, c, hts.URL, cfg.TenantID, testWSFedWctx, store.SeedUserAliceID)
	resp, err := c.Get(wsfedSignOutURL(hts.URL, cfg.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	_ = readAll(t, resp)

	oidc := driveAuthCode(t, hts, "verifier-supercalifragilistic-0123456789")
	if oidc["id_token"] == nil || oidc["access_token"] == nil {
		t.Fatalf("OIDC sign-in did not complete: %v", oidc)
	}
}

func TestSignOutWithALiveSessionDoesNotMintAToken(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPIWithSignOutReturn(t, st, cfg.TenantID)
	c := samlClient(t)
	completeTasksAPIWSFedSignInOn(t, c, hts.URL, cfg.TenantID, testWSFedWctx, store.SeedUserAliceID)
	resp, err := c.Get(wsfedSignOutURL(hts.URL, cfg.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, resp)
	assertSignOutDidNotMint(t, resp, page)
}

func TestRepeatingSignOutWithNoSessionStillReturnsToRegisteredReply(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPIWithSignOutReturn(t, st, cfg.TenantID)
	c := samlClient(t)
	resp, err := c.Get(wsfedSignOutURL(hts.URL, cfg.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, resp)
	assertSignOutDidNotMint(t, resp, page)
	if loc := resp.Header.Get("Location"); loc == testAttackerReply {
		t.Fatal("idempotent sign-out bounced to an unowned URL")
	}
}

func TestPOSTAsWellAsGETCanSignOut(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPIWithSignOutReturn(t, st, cfg.TenantID)
	c := samlClient(t)
	completeTasksAPIWSFedSignInOn(t, c, hts.URL, cfg.TenantID, testWSFedWctx, store.SeedUserAliceID)
	resp, err := c.PostForm(hts.URL+"/"+cfg.TenantID+"/wsfed", url.Values{
		"wa":      {"wsignout1.0"},
		"wtrealm": {testTasksAppIDURI},
		"wreply":  {testTasksWSFedSignOutReply},
	})
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, resp)
	assertSignOutDidNotMint(t, resp, page)
}

func TestAfterSignOutAliceIsStillListed(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPIWithSignOutReturn(t, st, cfg.TenantID)
	c := samlClient(t)
	completeTasksAPIWSFedSignInOn(t, c, hts.URL, cfg.TenantID, testWSFedWctx, store.SeedUserAliceID)
	resp, err := c.Get(wsfedSignOutURL(hts.URL, cfg.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, resp)
	assertSignOutDidNotMint(t, resp, page)
	challenge, err := c.Get(wsfedChallengeURL(hts.URL, cfg.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	next := readAll(t, challenge)
	if !strings.Contains(next, "alice@entraemulator.dev") {
		t.Fatalf("Alice is not listed after sign-out:\n%s", next)
	}
}

func TestChoosingAliceAfterSignOutStillCompletesSignIn(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPIWithSignOutReturn(t, st, cfg.TenantID)
	c := samlClient(t)
	completeTasksAPIWSFedSignInOn(t, c, hts.URL, cfg.TenantID, testWSFedWctx, store.SeedUserAliceID)
	resp, err := c.Get(wsfedSignOutURL(hts.URL, cfg.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	_ = readAll(t, resp)

	out := completeTasksAPIWSFedSignInOn(t, c, hts.URL, cfg.TenantID, testWSFedWctx, store.SeedUserAliceID)
	if got := firstMatch(t, actionRe, out, "auto-POST form action"); got != testTasksWSFedReply {
		t.Fatalf("wresult POSTs to %q, want sign-in callback %q", got, testTasksWSFedReply)
	}
}

func TestUnknownWaIsRefusedOnTheEmulator(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPIWithSignOutReturn(t, st, cfg.TenantID)
	q := url.Values{
		"wa":      {"wsignoutcleanup1.0"},
		"wtrealm": {testTasksAppIDURI},
		"wreply":  {testTasksWSFedSignOutReply},
	}
	c := samlClient(t)
	resp, err := c.Get(hts.URL + "/" + cfg.TenantID + "/wsfed?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, resp)
	assertWSFedRefusedOnEmulator(t, resp, page, testTasksWSFedSignOutReply)

	empty, err := c.Get(hts.URL + "/" + cfg.TenantID + "/wsfed?" + url.Values{
		"wtrealm": {testTasksAppIDURI},
		"wreply":  {testTasksWSFedReply},
	}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	emptyPage := readAll(t, empty)
	if empty.StatusCode != http.StatusOK || strings.Contains(emptyPage, "wresult") {
		t.Fatalf("empty wa must still start sign-in:\n%s", emptyPage)
	}
}

func TestSignOutCarryingATokenBodyDoesNotDeliverAToken(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPIWithSignOutReturn(t, st, cfg.TenantID)
	c := samlClient(t)
	completeTasksAPIWSFedSignInOn(t, c, hts.URL, cfg.TenantID, testWSFedWctx, store.SeedUserAliceID)
	resp, err := c.PostForm(hts.URL+"/"+cfg.TenantID+"/wsfed", url.Values{
		"wa":      {"wsignout1.0"},
		"wresult": {forgedWSFedWresult},
		"wtrealm": {testTasksAppIDURI},
		"wreply":  {testTasksWSFedReply},
	})
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, resp)
	if strings.Contains(page, `name="wresult"`) && strings.Contains(page, "SAMLV2.0") {
		t.Fatalf("sign-out with a wresult body minted a token:\n%s", page)
	}
	if m := actionRe.FindStringSubmatch(page); len(m) > 1 && m[1] == testTasksWSFedReply {
		t.Fatalf("sign-out delivered a token to the sign-in callback:\n%s", page)
	}
}

func TestUnknownWtrealmOnSignOutDoesNotReturnToCallerURL(t *testing.T) {
	t.Skip("pending: enable after walking skeleton (US-06)")
	hts, cfg, st := newTestServer(t)
	registerTasksAPIWithSignOutReturn(t, st, cfg.TenantID)
	q := url.Values{
		"wa":      {"wsignout1.0"},
		"wtrealm": {"api://not-registered"},
		"wreply":  {testAttackerReply},
	}
	c := samlClient(t)
	resp, err := c.Get(hts.URL + "/" + cfg.TenantID + "/wsfed?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, resp)
	assertWSFedRefusedOnEmulator(t, resp, page, testAttackerReply)
}

func TestEmptyRealmIsRefusedOnSignOut(t *testing.T) {
	t.Skip("pending: enable after walking skeleton (US-06)")
	for _, tc := range []struct {
		name    string
		wtrealm string
		omit    bool
	}{
		{name: "omitted", omit: true},
		{name: "empty", wtrealm: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hts, cfg, st := newTestServer(t)
			registerTasksAPIWithSignOutReturn(t, st, cfg.TenantID)
			q := url.Values{
				"wa":     {"wsignout1.0"},
				"wreply": {testAttackerReply},
			}
			if !tc.omit {
				q.Set("wtrealm", tc.wtrealm)
			}
			c := samlClient(t)
			resp, err := c.Get(hts.URL + "/" + cfg.TenantID + "/wsfed?" + q.Encode())
			if err != nil {
				t.Fatal(err)
			}
			page := readAll(t, resp)
			assertWSFedRefusedOnEmulator(t, resp, page, testAttackerReply)
		})
	}
}

func TestSAMLACSIsNotAcceptedAsSignOutReturn(t *testing.T) {
	t.Skip("pending: enable after walking skeleton (US-07)")
	assertWrongTypeSignOutReturnRefused(t, testSAMLACSOnlyReply, "saml-acs")
}

func TestWebCallbackIsNotAcceptedAsSignOutReturn(t *testing.T) {
	t.Skip("pending: enable after walking skeleton (US-07)")
	assertWrongTypeSignOutReturnRefused(t, testWebOnlyReply, "web")
}

func assertWrongTypeSignOutReturnRefused(t *testing.T, uri, typ string) {
	t.Helper()
	hts, cfg, st := newTestServer(t)
	app := &store.App{
		ID: testTasksAppID, TenantID: cfg.TenantID,
		DisplayName: "Tasks API", AppIDURI: testTasksAppIDURI,
	}
	if err := st.CreateApp(app); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddRedirectURI(app.ID, uri, typ); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddRedirectURI(app.ID, testTasksWSFedSignOutReply, "wsfed-reply"); err != nil {
		t.Fatal(err)
	}
	q := url.Values{
		"wa":      {"wsignout1.0"},
		"wtrealm": {testTasksAppIDURI},
		"wreply":  {uri},
	}
	c := samlClient(t)
	resp, err := c.Get(hts.URL + "/" + cfg.TenantID + "/wsfed?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, resp)
	assertWSFedRefusedOnEmulator(t, resp, page, uri)
}

func TestAnotherAppsReplyIsNotAcceptedOnSignOut(t *testing.T) {
	t.Skip("pending: enable after walking skeleton (US-07)")
	hts, cfg, st := newTestServer(t)
	registerTasksAPIWithSignOutReturn(t, st, cfg.TenantID)
	finance := &store.App{
		ID: testFinanceAppID, TenantID: cfg.TenantID,
		DisplayName: "Finance API", AppIDURI: testFinanceAppIDURI,
	}
	if err := st.CreateApp(finance); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddRedirectURI(finance.ID, testFinanceWSFedReply, "wsfed-reply"); err != nil {
		t.Fatal(err)
	}
	q := url.Values{
		"wa":      {"wsignout1.0"},
		"wtrealm": {testTasksAppIDURI},
		"wreply":  {testFinanceWSFedReply},
	}
	c := samlClient(t)
	resp, err := c.Get(hts.URL + "/" + cfg.TenantID + "/wsfed?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, resp)
	assertWSFedRefusedOnEmulator(t, resp, page, testFinanceWSFedReply)
}

func TestUnregisteredReturnDoesNotReceiveTheBrowserOnSignOut(t *testing.T) {
	t.Skip("pending: enable after walking skeleton (US-07)")
	hts, cfg, st := newTestServer(t)
	registerTasksAPIWithSignOutReturn(t, st, cfg.TenantID)
	q := url.Values{
		"wa":      {"wsignout1.0"},
		"wtrealm": {testTasksAppIDURI},
		"wreply":  {testUnregisteredReply},
	}
	c := samlClient(t)
	resp, err := c.Get(hts.URL + "/" + cfg.TenantID + "/wsfed?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, resp)
	assertWSFedRefusedOnEmulator(t, resp, page, testUnregisteredReply)
}

func TestMissingReturnUsesARegisteredWSFedReply(t *testing.T) {
	t.Skip("pending: enable after walking skeleton (US-07 omitted wreply)")
	hts, cfg, st := newTestServer(t)
	registerTasksAPIWithSignOutReturn(t, st, cfg.TenantID)
	c := samlClient(t)
	completeTasksAPIWSFedSignInOn(t, c, hts.URL, cfg.TenantID, testWSFedWctx, store.SeedUserAliceID)
	q := url.Values{
		"wa":      {"wsignout1.0"},
		"wtrealm": {testTasksAppIDURI},
	}
	resp, err := c.Get(hts.URL + "/" + cfg.TenantID + "/wsfed?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, resp)
	if strings.Contains(page, "wresult") || strings.Contains(page, "RequestSecurityTokenResponse") {
		t.Fatalf("omitted return minted a wresult:\n%s", page)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("omitted return returned %d, want 302 to a registered wsfed-reply:\n%s", resp.StatusCode, page)
	}
	loc := resp.Header.Get("Location")
	if loc != testTasksWSFedReply && loc != testTasksWSFedSignOutReply {
		t.Fatalf("omitted return Location %q is not a registered wsfed-reply", loc)
	}
	if loc == testSAMLACSOnlyReply || loc == testWebOnlyReply {
		t.Fatalf("omitted return picked a non-wsfed-reply %q", loc)
	}
}

func TestUnsolicitedWresultIsStillRefusedAfterSignOutCut(t *testing.T) {
	t.Skip("pending: enable after walking skeleton (US-08)")
	hts, cfg, st := newTestServer(t)
	registerTasksAPIWithSignOutReturn(t, st, cfg.TenantID)
	c := samlClient(t)
	resp, err := c.PostForm(hts.URL+"/"+cfg.TenantID+"/wsfed", url.Values{
		"wa":      {"wsignin1.0"},
		"wresult": {forgedWSFedWresult},
		"wtrealm": {testTasksAppIDURI},
		"wreply":  {testTasksWSFedReply},
		"wctx":    {testWSFedWctx},
	})
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, resp)
	assertWSFedRefusedOnEmulator(t, resp, page, testTasksWSFedReply)
}

func TestSOAPStaysAbsent(t *testing.T) {
	t.Skip("pending: enable after walking skeleton (US-08)")
	hts, cfg, _ := newTestServer(t)
	resp, err := http.Get(hts.URL + "/" + cfg.TenantID + "/trust/13/usernamemixed")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("SOAP / active WS-Trust path returned %d, want 404", resp.StatusCode)
	}
}

func TestUnsolicitedLoginIsStillNotOfferedAsASetting(t *testing.T) {
	t.Skip("pending: enable after walking skeleton (US-08)")
	_, cfg, _ := newTestServer(t)
	rt := reflect.TypeOf(*cfg)
	for i := 0; i < rt.NumField(); i++ {
		name := rt.Field(i).Name
		if strings.Contains(strings.ToLower(name), "unsolicited") {
			t.Fatalf("this cut offers unsolicited login as setting %s", name)
		}
	}
}

func TestSuccessfulSignOutIsRecordedWithoutATokenBody(t *testing.T) {
	t.Skip("pending: enable after walking skeleton (US-04)")
	hts, cfg, st := newTestServer(t)
	registerTasksAPIWithSignOutReturn(t, st, cfg.TenantID)
	c := samlClient(t)
	completeTasksAPIWSFedSignInOn(t, c, hts.URL, cfg.TenantID, testWSFedWctx, store.SeedUserAliceID)
	resp, err := c.Get(wsfedSignOutURL(hts.URL, cfg.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	_ = readAll(t, resp)

	var signOut map[string]any
	for _, e := range auditList(t, hts.URL) {
		if e["flow"] == "wsfed" && e["clientId"] == testTasksAppIDURI {
			signOut = e
		}
	}
	if signOut == nil {
		t.Fatal("admin audit has no wsfed event for the sign-out exchange")
	}
	if signOut["clientId"] != testTasksAppIDURI {
		t.Fatalf("sign-out ClientID = %v, want %s", signOut["clientId"], testTasksAppIDURI)
	}
	auditJSONMustOmitTokenBody(t, signOut)
}

func TestGraphSignInsStillTreatWSFedAsInteractiveAfterSignOut(t *testing.T) {
	t.Skip("pending: enable after walking skeleton (US-04)")
	hts, cfg, st := newTestServer(t)
	registerTasksAPIWithSignOutReturn(t, st, cfg.TenantID)
	c := samlClient(t)
	completeTasksAPIWSFedSignInOn(t, c, hts.URL, cfg.TenantID, testWSFedWctx, store.SeedUserAliceID)
	resp, err := c.Get(wsfedSignOutURL(hts.URL, cfg.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	_ = readAll(t, resp)

	app := appGraphToken(t, hts.URL)
	status, logs := graphGet(t, hts.URL, "/graph/v1.0/auditLogs/signIns", app)
	if status != http.StatusOK {
		t.Fatalf("signIns: %d %v", status, logs)
	}
	rows, _ := logs["value"].([]any)
	var row map[string]any
	for _, v := range rows {
		m, _ := v.(map[string]any)
		if m["appId"] == testTasksAppIDURI {
			row = m
			break
		}
	}
	if row == nil {
		t.Fatalf("Graph has no Tasks API WS-Fed row: %v", rows)
	}
	if row["isInteractive"] != true {
		t.Fatalf("WS-Fed exchange must be interactive: %v", row["isInteractive"])
	}
	auditJSONMustOmitTokenBody(t, row)
}

func TestRefusedSignOutIsRecordedWithAConcreteReason(t *testing.T) {
	t.Skip("pending: enable after walking skeleton (US-04 / US-06)")
	hts, cfg, st := newTestServer(t)
	registerTasksAPIWithSignOutReturn(t, st, cfg.TenantID)
	q := url.Values{
		"wa":      {"wsignout1.0"},
		"wtrealm": {"api://not-registered"},
		"wreply":  {testAttackerReply},
	}
	c := samlClient(t)
	resp, err := c.Get(hts.URL + "/" + cfg.TenantID + "/wsfed?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, resp)
	if strings.Contains(page, "wresult") || strings.Contains(page, "RequestSecurityTokenResponse") {
		t.Fatalf("unknown wtrealm issued a token:\n%s", page)
	}

	var failed map[string]any
	for _, e := range auditList(t, hts.URL) {
		if e["flow"] == "wsfed" && e["ok"] == false {
			failed = e
			break
		}
	}
	if failed == nil {
		t.Fatal("admin audit has no failed wsfed event")
	}
	reason, _ := failed["reason"].(string)
	if strings.TrimSpace(reason) == "" {
		t.Fatalf("refused sign-out must carry a concrete Reason: %v", failed)
	}
	auditJSONMustOmitTokenBody(t, failed)
}
