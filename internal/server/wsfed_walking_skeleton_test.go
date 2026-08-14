package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/beevik/etree"

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

// Test Budget: 5 remaining US-01 behaviors × 2 = 10.
// HTTP driving-port tests below: 5. XML builder unit tests: 2. Total 7 ≤ 10.

func TestSigningCertificatesInBothSectionsMatch(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	body := fetchMetadata(t, hts.URL, cfg.TenantID)
	entity := parseFederationMetadata(t, body)
	idp := entity.FindElement("./IDPSSODescriptor")
	rd := entity.FindElement("./RoleDescriptor")
	if idp == nil || rd == nil {
		t.Fatal("FederationMetadata must include IDPSSODescriptor and a WS-Fed RoleDescriptor")
	}
	samlCert := signingCertText(idp)
	wsfedCert := signingCertText(rd)
	if samlCert == "" || wsfedCert == "" {
		t.Fatal("both sections must publish a signing certificate")
	}
	if samlCert != wsfedCert {
		t.Fatal("the WS-Fed certificate is not the same as the SAML certificate")
	}
}

func TestSignOutIsAdvertisedWithoutASignOutWitness(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	c := &http.Client{Transport: signOutForbiddenTrip{t: t}}
	metaURL := hts.URL + "/" + cfg.TenantID + "/federationmetadata/2007-06/federationmetadata.xml"
	resp, err := c.Get(metaURL)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(readAll(t, resp))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET FederationMetadata returned %d:\n%s", resp.StatusCode, body)
	}

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

func TestSAMLAppsStillSeeTheirDescriptor(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	body := fetchMetadata(t, hts.URL, cfg.TenantID)
	entity := parseFederationMetadata(t, body)
	if entity.FindElement("./RoleDescriptor") == nil {
		t.Fatal("WS-Fed RoleDescriptor is missing; SAML guardrail is not on a grown document")
	}
	idp := entity.FindElement("./IDPSSODescriptor")
	if idp == nil {
		t.Fatal("growing WS-Fed RoleDescriptor removed IDPSSODescriptor")
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

func TestMetadataFetchStaysSamlMetadataAuditFlow(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	_ = fetchMetadata(t, hts.URL, cfg.TenantID)

	var sawSAMLMeta bool
	for _, e := range auditList(t, hts.URL) {
		flow, _ := e["flow"].(string)
		if flow == "wsfed-metadata" {
			t.Fatalf("metadata fetch was renamed away from saml-metadata: %v", e)
		}
		if flow == "saml-metadata" {
			sawSAMLMeta = true
		}
	}
	if !sawSAMLMeta {
		t.Fatal("FederationMetadata GET was not recorded as saml-metadata")
	}
}

func TestPriyaIsNotSentToASecondMetadataURL(t *testing.T) {
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

func parseFederationMetadata(t *testing.T, body []byte) *etree.Element {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(body); err != nil {
		t.Fatalf("FederationMetadata is not well-formed XML: %v", err)
	}
	if doc.Root() == nil {
		t.Fatal("FederationMetadata has no EntityDescriptor")
	}
	return doc.Root()
}

func signingCertText(section *etree.Element) string {
	el := section.FindElement(".//X509Certificate")
	if el == nil {
		return ""
	}
	return strings.Join(strings.Fields(el.Text()), "")
}

func fedEndpointAddress(rd *etree.Element, local string) string {
	ep := rd.FindElement("./fed:" + local)
	if ep == nil {
		return ""
	}
	addr := ep.FindElement(".//Address")
	if addr == nil {
		return ""
	}
	return strings.TrimSpace(addr.Text())
}

// signOutForbiddenTrip fails the test if anyone drives wa=wsignout1.0.
// Sign-out is advertised on PassiveRequestorEndpoint; this cut does not witness SLO.
type signOutForbiddenTrip struct{ t *testing.T }

func (s signOutForbiddenTrip) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Query().Get("wa") == "wsignout1.0" {
		s.t.Fatal("this story does not require a wsignout1.0 round-trip")
	}
	return http.DefaultTransport.RoundTrip(req)
}

func TestPOSTAsWellAsGETCanStartSignIn(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPI(t, st, cfg.TenantID)

	c := samlClient(t)
	resp, err := c.PostForm(hts.URL+"/"+cfg.TenantID+"/wsfed", url.Values{
		"wa":      {"wsignin1.0"},
		"wtrealm": {testTasksAppIDURI},
		"wreply":  {testTasksWSFedReply},
	})
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, resp)
	if resp.StatusCode == http.StatusNotFound {
		t.Fatalf("POST /{tid}/wsfed wa=wsignin1.0 returned 404; the challenge must be login HTML")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /{tid}/wsfed returned %d, want 200 login HTML:\n%s", resp.StatusCode, page)
	}
	if strings.Contains(page, "wresult") || strings.Contains(page, "RequestSecurityTokenResponse") {
		t.Fatal("unauthenticated POST challenge posted a wresult; want login HTML")
	}
	if !strings.Contains(page, "LOCAL EMULATOR") || !strings.Contains(page, "Pick an account") {
		t.Fatalf("POST challenge is not sign-in:\n%s", page)
	}
}

func TestOmittedContextIsAcceptedOnTheChallenge(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPI(t, st, cfg.TenantID)

	q := url.Values{
		"wa":      {"wsignin1.0"},
		"wtrealm": {testTasksAppIDURI},
		"wreply":  {testTasksWSFedReply},
	}
	c := samlClient(t)
	resp, err := c.Get(hts.URL + "/" + cfg.TenantID + "/wsfed?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge without wctx returned %d:\n%s", resp.StatusCode, page)
	}
	if !strings.Contains(page, "LOCAL EMULATOR") || !strings.Contains(page, "Pick an account") {
		t.Fatalf("challenge without wctx is not sign-in:\n%s", page)
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
	if !strings.Contains(out, `name="wresult"`) {
		t.Fatalf("later token POST missing wresult:\n%s", out)
	}
	if strings.Contains(out, `name="wctx"`) {
		t.Fatalf("token POST invented a wctx the RP never sent:\n%s", out)
	}
}

func TestPasswordRequiredModeStaysTheExistingForm(t *testing.T) {
	t.Skip("pending: US-03 password-required chrome")
}
