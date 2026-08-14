package server

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

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
	testTasksAppID        = "55556666-7777-8888-9999-000011112222"
	testTasksAppIDURI     = "api://tasks-api"
	testTasksWSFedReply   = "https://rp.example.test/signin-wsfed"
	testWSFedWctx         = "tasks-return-state-7"
	testAttackerReply     = "https://attacker.example.test/steal"
	testUnregisteredReply = "https://rp.example.test/not-a-callback"
	testSAMLACSOnlyReply  = "https://rp.example.test/acs"
	testWebOnlyReply      = "https://rp.example.test/signin-oidc"
	testFinanceAppID      = "aaaa1111-2222-3333-4444-555566667777"
	testFinanceAppIDURI   = "api://finance-api"
	testFinanceWSFedReply = "https://finance.example.test/signin-wsfed"
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

// Test Budget: 4 US-06 behaviors × 2 = 8. HTTP driving-port tests below: 2 ≤ 8.
// Gherkin: tests/acceptance/ws-fed/refuse-unsafe.feature
// Lookup is GetAppByIDURI; a miss must refuse on the emulator — never Location
// or wresult POST to the caller-supplied wreply.

func TestUnknownWtrealmDoesNotIssueAToken(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPI(t, st, cfg.TenantID)

	q := url.Values{
		"wa":      {"wsignin1.0"},
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

func TestEmptyRealmIsRefused(t *testing.T) {
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
			registerTasksAPI(t, st, cfg.TenantID)

			q := url.Values{
				"wa":     {"wsignin1.0"},
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

func assertWSFedRefusedOnEmulator(t *testing.T, resp *http.Response, page, unowned string) {
	t.Helper()
	if resp.StatusCode < 400 {
		t.Fatalf("unsafe challenge returned %d, want 4xx so the error stays on the emulator:\n%s", resp.StatusCode, page)
	}
	if loc := resp.Header.Get("Location"); loc != "" && (loc == unowned || strings.Contains(loc, "attacker.example.test")) {
		t.Fatalf("unknown realm sent Location to an unowned URL: %s", loc)
	}
	if m := actionRe.FindStringSubmatch(page); len(m) > 1 && m[1] == unowned {
		t.Fatalf("emulator POSTs wresult to caller wreply %q:\n%s", unowned, page)
	}
	if strings.Contains(page, "wresult") || strings.Contains(page, "RequestSecurityTokenResponse") {
		t.Fatalf("issued a token to the caller reply:\n%s", page)
	}
	if !strings.Contains(page, "LOCAL EMULATOR") {
		t.Fatalf("error did not stay on the emulator:\n%s", page)
	}
}

// Test Budget: 4 US-07 behaviors × 2 = 8. HTTP driving-port tests below: 5 ≤ 8.
// wreply must be an exact URI of type wsfed-reply for the wtrealm app.
// HasRedirectURI is type-blind — these tests fail if the STS uses it.

func TestUnregisteredWreplyDoesNotReceiveAToken(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPI(t, st, cfg.TenantID)

	q := url.Values{
		"wa":      {"wsignin1.0"},
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

func TestMissingWreplyDoesNotReceiveAToken(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPI(t, st, cfg.TenantID)

	q := url.Values{
		"wa":      {"wsignin1.0"},
		"wtrealm": {testTasksAppIDURI},
	}
	c := samlClient(t)
	resp, err := c.Get(hts.URL + "/" + cfg.TenantID + "/wsfed?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, resp)
	assertWSFedRefusedOnEmulator(t, resp, page, testTasksWSFedReply)
}

func TestSAMLACSOnlyReplyIsRefused(t *testing.T) {
	assertWrongTypeWreplyRefused(t, testSAMLACSOnlyReply, "saml-acs")
}

func TestWebOnlyReplyIsRefused(t *testing.T) {
	assertWrongTypeWreplyRefused(t, testWebOnlyReply, "web")
}

func assertWrongTypeWreplyRefused(t *testing.T, uri, typ string) {
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

	q := url.Values{
		"wa":      {"wsignin1.0"},
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

func TestAnotherAppsReplyIsNotAccepted(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPI(t, st, cfg.TenantID)
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
		"wa":      {"wsignin1.0"},
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

// Test Budget: 2 US-08 behaviors × 2 = 4. HTTP driving-port tests below: 2 ≤ 4.
// Kind wsfed signed state is the correlation (SAML InResponseTo analog).
// A token-shaped POST without that state must not mint a wresult or a session.

const forgedWSFedWresult = `<t:RequestSecurityTokenResponse xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"><t:RequestedSecurityToken>unsolicited</t:RequestedSecurityToken></t:RequestSecurityTokenResponse>`

func TestUnsolicitedWresultIsRefused(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPI(t, st, cfg.TenantID)

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

	origin, err := url.Parse(hts.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, ck := range c.Jar.Cookies(origin) {
		if ck.Name == "ee_session" && ck.Value != "" {
			t.Fatal("Tasks API gained a session from the unsolicited token via this STS")
		}
	}

	var failed map[string]any
	for _, e := range auditList(t, hts.URL) {
		if e["flow"] == "wsfed" && e["ok"] == false {
			failed = e
			break
		}
	}
	if failed == nil {
		t.Fatal("unsolicited wresult was not recorded as a failed wsfed event")
	}
	reason, _ := failed["reason"].(string)
	if strings.TrimSpace(reason) == "" {
		t.Fatalf("unsolicited refusal must carry a concrete Reason: %v", failed)
	}
}

func TestUnsolicitedLoginIsNotOfferedAsASetting(t *testing.T) {
	_, cfg, _ := newTestServer(t)
	rt := reflect.TypeOf(*cfg)
	for i := 0; i < rt.NumField(); i++ {
		name := rt.Field(i).Name
		if strings.Contains(strings.ToLower(name), "unsolicited") {
			t.Fatalf("v0.8.0 offers unsolicited login as setting %s", name)
		}
	}
}

// Test Budget: 6 distinct behaviors × 2 = 12. HTTP driving-port tests below: 3 ≤ 12.
// Gherkin: tests/acceptance/ws-fed/audit-observability.feature
// Journey persona Alex Rivera is the existing seeded user (Alice).

func TestWSFedChallengeAndSuccessAppearInAudit(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPI(t, st, cfg.TenantID)
	completeTasksAPIWSFedSignInAs(t, hts.URL, cfg.TenantID, testWSFedWctx, store.SeedUserAliceID)

	var challenge, success map[string]any
	for _, e := range auditList(t, hts.URL) {
		if e["flow"] != "wsfed" {
			continue
		}
		if e["ok"] == true && e["userId"] == nil {
			challenge = e
		}
		if e["ok"] == true && e["userId"] != nil {
			success = e
		}
	}
	if challenge == nil {
		t.Fatal("admin audit has no unauthenticated wsfed challenge")
	}
	if challenge["clientId"] != testTasksAppIDURI {
		t.Fatalf("challenge ClientID = %v, want %s", challenge["clientId"], testTasksAppIDURI)
	}
	if challenge["userPrincipalName"] != nil {
		t.Fatalf("challenge must have no user: %v", challenge)
	}

	if success == nil {
		t.Fatal("admin audit has no successful wsfed sign-in")
	}
	if success["clientId"] != testTasksAppIDURI {
		t.Fatalf("success ClientID = %v, want %s", success["clientId"], testTasksAppIDURI)
	}
	if success["userId"] != store.SeedUserAliceID {
		t.Fatalf("success userId = %v, want seeded user %s", success["userId"], store.SeedUserAliceID)
	}
	if success["userPrincipalName"] != "alice@entraemulator.dev" {
		t.Fatalf("success userPrincipalName = %v, want alice@entraemulator.dev", success["userPrincipalName"])
	}

	auditJSONMustOmitTokenBody(t, challenge)
	auditJSONMustOmitTokenBody(t, success)
}

func TestRefusedChallengeIsRecordedWithReason(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	q := url.Values{
		"wa":      {"wsignin1.0"},
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
		t.Fatalf("refused challenge must carry a concrete Reason: %v", failed)
	}
	auditJSONMustOmitTokenBody(t, failed)
}

func TestGraphSignInsIdentifyTasksAPIAsInteractive(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPI(t, st, cfg.TenantID)
	completeTasksAPIWSFedSignInAs(t, hts.URL, cfg.TenantID, testWSFedWctx, store.SeedUserAliceID)

	app := appGraphToken(t, hts.URL)
	status, logs := graphGet(t, hts.URL, "/graph/v1.0/auditLogs/signIns", app)
	if status != http.StatusOK {
		t.Fatalf("signIns: %d %v", status, logs)
	}
	rows, _ := logs["value"].([]any)
	var row map[string]any
	for _, v := range rows {
		m, _ := v.(map[string]any)
		if m["appId"] == testTasksAppIDURI && m["userId"] == store.SeedUserAliceID {
			row = m
			break
		}
	}
	if row == nil {
		t.Fatalf("Graph has no Tasks API WS-Fed sign-in row: %v", rows)
	}
	name, _ := row["appDisplayName"].(string)
	if name == "" {
		t.Fatalf("appDisplayName is blank when ClientID is Application ID URI %s: %v", testTasksAppIDURI, row)
	}
	if name != "Tasks API" {
		t.Fatalf("appDisplayName = %q, want Tasks API", name)
	}
	if row["isInteractive"] != true {
		t.Fatalf("WS-Fed exchange must be interactive: %v", row["isInteractive"])
	}
	auditJSONMustOmitTokenBody(t, row)
}

// Test Budget: 2 distinct behaviors × 2 = 4. HTTP driving-port tests below: 2 ≤ 4.
// Gherkin: tests/acceptance/ws-fed/guardrail-saml-oidc.feature
// In-process analog of e2e/saml and the existing OIDC authorize suite (driveAuthCode).

func TestExistingSAMLSignInStillCompletesAfterWSFedMetadataGrowth(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerSAMLApp(t, st, cfg.TenantID)

	entity := parseFederationMetadata(t, fetchMetadata(t, hts.URL, cfg.TenantID))
	if entity.FindElement("./RoleDescriptor") == nil {
		t.Fatal("FederationMetadata has no WS-Fed RoleDescriptor; guardrail is not on a grown document")
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

	body := signInOverSAML(t, &httptestServer{URL: hts.URL}, cfg.TenantID, "")
	if got := firstMatch(t, actionRe, body, "form action"); got != testSPACS {
		t.Fatalf("SAML form posts to %q, want the registered ACS %q", got, testSPACS)
	}
	raw, err := base64.StdEncoding.DecodeString(
		htmlUnescape(firstMatch(t, responseRe, body, "SAMLResponse")))
	if err != nil {
		t.Fatalf("SAMLResponse is not base64: %v", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		t.Fatalf("SAMLResponse is not XML: %v\n%s", err, raw)
	}
	assertion := doc.Root().FindElement("./saml:Assertion")
	if assertion == nil {
		t.Fatalf("no assertion in the SAML response:\n%s", raw)
	}
	cert := metadataCertificate(t, hts.URL, cfg.TenantID)
	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	})
	if _, err := ctx.Validate(assertion); err != nil {
		t.Fatalf("SAML assertion does not verify under the published certificate: %v", err)
	}
}

func TestExistingOIDCSignInStillCompletes(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	if parseFederationMetadata(t, fetchMetadata(t, hts.URL, cfg.TenantID)).FindElement("./RoleDescriptor") == nil {
		t.Fatal("WS-Fed is not advertised; OIDC guardrail is not on the same grown emulator")
	}

	body := driveAuthCode(t, hts, "verifier-supercalifragilistic-0123456789")
	if body["id_token"] == nil || body["access_token"] == nil {
		t.Fatalf("OIDC sign-in did not complete: %v", body)
	}
	idc := decodeJWTPayload(t, body["id_token"].(string))
	if idc["aud"] != spaID || idc["oid"] != aliceID || idc["ver"] != "2.0" {
		t.Fatalf("OIDC tokens are not the existing SPA sign-in: %v", idc)
	}
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

// Test Budget: 3 US-03 behaviors × 2 = 6. HTTP driving-port tests below: 3 ≤ 6.

func TestPasswordRequiredModeStaysTheExistingForm(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPI(t, st, cfg.TenantID)
	cfg.RequirePassword = true
	t.Cleanup(func() { cfg.RequirePassword = false })

	oidc := hts.URL + "/" + cfg.TenantID + "/oauth2/v2.0/authorize?" + url.Values{
		"client_id": {spaID}, "redirect_uri": {redirect},
		"response_type": {"code"}, "scope": {"openid"}, "state": {"s"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}.Encode()
	oidcResp, err := http.Get(oidc)
	if err != nil {
		t.Fatal(err)
	}
	oidcPage := readAll(t, oidcResp)
	if !strings.Contains(oidcPage, `name="__ee_username"`) || !strings.Contains(oidcPage, `name="__ee_password"`) {
		t.Fatalf("OIDC password-required analog is not the email and password form:\n%s", oidcPage)
	}

	c := samlClient(t)
	resp, err := c.Get(wsfedChallengeURL(hts.URL, cfg.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("password-required challenge returned %d:\n%s", resp.StatusCode, page)
	}
	if !strings.Contains(page, `name="__ee_username"`) || !strings.Contains(page, `name="__ee_password"`) {
		t.Fatalf("she does not see the same email and password form OIDC uses:\n%s", page)
	}
	if !strings.Contains(page, ">Email<") || !strings.Contains(page, ">Password<") {
		t.Fatalf("password form is missing Email/Password labels:\n%s", page)
	}
	if !strings.Contains(page, "LOCAL EMULATOR") || !strings.Contains(page, "<h1>Sign in</h1>") {
		t.Fatalf("password form is not the existing chrome:\n%s", page)
	}
	if strings.Contains(page, "Pick an account") {
		t.Fatal("password-required mode still showed Pick an account")
	}
	if !strings.Contains(page, "/"+cfg.TenantID+"/wsfed") {
		t.Fatalf("password form POST action is not /{tid}/wsfed:\n%s", page)
	}

	form := url.Values{
		"__ee_state":    {firstMatch(t, stateFieldRe, page, "signed state")},
		"__ee_username": {"alice@entraemulator.dev"},
		"__ee_password": {store.SeedPassword},
	}
	post, err := c.PostForm(hts.URL+"/"+cfg.TenantID+"/wsfed", form)
	if err != nil {
		t.Fatal(err)
	}
	out := readAll(t, post)
	if post.StatusCode != http.StatusOK {
		t.Fatalf("password sign-in returned %d:\n%s", post.StatusCode, out)
	}
	if !strings.Contains(out, `name="wresult"`) {
		t.Fatalf("correct credentials produced no wresult:\n%s", out)
	}
}

func TestChallengeParametersSurviveAccountChoice(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPI(t, st, cfg.TenantID)

	c := samlClient(t)
	resp, err := c.Get(wsfedChallengeURL(hts.URL, cfg.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge returned %d:\n%s", resp.StatusCode, page)
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
		t.Fatalf("wreply did not survive account choice: got %q, want %q", action, testTasksWSFedReply)
	}
	if !strings.Contains(out, `name="wctx"`) || !strings.Contains(out, testWSFedWctx) {
		t.Fatalf("completing POST missing wctx %q:\n%s", testWSFedWctx, out)
	}
	if !strings.Contains(out, testTasksAppIDURI) {
		t.Fatalf("wtrealm %q did not survive account choice:\n%s", testTasksAppIDURI, out)
	}
}

func TestDisabledUserIsNotListedAsSelectable(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPI(t, st, cfg.TenantID)

	jordan := &store.User{
		ID: store.NewGUID(), TenantID: cfg.TenantID,
		UserPrincipalName: "jordan.blake@workforce.example.test",
		DisplayName:       "Jordan Blake",
		GivenName:         "Jordan", Surname: "Blake",
		Mail:           "jordan.blake@workforce.example.test",
		AccountEnabled: false, CreatedAt: st.Now(),
	}
	if err := st.CreateUser(jordan); err != nil {
		t.Fatal(err)
	}

	c := samlClient(t)
	resp, err := c.Get(wsfedChallengeURL(hts.URL, cfg.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge returned %d:\n%s", resp.StatusCode, page)
	}
	if !strings.Contains(page, "Pick an account") {
		t.Fatalf("challenge is not Pick an account:\n%s", page)
	}
	if strings.Contains(page, "Jordan Blake") || strings.Contains(page, jordan.UserPrincipalName) {
		t.Fatalf("disabled user is listed as selectable:\n%s", page)
	}
	if !strings.Contains(page, "Alice Example") {
		t.Fatalf("enabled accounts missing from picker:\n%s", page)
	}
}

// Test Budget: 6 remaining US-04 behaviors × 2 = 12.
// HTTP driving-port tests below: 6. XML builder unit tests live in
// internal/identity/wsfedresponse_test.go. Total ≤ 12.

const (
	samlV2TokenTypeURI = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0"
	persistentNameID   = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	nsSAML20Assertion  = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsSAML11Assertion  = "urn:oasis:names:tc:SAML:1.1:assertion"
	nsSAML10Assertion  = "urn:oasis:names:tc:SAML:1.0:assertion"
)

var (
	wresultFieldRe = regexp.MustCompile(`name="wresult" value="([^"]*)"`)
	wctxFieldRe    = regexp.MustCompile(`name="wctx" value="([^"]*)"`)
)

func completeTasksAPIWSFedSignIn(t *testing.T, base, tenant, wctx string) string {
	t.Helper()
	return completeTasksAPIWSFedSignInAs(t, base, tenant, wctx, "")
}

func completeTasksAPIWSFedSignInAs(t *testing.T, base, tenant, wctx, userID string) string {
	t.Helper()
	q := url.Values{
		"wa":      {"wsignin1.0"},
		"wtrealm": {testTasksAppIDURI},
		"wreply":  {testTasksWSFedReply},
	}
	if wctx != "" {
		q.Set("wctx", wctx)
	}
	c := samlClient(t)
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
	return out
}

func auditJSONMustOmitTokenBody(t *testing.T, row map[string]any) {
	t.Helper()
	raw, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, needle := range []string{"wresult", "RequestSecurityTokenResponse"} {
		if strings.Contains(s, needle) {
			t.Fatalf("audit row includes %s:\n%s", needle, s)
		}
	}
}

func postedWresult(t *testing.T, page string) *etree.Element {
	t.Helper()
	raw := htmlUnescape(firstMatch(t, wresultFieldRe, page, "wresult"))
	doc := etree.NewDocument()
	if err := doc.ReadFromString(raw); err != nil {
		t.Fatalf("wresult is not XML: %v\n%s", err, raw)
	}
	if doc.Root() == nil {
		t.Fatal("wresult has no RequestSecurityTokenResponse")
	}
	return doc.Root()
}

func rstrAssertion(t *testing.T, rstr *etree.Element) *etree.Element {
	t.Helper()
	a := rstr.FindElement(".//saml:Assertion")
	if a == nil {
		t.Fatal("RequestedSecurityToken has no SAML assertion")
	}
	return a
}

func elementXML(t *testing.T, el *etree.Element) string {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())
	s, err := doc.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func federationEntityID(t *testing.T, body []byte) string {
	t.Helper()
	id := strings.TrimSpace(parseFederationMetadata(t, body).SelectAttrValue("entityID", ""))
	if id == "" {
		t.Fatal("FederationMetadata has no entityID")
	}
	return id
}

func TestTokenAudienceMatchesApplicationIDURI(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPI(t, st, cfg.TenantID)

	out := completeTasksAPIWSFedSignIn(t, hts.URL, cfg.TenantID, testWSFedWctx)
	assertion := rstrAssertion(t, postedWresult(t, out))
	aud := assertion.FindElement(".//saml:Audience")
	if aud == nil || strings.TrimSpace(aud.Text()) != testTasksAppIDURI {
		t.Fatalf("assertion Audience is not %s:\n%s", testTasksAppIDURI, elementXML(t, assertion))
	}
}

func TestIssuerMatchesFederationMetadata(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPI(t, st, cfg.TenantID)

	entityID := federationEntityID(t, fetchMetadata(t, hts.URL, cfg.TenantID))
	out := completeTasksAPIWSFedSignIn(t, hts.URL, cfg.TenantID, testWSFedWctx)
	assertion := rstrAssertion(t, postedWresult(t, out))
	issuer := assertion.FindElement("./saml:Issuer")
	if issuer == nil || strings.TrimSpace(issuer.Text()) != entityID {
		got := ""
		if issuer != nil {
			got = strings.TrimSpace(issuer.Text())
		}
		t.Fatalf("assertion Issuer %q does not equal FederationMetadata entityID %q:\n%s",
			got, entityID, elementXML(t, assertion))
	}

	cert := metadataCertificate(t, hts.URL, cfg.TenantID)
	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	})
	if _, err := ctx.Validate(assertion); err != nil {
		t.Fatalf("assertion does not verify under the FederationMetadata certificate: %v", err)
	}
}

func TestContextIsEchoedUnchanged(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPI(t, st, cfg.TenantID)

	out := completeTasksAPIWSFedSignIn(t, hts.URL, cfg.TenantID, testWSFedWctx)
	got := htmlUnescape(firstMatch(t, wctxFieldRe, out, "wctx"))
	if got != testWSFedWctx {
		t.Fatalf("wctx came back %q, want %q", got, testWSFedWctx)
	}
}

func TestOmittedContextStaysOmitted(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPI(t, st, cfg.TenantID)

	out := completeTasksAPIWSFedSignIn(t, hts.URL, cfg.TenantID, "")
	if !strings.Contains(out, `name="wresult"`) {
		t.Fatalf("token POST missing wresult:\n%s", out)
	}
	if wctxFieldRe.FindStringSubmatch(out) != nil {
		t.Fatalf("token POST invented a wctx the RP never sent:\n%s", out)
	}
}

func TestAssertionVersionIsSAML20ForThisWitness(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPI(t, st, cfg.TenantID)

	out := completeTasksAPIWSFedSignIn(t, hts.URL, cfg.TenantID, testWSFedWctx)
	rstr := postedWresult(t, out)
	tokenType := rstr.FindElement("./t:TokenType")
	if tokenType == nil {
		tokenType = rstr.FindElement(".//t:TokenType")
	}
	if tokenType == nil || !strings.HasSuffix(strings.TrimSpace(tokenType.Text()), "#SAMLV2.0") {
		got := ""
		if tokenType != nil {
			got = strings.TrimSpace(tokenType.Text())
		}
		t.Fatalf("TokenType %q is not SAML 2.0 ending in #SAMLV2.0:\n%s", got, elementXML(t, rstr))
	}
	if strings.TrimSpace(tokenType.Text()) != samlV2TokenTypeURI {
		t.Fatalf("TokenType %q, want %s", strings.TrimSpace(tokenType.Text()), samlV2TokenTypeURI)
	}

	assertion := rstrAssertion(t, rstr)
	if assertion.SelectAttrValue("Version", "") != "2.0" {
		t.Fatalf("inner assertion Version is %q, want 2.0:\n%s",
			assertion.SelectAttrValue("Version", ""), elementXML(t, assertion))
	}
	raw := elementXML(t, assertion)
	if strings.Contains(raw, nsSAML11Assertion) || strings.Contains(raw, nsSAML10Assertion) {
		t.Fatalf("assertion is SAML 1.1:\n%s", raw)
	}
	ns := assertion.SelectAttrValue("xmlns:saml", "")
	if ns != nsSAML20Assertion {
		t.Fatalf("assertion namespace %q, want SAML 2.0 %s:\n%s", ns, nsSAML20Assertion, raw)
	}
}

func TestNameIDFormatIsPersistent(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPI(t, st, cfg.TenantID)

	out := completeTasksAPIWSFedSignIn(t, hts.URL, cfg.TenantID, testWSFedWctx)
	nameID := rstrAssertion(t, postedWresult(t, out)).FindElement(".//saml:NameID")
	if nameID == nil {
		t.Fatal("assertion has no NameID")
	}
	if got := nameID.SelectAttrValue("Format", ""); got != persistentNameID {
		t.Fatalf("NameID format %q, want persistent %s", got, persistentNameID)
	}
}
