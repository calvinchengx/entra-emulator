package server

import (
	"bytes"
	"compress/flate"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// End to end: an AuthnRequest goes in, a human signs in, and the assertion
// that comes back is verified the way a service provider verifies it.

const (
	testSPEntityID = "https://sp.test/metadata"
	testSPACS      = "https://sp.test/acs"
)

func registerSAMLApp(t *testing.T, st *store.Store, tenantID string) *store.App {
	t.Helper()
	app := &store.App{
		ID: "22223333-4444-5555-6666-777788889999", TenantID: tenantID,
		DisplayName: "SAML Test SP", AppIDURI: testSPEntityID,
	}
	if err := st.CreateApp(app); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddRedirectURI(app.ID, testSPACS, "saml-acs"); err != nil {
		t.Fatal(err)
	}
	return app
}

func authnRequestFor(t *testing.T, acs string) string {
	t.Helper()
	req := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
		`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req0001" Version="2.0" ` +
		`AssertionConsumerServiceURL="` + acs + `">` +
		`<saml:Issuer>` + testSPEntityID + `</saml:Issuer></samlp:AuthnRequest>`
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	_, _ = w.Write([]byte(req))
	_ = w.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// A client that keeps cookies and never follows the auto-posting form, so the
// test sees the response the SP would receive.
func samlClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

var (
	stateFieldRe = regexp.MustCompile(`name="__ee_state" value="([^"]+)"`)
	userFieldRe  = regexp.MustCompile(`name="__ee_user" value="([^"]+)"`)
	responseRe   = regexp.MustCompile(`name="SAMLResponse" value="([^"]+)"`)
	actionRe     = regexp.MustCompile(`<form method="POST" action="([^"]+)"`)
	relayRe      = regexp.MustCompile(`name="RelayState" value="([^"]+)"`)
)

func firstMatch(t *testing.T, re *regexp.Regexp, body, what string) string {
	t.Helper()
	m := re.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no %s in:\n%s", what, body)
	}
	return m[1]
}

// signInOverSAML drives the whole flow and returns the SP-facing form.
func signInOverSAML(t *testing.T, hts *httptestServer, tenant, relay string) string {
	t.Helper()
	c := samlClient(t)
	u := hts.URL + "/" + tenant + "/saml2?SAMLRequest=" +
		url.QueryEscape(authnRequestFor(t, testSPACS))
	if relay != "" {
		u += "&RelayState=" + url.QueryEscape(relay)
	}
	resp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("SSO GET returned %d: %s", resp.StatusCode, body)
	}

	form := url.Values{
		"__ee_state": {firstMatch(t, stateFieldRe, body, "signed state")},
		"__ee_user":  {firstMatch(t, userFieldRe, body, "an account to pick")},
	}
	post, err := c.PostForm(hts.URL+"/"+tenant+"/saml2", form)
	if err != nil {
		t.Fatal(err)
	}
	out := readAll(t, post)
	if post.StatusCode != http.StatusOK {
		t.Fatalf("sign-in returned %d: %s", post.StatusCode, out)
	}
	if cc := post.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control %q: an assertion is a bearer credential", cc)
	}
	return out
}

func readAll(t *testing.T, r *http.Response) string {
	t.Helper()
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

type httptestServer = struct {
	URL string
	*http.Client
}

func TestSAMLSSODeliversAnAssertionAnSPCanVerify(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerSAMLApp(t, st, cfg.TenantID)
	srv := &httptestServer{URL: hts.URL}

	body := signInOverSAML(t, srv, cfg.TenantID, "")

	if got := firstMatch(t, actionRe, body, "form action"); got != testSPACS {
		t.Fatalf("form posts to %q, want the registered ACS %q", got, testSPACS)
	}
	raw, err := base64.StdEncoding.DecodeString(
		htmlUnescape(firstMatch(t, responseRe, body, "SAMLResponse")))
	if err != nil {
		t.Fatalf("SAMLResponse is not base64: %v", err)
	}

	// Parse as an SP does, then verify the assertion against the certificate
	// the IdP publishes in its metadata. Nothing here trusts our own code:
	// the certificate comes off the wire and the verifier is the SP's.
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		t.Fatalf("SAMLResponse is not XML: %v\n%s", err, raw)
	}
	assertion := doc.Root().FindElement("./saml:Assertion")
	if assertion == nil {
		t.Fatalf("no assertion in the response:\n%s", raw)
	}
	cert := metadataCertificate(t, hts.URL, cfg.TenantID)
	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	})
	if _, err := ctx.Validate(assertion); err != nil {
		t.Fatalf("assertion does not verify under the published certificate: %v", err)
	}

	s := string(raw)
	for _, want := range []string{
		`InResponseTo="_req0001"`,
		`<saml:Audience>` + testSPEntityID + `</saml:Audience>`,
		`Recipient="` + testSPACS + `"`,
		"urn:oasis:names:tc:SAML:2.0:status:Success",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("response is missing %s\n%s", want, s)
		}
	}
}

func metadataCertificate(t *testing.T, base, tenant string) *x509.Certificate {
	t.Helper()
	body := fetchMetadata(t, base, tenant)
	var doc struct {
		IDPSSO struct {
			KeyDescriptor struct {
				KeyInfo struct {
					X509Data struct {
						Cert string `xml:"X509Certificate"`
					} `xml:"X509Data"`
				} `xml:"KeyInfo"`
			} `xml:"KeyDescriptor"`
		} `xml:"IDPSSODescriptor"`
	}
	if err := xml.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	der, err := base64.StdEncoding.DecodeString(
		strings.Join(strings.Fields(doc.IDPSSO.KeyDescriptor.KeyInfo.X509Data.Cert), ""))
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// RelayState is the SP's opaque round-trip value, usually the page the user
// was heading to. Dropping it lands every login on the SP's home page and the
// cause is invisible from the SP side.
func TestSAMLSSOReturnsRelayStateUntouched(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerSAMLApp(t, st, cfg.TenantID)
	const relay = "/deep/link?with=query&and=more"

	body := signInOverSAML(t, &httptestServer{URL: hts.URL}, cfg.TenantID, relay)
	got := firstMatch(t, relayRe, body, "RelayState")
	// The form is HTML-escaped on the wire; compare after unescaping.
	if unescaped := htmlUnescape(got); unescaped != relay {
		t.Fatalf("RelayState came back %q, want %q", unescaped, relay)
	}
}

// The form field is HTML-escaped on the wire, so base64 "+" arrives as
// "&#43;". A browser unescapes before submitting; a test reading raw HTML has
// to do the same, or it decodes the markup rather than the value.
func htmlUnescape(s string) string { return html.UnescapeString(s) }

// An IdP that posts a signed assertion wherever it is told is an open
// redirector that mints credentials.
func TestSAMLSSORefusesAnUnregisteredACS(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerSAMLApp(t, st, cfg.TenantID)

	c := samlClient(t)
	resp, err := c.Get(hts.URL + "/" + cfg.TenantID + "/saml2?SAMLRequest=" +
		url.QueryEscape(authnRequestFor(t, "https://attacker.example/collect")))
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unregistered ACS returned %d, want 400:\n%s", resp.StatusCode, body)
	}
	if strings.Contains(body, "SAMLResponse") {
		t.Fatal("an assertion was issued for an unregistered reply URL")
	}
}

func TestSAMLSSORefusesAnUnknownServiceProvider(t *testing.T) {
	hts, cfg, _ := newTestServer(t) // no app registered at all
	c := samlClient(t)
	resp, err := c.Get(hts.URL + "/" + cfg.TenantID + "/saml2?SAMLRequest=" +
		url.QueryEscape(authnRequestFor(t, testSPACS)))
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unknown SP returned %d, want 400:\n%s", resp.StatusCode, body)
	}
}

func TestSAMLSSORejectsAGarbledRequest(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerSAMLApp(t, st, cfg.TenantID)
	c := samlClient(t)
	resp, err := c.Get(hts.URL + "/" + cfg.TenantID + "/saml2?SAMLRequest=not-base64%21%21")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("garbled SAMLRequest returned %d, want 400", resp.StatusCode)
	}
}

func TestSAMLSSORejectsAnUnknownTenant(t *testing.T) {
	hts, _, _ := newTestServer(t)
	c := samlClient(t)
	resp, err := c.Get(hts.URL + "/99999999-8888-7777-6666-555555555555/saml2?SAMLRequest=x")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown tenant returned %d, want 404", resp.StatusCode)
	}
}

// The POST binding is the other half of the contract, and it does not deflate.
func TestSAMLSSOAcceptsThePOSTBinding(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerSAMLApp(t, st, cfg.TenantID)
	req := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
		`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_post0001" Version="2.0" ` +
		`AssertionConsumerServiceURL="` + testSPACS + `">` +
		`<saml:Issuer>` + testSPEntityID + `</saml:Issuer></samlp:AuthnRequest>`

	c := samlClient(t)
	resp, err := c.PostForm(hts.URL+"/"+cfg.TenantID+"/saml2", url.Values{
		"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(req))},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST binding returned %d:\n%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, `name="__ee_state"`) {
		t.Fatalf("POST binding did not reach the sign-in page:\n%s", body)
	}
}

// A second application must not be able to sign in as the first by naming its
// entity ID and its own reply URL.
func TestSAMLSSOKeepsApplicationsApart(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerSAMLApp(t, st, cfg.TenantID)
	other := &store.App{
		ID: "33334444-5555-6666-7777-888899990000", TenantID: cfg.TenantID,
		DisplayName: "Other SP", AppIDURI: "https://other.test/metadata",
	}
	if err := st.CreateApp(other); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddRedirectURI(other.ID, "https://other.test/acs", "saml-acs"); err != nil {
		t.Fatal(err)
	}

	// The first SP's entity ID, the second SP's ACS.
	req := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
		`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_mix0001" Version="2.0" ` +
		`AssertionConsumerServiceURL="https://other.test/acs">` +
		`<saml:Issuer>` + testSPEntityID + `</saml:Issuer></samlp:AuthnRequest>`
	c := samlClient(t)
	resp, err := c.PostForm(hts.URL+"/"+cfg.TenantID+"/saml2", url.Values{
		"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(req))},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("cross-application ACS returned %d, want 400:\n%s", resp.StatusCode, body)
	}
}

// SSO means the second application does not ask again. Without this the
// feature is just "sign in", and the branch that reuses a session is exactly
// the one an SP notices when it breaks.
func TestSAMLSSOReusesAnExistingSession(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerSAMLApp(t, st, cfg.TenantID)
	c := samlClient(t)

	// First login: through the picker.
	resp, err := c.Get(hts.URL + "/" + cfg.TenantID + "/saml2?SAMLRequest=" +
		url.QueryEscape(authnRequestFor(t, testSPACS)))
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	post, err := c.PostForm(hts.URL+"/"+cfg.TenantID+"/saml2", url.Values{
		"__ee_state": {firstMatch(t, stateFieldRe, body, "state")},
		"__ee_user":  {firstMatch(t, userFieldRe, body, "user")},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = readAll(t, post)

	// Second request on the same cookie jar must skip straight to an assertion.
	again, err := c.Get(hts.URL + "/" + cfg.TenantID + "/saml2?SAMLRequest=" +
		url.QueryEscape(authnRequestFor(t, testSPACS)))
	if err != nil {
		t.Fatal(err)
	}
	out := readAll(t, again)
	if strings.Contains(out, `name="__ee_state"`) {
		t.Fatalf("a signed-in user was asked to sign in again:\n%s", out)
	}
	if !strings.Contains(out, "SAMLResponse") {
		t.Fatalf("no assertion for an existing session:\n%s", out)
	}
}

// An SP may omit AssertionConsumerServiceURL and expect its registered
// endpoint to be used. Refusing would break every such SP.
func TestSAMLSSOFallsBackToTheRegisteredACS(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerSAMLApp(t, st, cfg.TenantID)

	req := `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
		`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_noacs01" Version="2.0">` +
		`<saml:Issuer>` + testSPEntityID + `</saml:Issuer></samlp:AuthnRequest>`
	c := samlClient(t)
	resp, err := c.PostForm(hts.URL+"/"+cfg.TenantID+"/saml2", url.Values{
		"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(req))},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("omitted ACS returned %d:\n%s", resp.StatusCode, body)
	}
	post, err := c.PostForm(hts.URL+"/"+cfg.TenantID+"/saml2", url.Values{
		"__ee_state": {firstMatch(t, stateFieldRe, body, "state")},
		"__ee_user":  {firstMatch(t, userFieldRe, body, "user")},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := readAll(t, post)
	if got := firstMatch(t, actionRe, out, "form action"); got != testSPACS {
		t.Fatalf("fell back to %q, want the registered %q", got, testSPACS)
	}
}

func TestSAMLSSORefusesAnAppWithNoReplyURL(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	app := &store.App{
		ID: "44445555-6666-7777-8888-999900001111", TenantID: cfg.TenantID,
		DisplayName: "No Reply URL", AppIDURI: testSPEntityID,
	}
	if err := st.CreateApp(app); err != nil { // registered, but no saml-acs
		t.Fatal(err)
	}
	c := samlClient(t)
	resp, err := c.Get(hts.URL + "/" + cfg.TenantID + "/saml2?SAMLRequest=" +
		url.QueryEscape(authnRequestFor(t, testSPACS)))
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("app with no reply URL returned %d, want 400:\n%s", resp.StatusCode, body)
	}
}

// A forged or expired state must not reach the assertion builder.
func TestSAMLSSORejectsATamperedState(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerSAMLApp(t, st, cfg.TenantID)
	c := samlClient(t)
	resp, err := c.PostForm(hts.URL+"/"+cfg.TenantID+"/saml2", url.Values{
		"__ee_state": {"not-a-signed-state"},
		"__ee_user":  {"df8ec5dd-1599-45ef-908b-4ae020cd1dbe"},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("forged state returned %d, want 400", resp.StatusCode)
	}
	if strings.Contains(body, "SAMLResponse") {
		t.Fatal("an assertion was issued against a forged state")
	}
}

func TestSAMLSSORejectsAnUnknownAccount(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerSAMLApp(t, st, cfg.TenantID)
	c := samlClient(t)
	resp, err := c.Get(hts.URL + "/" + cfg.TenantID + "/saml2?SAMLRequest=" +
		url.QueryEscape(authnRequestFor(t, testSPACS)))
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	post, err := c.PostForm(hts.URL+"/"+cfg.TenantID+"/saml2", url.Values{
		"__ee_state": {firstMatch(t, stateFieldRe, body, "state")},
		"__ee_user":  {"00000000-0000-0000-0000-000000000000"},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := readAll(t, post)
	if strings.Contains(out, "SAMLResponse") {
		t.Fatal("an assertion was issued for an account that does not exist")
	}
	if !strings.Contains(out, "Incorrect") {
		t.Fatalf("no sign-in error shown:\n%.400s", out)
	}
}

// REQUIRE_PASSWORD swaps the picker for a credential form. The emulator ships
// both, so both need proving.
func TestSAMLSSOPasswordMode(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerSAMLApp(t, st, cfg.TenantID)
	cfg.RequirePassword = true
	t.Cleanup(func() { cfg.RequirePassword = false })

	c := samlClient(t)
	resp, err := c.Get(hts.URL + "/" + cfg.TenantID + "/saml2?SAMLRequest=" +
		url.QueryEscape(authnRequestFor(t, testSPACS)))
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	if !strings.Contains(body, `name="__ee_password"`) {
		t.Fatalf("password mode did not render a credential form:\n%.400s", body)
	}
	signed := firstMatch(t, stateFieldRe, body, "state")

	// Wrong password re-renders with an error and issues nothing.
	bad, err := c.PostForm(hts.URL+"/"+cfg.TenantID+"/saml2", url.Values{
		"__ee_state": {signed}, "__ee_username": {"alice@entraemulator.dev"},
		"__ee_password": {"wrong"},
	})
	if err != nil {
		t.Fatal(err)
	}
	badBody := readAll(t, bad)
	if strings.Contains(badBody, "SAMLResponse") {
		t.Fatal("a wrong password produced an assertion")
	}

	good, err := c.PostForm(hts.URL+"/"+cfg.TenantID+"/saml2", url.Values{
		"__ee_state":    {firstMatch(t, stateFieldRe, badBody, "state")},
		"__ee_username": {"alice@entraemulator.dev"},
		"__ee_password": {store.SeedPassword},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := readAll(t, good)
	if !strings.Contains(out, "SAMLResponse") {
		t.Fatalf("correct credentials produced no assertion:\n%.400s", out)
	}
}

// A disabled account must not be able to complete SSO. The picker only lists
// enabled users, so this posts the id directly, which is what an attacker with
// a stale page would do.
func TestSAMLSSORefusesADisabledAccount(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerSAMLApp(t, st, cfg.TenantID)
	c := samlClient(t)

	resp, err := c.Get(hts.URL + "/" + cfg.TenantID + "/saml2?SAMLRequest=" +
		url.QueryEscape(authnRequestFor(t, testSPACS)))
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	signed := firstMatch(t, stateFieldRe, body, "state")

	user, err := st.GetUser(store.SeedUserAliceID)
	if err != nil {
		t.Fatal(err)
	}
	user.AccountEnabled = false
	if err := st.UpdateUser(user); err != nil {
		t.Fatal(err)
	}

	post, err := c.PostForm(hts.URL+"/"+cfg.TenantID+"/saml2", url.Values{
		"__ee_state": {signed}, "__ee_user": {store.SeedUserAliceID},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := readAll(t, post)
	if strings.Contains(out, "SAMLResponse") {
		t.Fatal("a disabled account was issued a signed assertion")
	}
}
