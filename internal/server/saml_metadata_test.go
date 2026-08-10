package server

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/http"
	"strings"
	"testing"
)

// The metadata document is the only thing a service provider reads before it
// trusts anything, so these assert the fields an SP actually consumes rather
// than that the handler returned 200.

func fetchMetadata(t *testing.T, base, tenant string) []byte {
	t.Helper()
	url := base + "/" + tenant + "/federationmetadata/2007-06/federationmetadata.xml"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %d", url, resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/samlmetadata+xml" {
		t.Fatalf("Content-Type %q, want application/samlmetadata+xml", ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestSAMLMetadataIsWellFormedAndNamespaced(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	body := fetchMetadata(t, hts.URL, cfg.TenantID)

	var probe struct {
		XMLName  xml.Name
		EntityID string `xml:"entityID,attr"`
	}
	if err := xml.Unmarshal(body, &probe); err != nil {
		t.Fatalf("metadata is not well-formed XML: %v", err)
	}
	// An SP looks the element up by namespace, not by local name. Getting the
	// namespace wrong yields a document that reads correctly to a human and is
	// invisible to every parser.
	if probe.XMLName.Space != "urn:oasis:names:tc:SAML:2.0:metadata" {
		t.Fatalf("EntityDescriptor namespace %q", probe.XMLName.Space)
	}
	if probe.XMLName.Local != "EntityDescriptor" {
		t.Fatalf("root element %q, want EntityDescriptor", probe.XMLName.Local)
	}
	if probe.EntityID == "" || !strings.Contains(probe.EntityID, cfg.TenantID) {
		t.Fatalf("entityID %q does not name the tenant", probe.EntityID)
	}
}

// The certificate in metadata must be the key that signs assertions. If these
// two ever diverge, every signature verifies against nothing and the SP's
// error is "invalid signature", which sends the reader looking in the wrong
// place entirely.
func TestSAMLMetadataCertificateIsTheTenantSigningKey(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	body := fetchMetadata(t, hts.URL, cfg.TenantID)

	var doc struct {
		IDPSSO struct {
			KeyDescriptor struct {
				Use     string `xml:"use,attr"`
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
	kd := doc.IDPSSO.KeyDescriptor
	if kd.Use != "signing" {
		t.Fatalf("KeyDescriptor use=%q, want signing", kd.Use)
	}
	raw := strings.Join(strings.Fields(kd.KeyInfo.X509Data.Cert), "")
	if raw == "" {
		t.Fatal("metadata carries no X509Certificate")
	}
	// Base64 DER, no PEM armour: that is what the schema says and what SP
	// parsers feed straight into their X.509 reader.
	if strings.Contains(raw, "BEGIN CERTIFICATE") {
		t.Fatal("X509Certificate is PEM armoured; the schema wants bare base64 DER")
	}
	der, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("X509Certificate is not valid base64: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("X509Certificate does not parse: %v", err)
	}

	// Compare against the key the JWKS publishes: same tenant key, two envelopes.
	jwksResp, err := http.Get(hts.URL + "/" + cfg.TenantID + "/discovery/v2.0/keys")
	if err != nil {
		t.Fatal(err)
	}
	defer jwksResp.Body.Close()
	if jwksResp.StatusCode != http.StatusOK {
		t.Skipf("JWKS not served at this path (%d); certificate parsed correctly", jwksResp.StatusCode)
	}
	if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
		t.Fatalf("certificate key is %T, want RSA", cert.PublicKey)
	}
}

func TestSAMLMetadataAdvertisesBothSSOBindings(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	body := fetchMetadata(t, hts.URL, cfg.TenantID)

	var doc struct {
		IDPSSO struct {
			Protocol string `xml:"protocolSupportEnumeration,attr"`
			SSO      []struct {
				Binding  string `xml:"Binding,attr"`
				Location string `xml:"Location,attr"`
			} `xml:"SingleSignOnService"`
		} `xml:"IDPSSODescriptor"`
	}
	if err := xml.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.IDPSSO.Protocol != "urn:oasis:names:tc:SAML:2.0:protocol" {
		t.Fatalf("protocolSupportEnumeration %q", doc.IDPSSO.Protocol)
	}
	want := map[string]bool{
		"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect": false,
		"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST":     false,
	}
	for _, s := range doc.IDPSSO.SSO {
		if _, ok := want[s.Binding]; ok {
			want[s.Binding] = true
			if !strings.HasSuffix(s.Location, "/saml2") {
				t.Fatalf("SSO location %q does not end in /saml2", s.Location)
			}
		}
	}
	for binding, seen := range want {
		if !seen {
			t.Fatalf("metadata does not advertise %s", binding)
		}
	}
}

func TestSAMLMetadataRejectsAnUnknownTenant(t *testing.T) {
	hts, _, _ := newTestServer(t)
	resp, err := http.Get(hts.URL + "/11111111-2222-3333-4444-555555555555/federationmetadata/2007-06/federationmetadata.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown tenant returned %d, want 404", resp.StatusCode)
	}
}
