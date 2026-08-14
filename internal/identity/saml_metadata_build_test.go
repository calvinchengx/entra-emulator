package identity

import (
	"encoding/base64"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/beevik/etree"
)

// The document builder is unit-tested apart from the handler, because these
// refusals are what stop a broken IdP publishing metadata that looks valid.

func TestSAMLMetadataXMLRefusesAnEmptyCertificate(t *testing.T) {
	// Metadata with no certificate parses, validates, and is useless: every
	// assertion it vouches for would fail verification with no clue why.
	if _, err := samlMetadataXML(nil, "https://idp.example/t/", "https://idp.example/t/saml2"); err == nil {
		t.Fatal("want a refusal when there is no signing certificate")
	}
}

func TestSAMLMetadataXMLRequiresEntityIDAndLocation(t *testing.T) {
	der := []byte{0x30, 0x82}
	if _, err := samlMetadataXML(der, "", "https://idp.example/t/saml2"); err == nil {
		t.Fatal("want a refusal with no entityID")
	}
	if _, err := samlMetadataXML(der, "https://idp.example/t/", ""); err == nil {
		t.Fatal("want a refusal with no SSO location")
	}
}

func TestSAMLMetadataXMLEmitsADeclarationAndParses(t *testing.T) {
	out, err := samlMetadataXML([]byte{0x30, 0x82, 0x01}, "https://idp.example/t/",
		"https://idp.example/t/saml2")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(out), "<?xml") {
		t.Fatalf("no XML declaration: %q", string(out[:20]))
	}
	var probe struct {
		XMLName  xml.Name
		EntityID string `xml:"entityID,attr"`
	}
	if err := xml.Unmarshal(out, &probe); err != nil {
		t.Fatalf("builder produced XML that does not parse: %v", err)
	}
	if probe.EntityID != "https://idp.example/t/" {
		t.Fatalf("entityID %q", probe.EntityID)
	}
}

// Test Budget: 5 walking-skeleton behaviors × 2 = 10. This is behavior 1
// (FederationMetadata names a WS-Fed STS at /{tid}/wsfed).
func TestSAMLMetadataXMLEmitsWSFedRoleDescriptor(t *testing.T) {
	cert := []byte{0x30, 0x82, 0x01}
	out, err := samlMetadataXML(cert, "https://idp.example/t/", "https://idp.example/t/saml2")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	if !strings.Contains(body, "RoleDescriptor") {
		t.Fatal("FederationMetadata has no WS-Fed RoleDescriptor")
	}
	if !strings.Contains(body, "SecurityTokenServiceType") {
		t.Fatalf("RoleDescriptor is not SecurityTokenServiceType:\n%s", body)
	}
	wantSTS := "https://idp.example/t/wsfed"
	if !strings.Contains(body, "PassiveRequestorEndpoint") || !strings.Contains(body, wantSTS) {
		t.Fatalf("missing PassiveRequestorEndpoint %s:\n%s", wantSTS, body)
	}
	if !strings.Contains(body, "SecurityTokenServiceEndpoint") {
		t.Fatalf("missing SecurityTokenServiceEndpoint:\n%s", body)
	}
	if !strings.Contains(body, "IDPSSODescriptor") {
		t.Fatal("growing WS-Fed RoleDescriptor removed IDPSSODescriptor")
	}
	certB64 := base64.StdEncoding.EncodeToString(cert)
	idpCert := metadataSectionCert(t, out, "./IDPSSODescriptor")
	wsfedCert := metadataSectionCert(t, out, "./RoleDescriptor")
	if idpCert != certB64 || wsfedCert != certB64 || idpCert != wsfedCert {
		t.Fatal("WS-Fed RoleDescriptor must publish the same signing certificate as IDPSSODescriptor")
	}
}

func TestSAMLMetadataXMLAdvertisesSignOutOnPassiveRequestorEndpoint(t *testing.T) {
	out, err := samlMetadataXML([]byte{0x30, 0x82, 0x01}, "https://idp.example/t/",
		"https://idp.example/t/saml2")
	if err != nil {
		t.Fatal(err)
	}
	rd := parseMetadataRoot(t, out).FindElement("./RoleDescriptor")
	if rd == nil {
		t.Fatal("FederationMetadata has no WS-Fed RoleDescriptor")
	}
	want := "https://idp.example/t/wsfed"
	passive := metadataFedAddress(rd, "PassiveRequestorEndpoint")
	if passive != want {
		t.Fatalf("sign-out URL %q is not the PassiveRequestorEndpoint %s", passive, want)
	}
	if sts := metadataFedAddress(rd, "SecurityTokenServiceEndpoint"); sts != passive {
		t.Fatalf("STS %q differs from PassiveRequestorEndpoint %q", sts, passive)
	}
	if strings.Contains(string(out), "wsignout1.0") {
		t.Fatal("metadata must not require a wsignout1.0 round-trip")
	}
}

func TestSAMLMetadataXMLDoesNotPublishASecondMetadataPath(t *testing.T) {
	out, err := samlMetadataXML([]byte{0x30, 0x82, 0x01}, "https://idp.example/t/",
		"https://idp.example/t/saml2")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "/wsfed/metadata") {
		t.Fatal("builder published a second metadata URL")
	}
	if parseMetadataRoot(t, out).FindElement("./RoleDescriptor") == nil {
		t.Fatal("WS-Fed RoleDescriptor must live on the existing FederationMetadata document")
	}
}

func parseMetadataRoot(t *testing.T, out []byte) *etree.Element {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(out); err != nil {
		t.Fatalf("builder produced XML that does not parse: %v", err)
	}
	if doc.Root() == nil {
		t.Fatal("metadata has no EntityDescriptor")
	}
	return doc.Root()
}

func metadataSectionCert(t *testing.T, out []byte, path string) string {
	t.Helper()
	section := parseMetadataRoot(t, out).FindElement(path)
	if section == nil {
		t.Fatalf("missing %s", path)
	}
	el := section.FindElement(".//X509Certificate")
	if el == nil {
		t.Fatalf("%s has no X509Certificate", path)
	}
	return strings.Join(strings.Fields(el.Text()), "")
}

func metadataFedAddress(rd *etree.Element, local string) string {
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
