package identity

import (
	"encoding/xml"
	"strings"
	"testing"
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
