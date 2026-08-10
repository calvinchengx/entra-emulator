package identity

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"time"

	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// SAML 2.0, the half of Entra that speaks XML.
//
// WHY THIS IS IN SCOPE. The project's boundary asks one question of any
// capability: does it need a policy engine, a risk model, or a tenant's
// compliance posture? SAML needs none of the three. It is a signed-assertion
// protocol, and an assertion this emulator signs is exactly as real as a token
// it signs: same tenant key, same RSA, a different envelope. Conditional
// Access and Identity Protection are the things that genuinely sit the other
// side of that line, and they stay there.
//
// The paths are Entra's own, so an SP configured against a real tenant can be
// repointed by changing the host and nothing else:
//
//	/{tenant}/federationmetadata/2007-06/federationmetadata.xml
//	/{tenant}/saml2                      (SSO, Redirect and POST bindings)

const (
	nsMetadata  = "urn:oasis:names:tc:SAML:2.0:metadata"
	nsAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsDSig      = "http://www.w3.org/2000/09/xmldsig#"

	bindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	bindingPOST     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

	// Entra issues NameID in this format by default for SAML apps.
	nameIDFormatEmail = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
)

// entityDescriptor is the IdP half of SAML metadata. Only the elements a
// service provider actually reads are modelled: an SP that needs more will say
// so loudly, and inventing elements nobody consumes is how XML documents grow
// without anyone able to say what depends on them.
type entityDescriptor struct {
	XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID string   `xml:"entityID,attr"`
	IDPSSO   idpSSODescriptor
}

type idpSSODescriptor struct {
	XMLName                    xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
	ProtocolSupportEnumeration string   `xml:"protocolSupportEnumeration,attr"`
	// Entra sets this, and some SPs refuse an IdP that does not commit to
	// signing its assertions.
	WantAuthnRequestsSigned bool          `xml:"WantAuthnRequestsSigned,attr"`
	KeyDescriptor           keyDescriptor `xml:"KeyDescriptor"`
	NameIDFormat            []string      `xml:"NameIDFormat"`
	SingleSignOnService     []ssoService  `xml:"SingleSignOnService"`
	SingleLogoutService     []ssoService  `xml:"SingleLogoutService"`
}

type keyDescriptor struct {
	Use     string  `xml:"use,attr"`
	KeyInfo keyInfo `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
}

type keyInfo struct {
	X509Data x509Data `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
}

type x509Data struct {
	// Base64 DER without PEM armour, which is what the schema specifies and
	// what every SP parser expects.
	X509Certificate string `xml:"http://www.w3.org/2000/09/xmldsig# X509Certificate"`
}

type ssoService struct {
	Binding  string `xml:"Binding,attr"`
	Location string `xml:"Location,attr"`
}

// samlEntityID is the IdP's identity as an SP records it. Real Entra uses
// https://sts.windows.net/{tid}/ because that is where its STS lives; this
// emulator names its own origin for the same reason, so the value is
// self-describing rather than a borrowed constant that resolves to Microsoft.
func (i *Identity) samlEntityID(tid string) string {
	return i.Cfg.Origins.Login + "/" + tid + "/"
}

func (i *Identity) samlSSOURL(tid string) string {
	return i.Cfg.Origins.Login + "/" + tid + "/saml2"
}

// handleSAMLMetadata serves the IdP metadata document.
func (i *Identity) handleSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	tid, ok := i.tenantSegment(r)
	if !ok {
		i.renderErrorPage(w, http.StatusNotFound, "Unknown tenant",
			"No such tenant in this directory.")
		return
	}
	signer, err := tokens.EnsureActiveKey(i.Store, tid)
	if err != nil {
		i.renderErrorPage(w, http.StatusInternalServerError, "Metadata unavailable",
			"No signing key for this tenant.")
		return
	}
	// A window anchored to today, not to when the key was made. Anchoring it
	// to key creation looked reproducible and shipped an expired certificate
	// the moment a database outlived the validity period, which every SP that
	// checks validity would reject. Truncating to the day keeps it stable for
	// anyone fetching metadata twice in a session.
	der, err := signer.SAMLCertificate(tid, time.Now().AddDate(0, 0, -1).Truncate(24*time.Hour))
	if err != nil {
		i.renderErrorPage(w, http.StatusInternalServerError, "Metadata unavailable",
			"Could not derive the signing certificate.")
		return
	}

	out, err := samlMetadataXML(der, i.samlEntityID(tid), i.samlSSOURL(tid))
	if err != nil {
		i.renderErrorPage(w, http.StatusInternalServerError, "Metadata unavailable",
			"Could not encode metadata.")
		return
	}

	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

// samlMetadataXML builds the document, separately from serving it.
//
// Split out because the handler's failure modes were otherwise unreachable
// from a test: a store that cannot produce a key and a marshaller that cannot
// encode our own struct are both hard to arrange through an HTTP request, so
// those branches would have been shipped unexecuted. Here they are ordinary
// arguments and return values.
func samlMetadataXML(certDER []byte, entityID, ssoURL string) ([]byte, error) {
	if len(certDER) == 0 {
		return nil, fmt.Errorf("saml: refusing to publish metadata with no signing certificate")
	}
	if entityID == "" || ssoURL == "" {
		return nil, fmt.Errorf("saml: entityID and SSO location are both required")
	}
	doc := entityDescriptor{
		EntityID: entityID,
		IDPSSO: idpSSODescriptor{
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			WantAuthnRequestsSigned:    false,
			KeyDescriptor: keyDescriptor{
				Use: "signing",
				KeyInfo: keyInfo{X509Data: x509Data{
					X509Certificate: base64.StdEncoding.EncodeToString(certDER),
				}},
			},
			NameIDFormat: []string{nameIDFormatEmail},
			SingleSignOnService: []ssoService{
				{Binding: bindingRedirect, Location: ssoURL},
				{Binding: bindingPOST, Location: ssoURL},
			},
			SingleLogoutService: []ssoService{
				{Binding: bindingRedirect, Location: ssoURL},
			},
		},
	}
	body, err := xml.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), body...), nil
}
