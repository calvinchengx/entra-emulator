package identity

import (
	"fmt"
	"time"

	"github.com/beevik/etree"
)

// TokenType is the OASIS SAML *token profile* 1.1 URI. The assertion itself
// is SAML 2.0; the 1.1 in the URI is the profile version, not the assertion
// version. Entra puts this exact value in wresult for an app-registration
// Wtrealm (spike S3b).
const samlV2TokenType = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0"

const (
	nsWSTrust = "http://schemas.xmlsoap.org/ws/2005/02/trust"
	nsWSU     = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	nsWSP     = "http://schemas.xmlsoap.org/ws/2004/09/policy"
)

type rstrInput struct {
	AppliesTo string
	Now       time.Time
}

func (in rstrInput) validate() error {
	if in.AppliesTo == "" {
		return fmt.Errorf("wsfed: RSTR needs AppliesTo, or the token is valid at every RP")
	}
	return nil
}

// buildRSTR wraps a signed SAML 2.0 assertion in a RequestSecurityTokenResponse.
//
// WHAT AN RP ACTUALLY CHECKS, and therefore what this has to get right:
//
//	TokenType          SAML 2.0 (the profile URI, not SAML 1.1)
//	RequestedSecurityToken  the signed assertion, not a SAML Response envelope
//	AppliesTo / Audience    this token is for THIS relying party
//
// WsFederationMessage.GetToken extracts the XML inside RequestedSecurityToken
// and ignores the TokenType element; handler selection is CanReadToken on
// that inner XML. The TokenType is still emitted because Entra emits it.
func buildRSTR(signedAssertion *etree.Element, in rstrInput) ([]byte, error) {
	if signedAssertion == nil {
		return nil, fmt.Errorf("wsfed: refusing to send a response with no assertion")
	}
	if err := in.validate(); err != nil {
		return nil, err
	}
	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)

	rstr := doc.CreateElement("t:RequestSecurityTokenResponse")
	rstr.CreateAttr("xmlns:t", nsWSTrust)

	lifetime := rstr.CreateElement("t:Lifetime")
	created := lifetime.CreateElement("wsu:Created")
	created.CreateAttr("xmlns:wsu", nsWSU)
	created.SetText(iso(in.Now))
	expires := lifetime.CreateElement("wsu:Expires")
	expires.CreateAttr("xmlns:wsu", nsWSU)
	expires.SetText(iso(in.Now.Add(assertionLifetime)))

	applies := rstr.CreateElement("wsp:AppliesTo")
	applies.CreateAttr("xmlns:wsp", nsWSP)
	epr := applies.CreateElement("wsa:EndpointReference")
	epr.CreateAttr("xmlns:wsa", nsWSA)
	epr.CreateElement("wsa:Address").SetText(in.AppliesTo)

	rst := rstr.CreateElement("t:RequestedSecurityToken")
	rst.AddChild(signedAssertion.Copy())

	rstr.CreateElement("t:TokenType").SetText(samlV2TokenType)
	rstr.CreateElement("t:RequestType").SetText("http://schemas.xmlsoap.org/ws/2005/02/trust/Issue")
	rstr.CreateElement("t:KeyType").SetText("http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey")

	return doc.WriteToBytes()
}
