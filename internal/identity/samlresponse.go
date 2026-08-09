package identity

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// The IdP's half: a signed Assertion, wrapped in a Response, delivered by POST.
//
// WHAT AN SP ACTUALLY CHECKS, and therefore what this has to get right:
//
//	the signature      over the Assertion, enveloped, exclusive c14n
//	Audience           this assertion is for THIS service provider
//	Recipient          delivered to the endpoint it was meant for
//	InResponseTo       answers the request the SP actually sent
//	NotOnOrAfter       and it has not been sitting in a proxy log for a week
//
// Every one of those is a replay or redirection defence. An assertion missing
// AudienceRestriction is valid at every SP that trusts this IdP, which turns a
// login at one application into a login at all of them.

const (
	statusSuccess     = "urn:oasis:names:tc:SAML:2.0:status:Success"
	confirmationBeare = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
	authnCtxPassword  = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"

	// assertionLifetime is how long the SP may accept it. Entra uses five
	// minutes for the confirmation window; short is the point, because a
	// bearer assertion is a credential and anyone holding it is the subject.
	assertionLifetime = 5 * time.Minute
	// clockSkew is subtracted from NotBefore. Without it, an SP whose clock is
	// a second behind rejects a valid assertion, and the failure looks like a
	// signature problem rather than a clock problem.
	clockSkew = 1 * time.Minute
)

// samlKeyStore adapts the tenant signing key to what goxmldsig wants.
type samlKeyStore struct {
	key     *rsa.PrivateKey
	certDER []byte
}

func (k samlKeyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	if k.key == nil || len(k.certDER) == 0 {
		return nil, nil, fmt.Errorf("saml: signing material is incomplete")
	}
	return k.key, k.certDER, nil
}

// samlAssertionInput is everything the assertion asserts. Passed as one struct
// so a caller cannot silently omit the audience or the recipient, which are
// the two fields whose absence is invisible until someone replays a token.
type samlAssertionInput struct {
	IssuerEntityID string
	SPEntityID     string
	ACSURL         string
	InResponseTo   string
	NameID         string
	NameIDFormat   string
	SessionIndex   string
	Attributes     map[string][]string
	Now            time.Time
}

func (in samlAssertionInput) validate() error {
	switch {
	case in.IssuerEntityID == "":
		return fmt.Errorf("saml: assertion needs an issuer")
	case in.SPEntityID == "":
		return fmt.Errorf("saml: assertion needs an audience, or it is valid at every SP")
	case in.ACSURL == "":
		return fmt.Errorf("saml: assertion needs a recipient")
	case in.NameID == "":
		return fmt.Errorf("saml: assertion needs a subject")
	}
	return nil
}

func iso(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// buildAssertion returns the unsigned <saml:Assertion>.
func buildAssertion(in samlAssertionInput, id string) (*etree.Element, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	notBefore := in.Now.Add(-clockSkew)
	notAfter := in.Now.Add(assertionLifetime)

	a := etree.NewElement("saml:Assertion")
	a.CreateAttr("xmlns:saml", nsAssertion)
	a.CreateAttr("ID", id)
	a.CreateAttr("Version", "2.0")
	a.CreateAttr("IssueInstant", iso(in.Now))
	a.CreateElement("saml:Issuer").SetText(in.IssuerEntityID)

	subj := a.CreateElement("saml:Subject")
	nameID := subj.CreateElement("saml:NameID")
	format := in.NameIDFormat
	if format == "" {
		format = nameIDFormatEmail
	}
	nameID.CreateAttr("Format", format)
	nameID.SetText(in.NameID)

	sc := subj.CreateElement("saml:SubjectConfirmation")
	sc.CreateAttr("Method", confirmationBeare)
	scd := sc.CreateElement("saml:SubjectConfirmationData")
	scd.CreateAttr("NotOnOrAfter", iso(notAfter))
	scd.CreateAttr("Recipient", in.ACSURL)
	if in.InResponseTo != "" {
		scd.CreateAttr("InResponseTo", in.InResponseTo)
	}

	cond := a.CreateElement("saml:Conditions")
	cond.CreateAttr("NotBefore", iso(notBefore))
	cond.CreateAttr("NotOnOrAfter", iso(notAfter))
	ar := cond.CreateElement("saml:AudienceRestriction")
	ar.CreateElement("saml:Audience").SetText(in.SPEntityID)

	as := a.CreateElement("saml:AuthnStatement")
	as.CreateAttr("AuthnInstant", iso(in.Now))
	if in.SessionIndex != "" {
		as.CreateAttr("SessionIndex", in.SessionIndex)
	}
	as.CreateElement("saml:AuthnContext").
		CreateElement("saml:AuthnContextClassRef").SetText(authnCtxPassword)

	if len(in.Attributes) > 0 {
		stmt := a.CreateElement("saml:AttributeStatement")
		for _, name := range sortedKeys(in.Attributes) {
			at := stmt.CreateElement("saml:Attribute")
			at.CreateAttr("Name", name)
			at.CreateAttr("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:uri")
			for _, v := range in.Attributes[name] {
				at.CreateElement("saml:AttributeValue").SetText(v)
			}
		}
	}
	return a, nil
}

// signAssertion returns the assertion with an enveloped signature.
//
// Delegated to goxmldsig rather than hand-rolled. Exclusive canonicalisation
// and the signature-wrapping attack class are exactly the kind of thing that
// looks finished long before it is correct, and a dev tool that gets it wrong
// teaches an SP author their verification works when it does not.
func signAssertion(a *etree.Element, key *rsa.PrivateKey, certDER []byte) (*etree.Element, error) {
	ctx := dsig.NewDefaultSigningContext(samlKeyStore{key: key, certDER: certDER})
	if err := ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		return nil, fmt.Errorf("saml: %w", err)
	}
	// EXCLUSIVE canonicalisation, overriding the library's inclusive C14N 1.1
	// default. SAML requires exclusive, and every SP library expects it; the
	// default produced a signature that would not verify. Inclusive c14n also
	// drags in ancestor namespace declarations, so an assertion that verifies
	// on its own breaks the moment it is wrapped in the Response envelope,
	// which is precisely what happens here.
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signed, err := ctx.SignEnveloped(a)
	if err != nil {
		return nil, fmt.Errorf("saml: signing the assertion: %w", err)
	}
	return signed, nil
}

// buildResponse wraps a signed assertion in the <samlp:Response> envelope and
// returns it serialised.
func buildResponse(signedAssertion *etree.Element, issuerEntityID, acsURL, inResponseTo, id string,
	now time.Time) ([]byte, error) {
	if signedAssertion == nil {
		return nil, fmt.Errorf("saml: refusing to send a response with no assertion")
	}
	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)

	r := doc.CreateElement("samlp:Response")
	r.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	r.CreateAttr("ID", id)
	r.CreateAttr("Version", "2.0")
	r.CreateAttr("IssueInstant", iso(now))
	r.CreateAttr("Destination", acsURL)
	if inResponseTo != "" {
		r.CreateAttr("InResponseTo", inResponseTo)
	}
	iss := r.CreateElement("saml:Issuer")
	iss.CreateAttr("xmlns:saml", nsAssertion)
	iss.SetText(issuerEntityID)

	st := r.CreateElement("samlp:Status")
	st.CreateElement("samlp:StatusCode").CreateAttr("Value", statusSuccess)

	r.AddChild(signedAssertion)
	return doc.WriteToBytes()
}

// encodeSAMLResponse is what goes in the form field: base64, never deflated.
// The POST binding does not compress, and an SP handed deflated bytes reports
// invalid XML.
func encodeSAMLResponse(xmlBytes []byte) string {
	return base64.StdEncoding.EncodeToString(xmlBytes)
}

func sortedKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// Stable output so the same login twice produces the same document, which
	// is what makes a golden test possible.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
