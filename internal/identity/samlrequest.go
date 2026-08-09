package identity

import (
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// The SP's half of the conversation: an AuthnRequest, arriving by one of two
// bindings that differ in exactly one way.
//
//	HTTP-Redirect  SAMLRequest = base64(raw DEFLATE(xml)), in the query string
//	HTTP-POST      SAMLRequest = base64(xml), in a form field
//
// The Redirect binding compresses because a query string has a length limit;
// the POST binding does not because a form body does not. Getting that pairing
// backwards produces "not valid XML" against a request that is perfectly
// valid, so the binding is passed explicitly rather than sniffed.

// maxAuthnRequestBytes bounds the INFLATED size, not the encoded size.
//
// Raw DEFLATE compresses a megabyte of zeroes into about a kilobyte, so an
// unbounded inflate of an attacker-supplied query parameter is a memory
// exhaustion primitive that costs the sender nothing. Real AuthnRequests are
// one to two kilobytes; 128 KiB is generous by two orders of magnitude and
// still bounded.
const maxAuthnRequestBytes = 128 << 10

type authnRequest struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	ID      string   `xml:"ID,attr"`
	Version string   `xml:"Version,attr"`
	// Where the SP wants the assertion delivered. Optional: an SP that omits
	// it is asking the IdP to use the endpoint it registered.
	AssertionConsumerServiceURL string `xml:"AssertionConsumerServiceURL,attr"`
	Destination                 string `xml:"Destination,attr"`
	Issuer                      string `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	NameIDPolicy                struct {
		Format string `xml:"Format,attr"`
	} `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
}

// decodeAuthnRequest turns the wire value into a request, or explains why not.
func decodeAuthnRequest(encoded string, deflated bool) (*authnRequest, error) {
	if strings.TrimSpace(encoded) == "" {
		return nil, fmt.Errorf("saml: no SAMLRequest")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("saml: SAMLRequest is not base64: %w", err)
	}
	if deflated {
		// LimitReader before the decompressor, so a bomb is truncated rather
		// than buffered. Reading one byte past the limit is how truncation is
		// told apart from a request that merely happens to be exactly the
		// limit, which would otherwise parse as valid XML cut in half.
		r := flate.NewReader(strings.NewReader(string(raw)))
		defer r.Close()
		limited, err := io.ReadAll(io.LimitReader(r, maxAuthnRequestBytes+1))
		if err != nil {
			return nil, fmt.Errorf("saml: SAMLRequest is not DEFLATE: %w", err)
		}
		if len(limited) > maxAuthnRequestBytes {
			return nil, fmt.Errorf("saml: SAMLRequest inflates past %d bytes", maxAuthnRequestBytes)
		}
		raw = limited
	} else if len(raw) > maxAuthnRequestBytes {
		return nil, fmt.Errorf("saml: SAMLRequest is larger than %d bytes", maxAuthnRequestBytes)
	}

	var req authnRequest
	if err := xml.Unmarshal(raw, &req); err != nil {
		return nil, fmt.Errorf("saml: SAMLRequest is not valid XML: %w", err)
	}
	if req.ID == "" {
		return nil, fmt.Errorf("saml: AuthnRequest has no ID")
	}
	// The response has to echo this, and an SP that cannot correlate its
	// request will reject a perfectly good assertion.
	if req.Issuer == "" {
		return nil, fmt.Errorf("saml: AuthnRequest has no Issuer")
	}
	return &req, nil
}

// resolveServiceProvider maps an AuthnRequest's Issuer onto a registered app,
// and decides where the assertion may be delivered.
//
// THE ACS IS VALIDATED, NOT TRUSTED. AssertionConsumerServiceURL arrives from
// the caller, and an IdP that posts a signed assertion to whatever URL it is
// handed is an open redirector that mints credentials. Real Entra checks the
// value against the app's registered reply URLs and refuses otherwise; so does
// this. An SP that omits the attribute gets its registered endpoint.
func (i *Identity) resolveServiceProvider(req *authnRequest) (*store.App, string, error) {
	app, err := i.Store.GetAppByIDURI(req.Issuer)
	if err != nil {
		return nil, "", fmt.Errorf("saml: no application registered with identifier %q", req.Issuer)
	}
	uris, err := i.Store.ListRedirectURIs(app.ID)
	if err != nil {
		return nil, "", fmt.Errorf("saml: cannot read reply URLs for %s: %w", app.ID, err)
	}
	var registered []string
	for _, u := range uris {
		if u.Type == redirectTypeSAMLACS {
			registered = append(registered, u.URI)
		}
	}
	if len(registered) == 0 {
		return nil, "", fmt.Errorf("saml: %s has no %s reply URL registered", app.ID, redirectTypeSAMLACS)
	}
	if req.AssertionConsumerServiceURL == "" {
		return app, registered[0], nil
	}
	for _, u := range registered {
		if u == req.AssertionConsumerServiceURL {
			return app, u, nil
		}
	}
	return nil, "", fmt.Errorf("saml: %q is not a registered reply URL for %s",
		req.AssertionConsumerServiceURL, app.ID)
}

// redirectTypeSAMLACS is the redirect-URI type that marks an Assertion
// Consumer Service endpoint. Reusing the existing table rather than adding a
// SAML-specific one keeps one answer to "where may this app receive
// credentials", which is the question that matters when reviewing an app.
const redirectTypeSAMLACS = "saml-acs"
