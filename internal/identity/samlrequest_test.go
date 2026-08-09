package identity

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"strings"
	"testing"
)

const sampleAuthnRequest = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
	`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_abc123" Version="2.0" ` +
	`AssertionConsumerServiceURL="https://sp.example/acs" Destination="https://idp.example/t/saml2">` +
	`<saml:Issuer>https://sp.example/metadata</saml:Issuer>` +
	`<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/>` +
	`</samlp:AuthnRequest>`

func deflateB64(t *testing.T, s string) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// Both bindings must yield the same request. They differ only in whether the
// XML was compressed, and pairing them wrongly reports "not valid XML" against
// a request that is entirely valid, which sends the reader hunting in the SP.
func TestDecodeAuthnRequestAcceptsBothBindings(t *testing.T) {
	redirect, err := decodeAuthnRequest(deflateB64(t, sampleAuthnRequest), true)
	if err != nil {
		t.Fatalf("redirect binding: %v", err)
	}
	post, err := decodeAuthnRequest(base64.StdEncoding.EncodeToString([]byte(sampleAuthnRequest)), false)
	if err != nil {
		t.Fatalf("post binding: %v", err)
	}
	for _, got := range []*authnRequest{redirect, post} {
		if got.ID != "_abc123" {
			t.Fatalf("ID %q", got.ID)
		}
		if got.Issuer != "https://sp.example/metadata" {
			t.Fatalf("Issuer %q", got.Issuer)
		}
		if got.AssertionConsumerServiceURL != "https://sp.example/acs" {
			t.Fatalf("ACS %q", got.AssertionConsumerServiceURL)
		}
		if got.NameIDPolicy.Format != nameIDFormatEmail {
			t.Fatalf("NameIDPolicy %q", got.NameIDPolicy.Format)
		}
	}
}

func TestDecodeAuthnRequestRejectsTheWrongBinding(t *testing.T) {
	// Deflated bytes read as plain base64 XML: the classic mispairing.
	if _, err := decodeAuthnRequest(deflateB64(t, sampleAuthnRequest), false); err == nil {
		t.Fatal("deflated payload decoded as POST binding, want an error")
	}
}

// A megabyte of zeroes is about a kilobyte deflated. Without a bound on the
// INFLATED size, that is memory exhaustion for the price of a query string.
func TestDecodeAuthnRequestBoundsTheInflatedSize(t *testing.T) {
	bomb := deflateB64(t, strings.Repeat("A", 4*maxAuthnRequestBytes))
	if len(bomb) > maxAuthnRequestBytes {
		t.Fatalf("test bomb is %d encoded bytes, not small enough to prove the point", len(bomb))
	}
	_, err := decodeAuthnRequest(bomb, true)
	if err == nil {
		t.Fatal("a payload inflating past the limit was accepted")
	}
	if !strings.Contains(err.Error(), "inflates past") {
		t.Fatalf("rejected for the wrong reason: %v", err)
	}
}

func TestDecodeAuthnRequestBoundsTheUncompressedSize(t *testing.T) {
	big := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("A"), maxAuthnRequestBytes+1))
	if _, err := decodeAuthnRequest(big, false); err == nil {
		t.Fatal("an oversized POST payload was accepted")
	}
}

func TestDecodeAuthnRequestRejectsMalformedInput(t *testing.T) {
	cases := map[string]struct {
		in       string
		deflated bool
	}{
		"empty":         {"", false},
		"whitespace":    {"   ", false},
		"not base64":    {"!!!!not base64!!!!", false},
		"not xml":       {base64.StdEncoding.EncodeToString([]byte("hello")), false},
		"not deflate":   {base64.StdEncoding.EncodeToString([]byte("hello")), true},
		"wrong element": {base64.StdEncoding.EncodeToString([]byte(`<html><body/></html>`)), false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeAuthnRequest(tc.in, tc.deflated); err == nil {
				t.Fatal("want an error, got none")
			}
		})
	}
}

// ID and Issuer are load-bearing rather than decorative: the response echoes
// the ID so the SP can correlate it, and the Issuer is how the IdP knows which
// application is asking.
func TestDecodeAuthnRequestRequiresIDAndIssuer(t *testing.T) {
	noID := strings.Replace(sampleAuthnRequest, ` ID="_abc123"`, "", 1)
	if _, err := decodeAuthnRequest(base64.StdEncoding.EncodeToString([]byte(noID)), false); err == nil {
		t.Fatal("accepted an AuthnRequest with no ID")
	}
	noIssuer := strings.Replace(sampleAuthnRequest,
		`<saml:Issuer>https://sp.example/metadata</saml:Issuer>`, "", 1)
	if _, err := decodeAuthnRequest(base64.StdEncoding.EncodeToString([]byte(noIssuer)), false); err == nil {
		t.Fatal("accepted an AuthnRequest with no Issuer")
	}
}
