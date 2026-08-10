package identity

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

func signingMaterial(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s := &tokens.Signer{Kid: "saml-test", PrivateKey: key}
	der, err := s.SAMLCertificate("tenant-a", time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return key, der
}

// reparse serialises an element and reads it back, which is what crossing the
// wire does to it.
func reparse(t *testing.T, el *etree.Element) *etree.Element {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	back := etree.NewDocument()
	if err := back.ReadFromBytes(raw); err != nil {
		t.Fatal(err)
	}
	return back.Root()
}

func testInput(now time.Time) samlAssertionInput {
	return samlAssertionInput{
		IssuerEntityID: "https://idp.example/t/",
		SPEntityID:     "https://sp.example/metadata",
		ACSURL:         "https://sp.example/acs",
		InResponseTo:   "_abc123",
		NameID:         "alice@example.test",
		SessionIndex:   "sess-1",
		Attributes:     map[string][]string{"groups": {"admins", "users"}},
		Now:            now,
	}
}

// The whole point of the exercise: a signature an INDEPENDENT verifier
// accepts. Verifying with the same library that signed it would still catch a
// broken key pairing, so this checks the property that matters and no more.
func TestSignedAssertionVerifiesAgainstTheAdvertisedCertificate(t *testing.T) {
	key, certDER := signingMaterial(t)
	a, err := buildAssertion(testInput(time.Now()), "_assert1")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signAssertion(a, key, certDER)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	// Verified from BYTES, not from the tree that was just signed. A service
	// provider receives a serialised document and parses it, and namespace
	// context is only fixed at serialisation, so validating the in-memory
	// element would test something no SP ever does.
	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	})
	if _, err := ctx.Validate(reparse(t, signed)); err != nil {
		t.Fatalf("assertion does not verify under the published certificate: %v", err)
	}
}

// Tampering must break verification. Without this the test above passes even
// if the signature covers nothing that matters.
func TestSignatureDoesNotSurviveTampering(t *testing.T) {
	key, certDER := signingMaterial(t)
	a, err := buildAssertion(testInput(time.Now()), "_assert1")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signAssertion(a, key, certDER)
	if err != nil {
		t.Fatal(err)
	}
	// Promote the subject to somebody else, exactly as an attacker would.
	if nameID := signed.FindElement("./saml:Subject/saml:NameID"); nameID != nil {
		nameID.SetText("attacker@example.test")
	} else {
		t.Fatal("could not find the NameID to tamper with")
	}
	cert, _ := x509.ParseCertificate(certDER)
	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	})
	if _, err := ctx.Validate(reparse(t, signed)); err == nil {
		t.Fatal("a tampered assertion still verified")
	}
}

// Each of these absences is silently exploitable, so each is refused rather
// than defaulted.
func TestAssertionRefusesToOmitItsDefences(t *testing.T) {
	now := time.Now()
	cases := map[string]func(*samlAssertionInput){
		"no audience makes it valid at every SP":     func(in *samlAssertionInput) { in.SPEntityID = "" },
		"no recipient makes it deliverable anywhere": func(in *samlAssertionInput) { in.ACSURL = "" },
		"no subject asserts nothing":                 func(in *samlAssertionInput) { in.NameID = "" },
		"no issuer cannot be attributed":             func(in *samlAssertionInput) { in.IssuerEntityID = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := testInput(now)
			mutate(&in)
			if _, err := buildAssertion(in, "_id"); err == nil {
				t.Fatal("want a refusal, got an assertion")
			}
		})
	}
}

func TestAssertionCarriesTheReplayDefences(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	a, err := buildAssertion(testInput(now), "_assert1")
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	doc.SetRoot(a.Copy())
	out, err := doc.WriteToString()
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{
		`<saml:Audience>https://sp.example/metadata</saml:Audience>`,
		`Recipient="https://sp.example/acs"`,
		`InResponseTo="_abc123"`,
		`NotOnOrAfter="2026-08-10T12:05:00Z"`, // now + 5 minutes
		`NotBefore="2026-08-10T11:59:00Z"`,    // now - 1 minute of skew
		`SessionIndex="sess-1"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("assertion is missing %s\n%s", want, out)
		}
	}
}

// Attribute order must be stable, or the same login twice produces different
// documents and nothing downstream can be compared.
func TestAttributeOrderIsStable(t *testing.T) {
	in := testInput(time.Now())
	in.Attributes = map[string][]string{"zeta": {"1"}, "alpha": {"2"}, "mid": {"3"}}
	var first string
	for i := 0; i < 5; i++ {
		a, err := buildAssertion(in, "_id")
		if err != nil {
			t.Fatal(err)
		}
		doc := etree.NewDocument()
		doc.SetRoot(a.Copy())
		out, _ := doc.WriteToString()
		if i == 0 {
			first = out
			if strings.Index(out, "alpha") > strings.Index(out, "zeta") {
				t.Fatal("attributes are not sorted")
			}
			continue
		}
		if out != first {
			t.Fatal("the same input produced two different assertions")
		}
	}
}

func TestBuildResponseWrapsAndRefusesEmptiness(t *testing.T) {
	key, certDER := signingMaterial(t)
	now := time.Now()
	a, err := buildAssertion(testInput(now), "_assert1")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signAssertion(a, key, certDER)
	if err != nil {
		t.Fatal(err)
	}
	out, err := buildResponse(signed, "https://idp.example/t/", "https://sp.example/acs",
		"_abc123", "_resp1", now)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{
		`<samlp:Response`,
		`Destination="https://sp.example/acs"`,
		`InResponseTo="_abc123"`,
		statusSuccess,
		`<saml:Assertion`,
		`<ds:Signature`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("response is missing %s", want)
		}
	}
	if _, err := buildResponse(nil, "https://idp.example/t/", "https://sp.example/acs", "", "_r", now); err == nil {
		t.Fatal("want a refusal for a response with no assertion")
	}
}

// The POST binding does not deflate. Sending compressed bytes yields "invalid
// XML" at the SP, which sends the reader looking at the wrong layer.
func TestEncodeSAMLResponseIsPlainBase64(t *testing.T) {
	raw := []byte(`<samlp:Response/>`)
	got := encodeSAMLResponse(raw)
	back, err := base64.StdEncoding.DecodeString(got)
	if err != nil {
		t.Fatalf("not base64: %v", err)
	}
	if string(back) != string(raw) {
		t.Fatal("encoding is not a plain base64 round trip")
	}
}

func TestKeyStoreRefusesIncompleteMaterial(t *testing.T) {
	if _, _, err := (samlKeyStore{}).GetKeyPair(); err == nil {
		t.Fatal("want an error with no key and no certificate")
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, _, err := (samlKeyStore{key: key}).GetKeyPair(); err == nil {
		t.Fatal("want an error with a key but no certificate")
	}
}
