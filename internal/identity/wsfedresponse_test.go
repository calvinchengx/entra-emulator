package identity

import (
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
)

const persistentNameID = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"

// Test Budget: walking-skeleton behavior 4+5 (RSTR wrapping SAML 2.0;
// Audience = wtrealm, Issuer = entityID, NameID persistent).
func TestRSTRWrapsSAML20AssertionForTheRealm(t *testing.T) {
	key, certDER := signingMaterial(t)
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	a, err := buildAssertion(samlAssertionInput{
		IssuerEntityID: "https://idp.example/t/",
		SPEntityID:     "api://tasks-api",
		ACSURL:         "https://rp.example.test/signin-wsfed",
		NameID:         "user-object-id",
		NameIDFormat:   persistentNameID,
		Now:            now,
	}, "_assert1")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signAssertion(a, key, certDER)
	if err != nil {
		t.Fatal(err)
	}
	out, err := buildRSTR(signed, rstrInput{
		AppliesTo: "api://tasks-api",
		Now:       now,
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{
		"RequestSecurityTokenResponse",
		"RequestedSecurityToken",
		samlV2TokenType,
		`Version="2.0"`,
		"api://tasks-api",
		persistentNameID,
		`<saml:Issuer>https://idp.example/t/</saml:Issuer>`,
		nsAssertion,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("RSTR is missing %s\n%s", want, s)
		}
	}
	if strings.Contains(s, "urn:oasis:names:tc:SAML:1.1:assertion") ||
		strings.Contains(s, "urn:oasis:names:tc:SAML:1.0:assertion") {
		t.Fatalf("RSTR wrapped a SAML 1.1 assertion:\n%s", s)
	}
}

func TestBuildRSTRRefusesANilAssertion(t *testing.T) {
	_, err := buildRSTR(nil, rstrInput{AppliesTo: "api://tasks-api", Now: time.Now()})
	if err == nil || !strings.Contains(err.Error(), "no assertion") {
		t.Fatalf("want a nil-assertion refusal, got %v", err)
	}
}

func TestBuildRSTRRefusesEmptyAppliesTo(t *testing.T) {
	el := etree.NewElement("saml:Assertion")
	_, err := buildRSTR(el, rstrInput{Now: time.Now()})
	if err == nil || !strings.Contains(err.Error(), "AppliesTo") {
		t.Fatalf("want an AppliesTo refusal, got %v", err)
	}
}

func TestSignAndWrapRSTRRefusesIncompleteSigningMaterial(t *testing.T) {
	a, err := buildAssertion(samlAssertionInput{
		IssuerEntityID: "https://idp.example/t/",
		SPEntityID:     "api://tasks-api",
		ACSURL:         "https://rp.example.test/signin-wsfed",
		NameID:         "user-object-id",
		NameIDFormat:   persistentNameID,
		Now:            time.Now(),
	}, "_assert1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = signAndWrapRSTR(a, nil, nil, rstrInput{AppliesTo: "api://tasks-api", Now: time.Now()})
	if err == nil {
		t.Fatal("want a refusal when there is no key or certificate")
	}
}

func TestSignAndWrapRSTRRefusesEmptyAppliesToAfterSigning(t *testing.T) {
	key, certDER := signingMaterial(t)
	a, err := buildAssertion(samlAssertionInput{
		IssuerEntityID: "https://idp.example/t/",
		SPEntityID:     "api://tasks-api",
		ACSURL:         "https://rp.example.test/signin-wsfed",
		NameID:         "user-object-id",
		NameIDFormat:   persistentNameID,
		Now:            time.Now(),
	}, "_assert1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = signAndWrapRSTR(a, key, certDER, rstrInput{Now: time.Now()})
	if err == nil || !strings.Contains(err.Error(), "AppliesTo") {
		t.Fatalf("want AppliesTo refusal after a successful sign, got %v", err)
	}
}
