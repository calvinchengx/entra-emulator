package identity

import (
	"strings"
	"testing"
	"time"
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
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("RSTR is missing %s\n%s", want, s)
		}
	}
}
