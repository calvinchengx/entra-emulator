package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// signRS256 builds a signed JWT for tests using the given key and kid.
func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	b64 := func(v any) string {
		raw, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	head := b64(map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid})
	body := b64(claims)
	sum := sha256.Sum256([]byte(head + "." + body))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return head + "." + body + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// jwksServer serves a single-key JWKS for the given public key.
func jwksServer(t *testing.T, kid string, pub *rsa.PublicKey) *httptest.Server {
	t.Helper()
	eb := make([]byte, 8)
	binary.BigEndian.PutUint64(eb, uint64(pub.E))
	i := 0
	for i < len(eb) && eb[i] == 0 {
		i++
	}
	jwk := map[string]string{
		"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid,
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(eb[i:]),
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{jwk}})
	}))
}

func newValidator(t *testing.T, srv *httptest.Server, aud string) *TokenValidator {
	fixed := time.Unix(1_600_000_000, 0)
	return &TokenValidator{
		JWKSURL: srv.URL, Issuer: "https://issuer.example/v2.0", Audience: aud,
		Client: srv.Client(), Now: func() time.Time { return fixed },
	}
}

func baseClaims(aud string) map[string]any {
	return map[string]any{
		"iss": "https://issuer.example/v2.0", "aud": aud,
		"iat": 1_599_999_000, "nbf": 1_599_999_000, "exp": 1_600_003_600,
		"oid": "user-1", "sub": "pairwise-1", "scp": "access_as_user",
		"groups": []any{"g1", "g2"},
	}
}

func TestValidatorHappyPath(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, "kid1", &key.PublicKey)
	defer srv.Close()
	v := newValidator(t, srv, "api://docs-api")

	tok := signRS256(t, key, "kid1", baseClaims("api://docs-api"))
	claims, err := v.Validate(tok)
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if claims.OID != "user-1" || len(claims.Groups) != 2 || len(claims.Scopes) != 1 {
		t.Fatalf("claims not parsed: %+v", claims)
	}
}

func TestValidatorAudienceArray(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, "kid1", &key.PublicKey)
	defer srv.Close()
	v := newValidator(t, srv, "api://docs-api")

	c := baseClaims("ignored")
	c["aud"] = []any{"api://other", "api://docs-api"}
	if _, err := v.Validate(signRS256(t, key, "kid1", c)); err != nil {
		t.Fatalf("array audience containing the resource should pass: %v", err)
	}
}

func TestValidatorRejections(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := jwksServer(t, "kid1", &key.PublicKey)
	defer srv.Close()
	v := newValidator(t, srv, "api://docs-api")

	tamper := func(mut func(map[string]any)) string {
		c := baseClaims("api://docs-api")
		mut(c)
		return signRS256(t, key, "kid1", c)
	}

	cases := map[string]string{
		"malformed":       "not.a.jwt.at.all",
		"two segments":    "aa.bb",
		"wrong issuer":    tamper(func(c map[string]any) { c["iss"] = "https://evil/v2.0" }),
		"wrong audience":  tamper(func(c map[string]any) { c["aud"] = "api://other" }),
		"expired":         tamper(func(c map[string]any) { c["exp"] = 1_500_000_000 }),
		"not yet valid":   tamper(func(c map[string]any) { c["nbf"] = 1_700_000_000 }),
		"unknown kid":     signRS256(t, key, "unknown-kid", baseClaims("api://docs-api")),
		"bad signature":   signRS256(t, other, "kid1", baseClaims("api://docs-api")),
	}
	for name, tok := range cases {
		if _, err := v.Validate(tok); err == nil {
			t.Fatalf("%s: expected rejection, got nil", name)
		}
	}
}

func TestValidatorWrongAlg(t *testing.T) {
	srv := jwksServer(t, "kid1", &rsaKey(t).PublicKey)
	defer srv.Close()
	v := newValidator(t, srv, "api://docs-api")
	// Hand-craft an HS256 header — the validator must refuse non-RS256.
	b64 := func(v any) string { raw, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(raw) }
	tok := b64(map[string]any{"alg": "HS256", "kid": "kid1"}) + "." + b64(baseClaims("api://docs-api")) + ".sig"
	if _, err := v.Validate(tok); err == nil {
		t.Fatal("HS256 token should be rejected")
	}
}

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestPureHelpers(t *testing.T) {
	if !audienceMatches("x", "x") || audienceMatches("x", "y") {
		t.Fatal("string audienceMatches")
	}
	if !audienceMatches([]any{"a", "b"}, "b") || audienceMatches([]any{"a"}, "z") {
		t.Fatal("array audienceMatches")
	}
	c := toClaims(map[string]any{"oid": "o", "scp": "a b", "groups": []any{"g"}})
	if c.OID != "o" || len(c.Scopes) != 2 || len(c.Groups) != 1 {
		t.Fatalf("toClaims: %+v", c)
	}
}
