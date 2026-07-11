package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// localAPI builds a ResourceServer backed by a locally-signed JWKS (no emulator
// required) so we can drive the HTTP handler through every branch. It returns
// the running test server, the signing key, its kid, and the PDP to seed.
func localAPI(t *testing.T, pdp PDP) (*httptest.Server, *rsa.PrivateKey, string) {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "local-kid"
	jwks := jwksServer(t, kid, &key.PublicKey)
	t.Cleanup(jwks.Close)

	fixed := time.Unix(1_600_000_000, 0)
	srv := &ResourceServer{
		Validator: &TokenValidator{
			JWKSURL:  jwks.URL,
			Issuer:   "https://issuer.example/v2.0",
			Audience: "api://docs-api",
			Client:   jwks.Client(),
			Now:      func() time.Time { return fixed },
		},
		PDP: pdp,
	}
	api := httptest.NewServer(srv.Handler())
	t.Cleanup(api.Close)
	return api, key, kid
}

func doCall(t *testing.T, method, url, bearer string) int {
	t.Helper()
	req, _ := http.NewRequest(method, url, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// TestWriteDocumentAllowed exercises the POST/writer path end-to-end (200) so
// writeDocument runs.
func TestWriteDocumentAllowed(t *testing.T) {
	pdp := NewInMemoryPDP()
	pdp.Write("user:user-1", "writer", "doc:readme")
	api, key, kid := localAPI(t, pdp)

	tok := signRS256(t, key, kid, baseClaims("api://docs-api"))
	if code := doCall(t, "POST", api.URL+"/documents/readme", tok); code != 200 {
		t.Fatalf("authorized write: want 200, got %d", code)
	}
}

// TestAuthorizeMalformedBearer covers the "Authorization present but no Bearer
// prefix" 401 branch (TrimPrefix returns the header unchanged).
func TestAuthorizeMalformedBearer(t *testing.T) {
	api, _, _ := localAPI(t, NewInMemoryPDP())
	req, _ := http.NewRequest("GET", api.URL+"/documents/readme", nil)
	req.Header.Set("Authorization", "Basic abc123") // no "Bearer " prefix
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("non-bearer auth header: want 401, got %d", resp.StatusCode)
	}
}

// TestAuthorizeNoOID covers the "token has no user subject (oid)" 403 branch.
func TestAuthorizeNoOID(t *testing.T) {
	api, key, kid := localAPI(t, NewInMemoryPDP())
	claims := baseClaims("api://docs-api")
	delete(claims, "oid")
	tok := signRS256(t, key, kid, claims)
	if code := doCall(t, "GET", api.URL+"/documents/readme", tok); code != 403 {
		t.Fatalf("token without oid: want 403, got %d", code)
	}
}

// errPDP always fails, to drive the 502 "authorization service error" branch.
type errPDP struct{}

func (errPDP) Check(context.Context, CheckRequest) (bool, error) {
	return false, fmt.Errorf("boom")
}

// TestAuthorizePDPError covers the StatusBadGateway (502) branch when the PDP
// returns an error.
func TestAuthorizePDPError(t *testing.T) {
	api, key, kid := localAPI(t, errPDP{})
	tok := signRS256(t, key, kid, baseClaims("api://docs-api"))
	if code := doCall(t, "GET", api.URL+"/documents/readme", tok); code != http.StatusBadGateway {
		t.Fatalf("PDP error: want 502, got %d", code)
	}
}

// TestEnv covers the env() helper both branches.
func TestEnv(t *testing.T) {
	const k = "EXTAUTHZ_TEST_ENV"
	os.Unsetenv(k)
	if got := env(k, "fallback"); got != "fallback" {
		t.Fatalf("unset env: want fallback, got %q", got)
	}
	t.Setenv(k, "explicit")
	if got := env(k, "fallback"); got != "explicit" {
		t.Fatalf("set env: want explicit, got %q", got)
	}
}

// TestValidatorDefaultClient exercises client()'s default-http.DefaultClient
// branch (Client left nil) — the httptest JWKS server listens on real
// localhost, so http.DefaultClient can reach it.
func TestValidatorDefaultClient(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := jwksServer(t, "kid1", &key.PublicKey)
	defer jwks.Close()
	v := &TokenValidator{
		JWKSURL:  jwks.URL,
		Issuer:   "https://issuer.example/v2.0",
		Audience: "api://docs-api",
		Now:      func() time.Time { return time.Unix(1_600_000_000, 0) },
		// Client intentionally nil → http.DefaultClient
	}
	tok := signRS256(t, key, "kid1", baseClaims("api://docs-api"))
	if _, err := v.Validate(tok); err != nil {
		t.Fatalf("default-client validation failed: %v", err)
	}
}

// TestDecodeSegmentBadBase64 drives decodeSegment's base64-error branch through
// Validate: a 3-part token whose header segment is not valid base64url.
func TestDecodeSegmentBadBase64(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := jwksServer(t, "kid1", &key.PublicKey)
	defer jwks.Close()
	v := newValidator(t, jwks, "api://docs-api")
	// "!!!" is not valid base64url, so decodeSegment(parts[0]) errors.
	if _, err := v.Validate("!!!.payload.sig"); err == nil {
		t.Fatal("bad base64 header should be rejected")
	}
}

// TestValidateBadSignatureEncoding covers Validate's base64-decode-of-signature
// error branch: a well-formed RS256 header + valid kid, but an un-decodable
// signature segment.
func TestValidateBadSignatureEncoding(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := jwksServer(t, "kid1", &key.PublicKey)
	defer jwks.Close()
	v := newValidator(t, jwks, "api://docs-api")

	b64 := func(x any) string { raw, _ := json.Marshal(x); return base64.RawURLEncoding.EncodeToString(raw) }
	tok := b64(map[string]any{"alg": "RS256", "kid": "kid1"}) + "." + b64(baseClaims("api://docs-api")) + ".!!!"
	if _, err := v.Validate(tok); err == nil {
		t.Fatal("un-decodable signature should be rejected")
	}
}

// TestValidateBadPayload covers Validate's payload-decode error branch: header
// and signature verify, but the payload segment isn't valid JSON.
func TestValidateBadPayload(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := jwksServer(t, "kid1", &key.PublicKey)
	defer jwks.Close()
	v := newValidator(t, jwks, "api://docs-api")

	b64 := func(x any) string { raw, _ := json.Marshal(x); return base64.RawURLEncoding.EncodeToString(raw) }
	head := b64(map[string]any{"alg": "RS256", "kid": "kid1"})
	// Valid base64url that decodes to bytes which are NOT valid JSON.
	body := base64.RawURLEncoding.EncodeToString([]byte("not-json-payload"))
	sum := sha256.Sum256([]byte(head + "." + body))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	tok := head + "." + body + "." + base64.RawURLEncoding.EncodeToString(sig)
	if _, err := v.Validate(tok); err == nil {
		t.Fatal("non-JSON payload should be rejected")
	}
}

// TestKeyForKidRefreshError covers keyForKid's branch where the cache misses and
// the JWKS refresh itself fails.
func TestKeyForKidRefreshError(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	v := &TokenValidator{
		JWKSURL:  "http://127.0.0.1:1/keys", // unreachable
		Issuer:   "https://issuer.example/v2.0",
		Audience: "api://docs-api",
		Client:   &http.Client{Timeout: time.Second},
		Now:      func() time.Time { return time.Unix(1_600_000_000, 0) },
	}
	tok := signRS256(t, key, "kid1", baseClaims("api://docs-api"))
	if _, err := v.Validate(tok); err == nil {
		t.Fatal("unreachable JWKS during key lookup should fail validation")
	}
}

// TestKeyForKidCacheHit validates twice with the same validator so the second
// call hits the cached-key fast path in keyForKid (before any refresh).
func TestKeyForKidCacheHit(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks := jwksServer(t, "kid1", &key.PublicKey)
	defer jwks.Close()
	v := newValidator(t, jwks, "api://docs-api")
	tok := signRS256(t, key, "kid1", baseClaims("api://docs-api"))
	for i := 0; i < 2; i++ {
		if _, err := v.Validate(tok); err != nil {
			t.Fatalf("validate #%d: %v", i, err)
		}
	}
}

// TestRefreshKeysErrors covers refreshKeys failure branches: unreachable JWKS
// URL, a non-JSON body, and malformed key material (which is skipped).
func TestRefreshKeysErrors(t *testing.T) {
	fixed := func() time.Time { return time.Unix(1_600_000_000, 0) }

	// (a) JWKS fetch fails (connection refused on an unused port).
	v := &TokenValidator{
		JWKSURL:  "http://127.0.0.1:1/keys",
		Issuer:   "https://issuer.example/v2.0",
		Audience: "api://docs-api",
		Client:   &http.Client{Timeout: time.Second},
		Now:      fixed,
	}
	if err := v.refreshKeys(); err == nil {
		t.Fatal("unreachable JWKS: expected fetch error")
	}

	// (b) JWKS body is not valid JSON → decode error.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("not json"))
	}))
	defer bad.Close()
	v.JWKSURL = bad.URL
	v.Client = bad.Client()
	if err := v.refreshKeys(); err == nil {
		t.Fatal("non-JSON JWKS: expected decode error")
	}

	// (c) Keys with un-decodable N/E are skipped (continue branches), leaving no
	// usable key for the kid.
	skip := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{
			{"kid": "bad-n", "n": "!!!", "e": "AQAB"},
			{"kid": "bad-e", "n": "AQAB", "e": "!!!"},
		}})
	}))
	defer skip.Close()
	v.JWKSURL = skip.URL
	v.Client = skip.Client()
	if err := v.refreshKeys(); err != nil {
		t.Fatalf("refreshKeys with skippable keys should not error: %v", err)
	}
	if _, err := v.keyForKid("bad-n"); err == nil {
		t.Fatal("bad-n key should have been skipped")
	}
}
