package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/url"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// registerKey generates an RSA keypair, registers the public key on the app,
// and returns the private key for signing assertions.
func registerKey(t *testing.T, origin, appID string) *rsa.PrivateKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	status, _ := postJSON(t, origin+"/admin/api/apps/"+appID+"/keyCredentials",
		map[string]any{"publicKey": pubPEM, "displayName": "test key"})
	if status != 201 {
		t.Fatalf("register key credential: want 201, got %d", status)
	}
	return priv
}

// signAssertion signs a client assertion. A wide iat/nbf window (year 2001)
// brackets the emulator's real clock; exp defaults far in the future, or use
// the exp arg to force an expired assertion.
func signAssertion(t *testing.T, priv *rsa.PrivateKey, kid, clientID, aud string, exp int64) string {
	t.Helper()
	if exp == 0 {
		exp = 4_000_000_000 // year 2096
	}
	jwt, err := tokens.SignRS256(priv, kid, map[string]any{
		"iss": clientID, "sub": clientID, "aud": aud,
		"jti": "assertion-1", "iat": 1_000_000_000, "nbf": 1_000_000_000, "exp": exp,
	})
	if err != nil {
		t.Fatal(err)
	}
	return jwt
}

func tokenEndpoint(origin string) string {
	return origin + "/" + tenant + "/oauth2/v2.0/token"
}

func TestClientAssertionHappyPath(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	priv := registerKey(t, hts.URL, daemonID)

	// Note: newTestServer re-points cfg.Origins to hts.URL, so the token
	// endpoint the emulator accepts is hts.URL/<tenant>/oauth2/v2.0/token.
	aud := cfg.Origins.Login + "/" + tenant + "/oauth2/v2.0/token"
	assertion := signAssertion(t, priv, "k1", daemonID, aud, 0)

	resp, body := postForm(t, http.DefaultClient, tokenEndpoint(hts.URL), url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {daemonID},
		"client_assertion_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"client_assertion":      {assertion},
		"scope":                 {"https://graph.microsoft.com/.default"},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("client assertion auth: want 200, got %d %v", resp.StatusCode, body)
	}
	claims := decodeJWTPayload(t, body["access_token"].(string))
	if claims["appid"] != daemonID {
		t.Fatalf("unexpected token appid: %v", claims["appid"])
	}
}

func TestClientAssertionWrongKey(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	registerKey(t, hts.URL, daemonID)

	// Sign with a DIFFERENT (unregistered) key.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	aud := cfg.Origins.Login + "/" + tenant + "/oauth2/v2.0/token"
	assertion := signAssertion(t, other, "k1", daemonID, aud, 0)

	resp, body := postForm(t, http.DefaultClient, tokenEndpoint(hts.URL), url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {daemonID},
		"client_assertion_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"client_assertion":      {assertion},
		"scope":                 {"https://graph.microsoft.com/.default"},
	})
	if resp.StatusCode != 401 || body["error"] != "invalid_client" {
		t.Fatalf("wrong key: want 401 invalid_client, got %d %v", resp.StatusCode, body)
	}
}

func TestClientAssertionExpired(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	priv := registerKey(t, hts.URL, daemonID)
	aud := cfg.Origins.Login + "/" + tenant + "/oauth2/v2.0/token"
	assertion := signAssertion(t, priv, "k1", daemonID, aud, 1_000_000_000) // long past

	resp, body := postForm(t, http.DefaultClient, tokenEndpoint(hts.URL), url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {daemonID},
		"client_assertion_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"client_assertion":      {assertion},
		"scope":                 {"https://graph.microsoft.com/.default"},
	})
	if resp.StatusCode != 401 || body["error"] != "invalid_client" {
		t.Fatalf("expired assertion: want 401 invalid_client, got %d %v", resp.StatusCode, body)
	}
}

func TestClientAssertionWrongAudience(t *testing.T) {
	hts, _, _ := newTestServer(t)
	priv := registerKey(t, hts.URL, daemonID)
	assertion := signAssertion(t, priv, "k1", daemonID, "https://wrong.example/token", 0)

	resp, body := postForm(t, http.DefaultClient, tokenEndpoint(hts.URL), url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {daemonID},
		"client_assertion_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"client_assertion":      {assertion},
		"scope":                 {"https://graph.microsoft.com/.default"},
	})
	if resp.StatusCode != 401 || body["error"] != "invalid_client" {
		t.Fatalf("wrong audience: want 401 invalid_client, got %d %v", resp.StatusCode, body)
	}
}

func TestClientAssertionNoRegisteredKey(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	// No key registered on the SPA; a self-signed assertion must be rejected.
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	aud := cfg.Origins.Login + "/" + tenant + "/oauth2/v2.0/token"
	assertion := signAssertion(t, priv, "k1", spaID, aud, 0)

	resp, body := postForm(t, http.DefaultClient, tokenEndpoint(hts.URL), url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {spaID},
		"client_assertion_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"client_assertion":      {assertion},
		"scope":                 {"https://graph.microsoft.com/.default"},
	})
	if resp.StatusCode != 401 || body["error"] != "invalid_client" {
		t.Fatalf("no registered key: want 401 invalid_client, got %d %v", resp.StatusCode, body)
	}
}
