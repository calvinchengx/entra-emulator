package tokens

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// signWith builds a compact JWS with an arbitrary header alg, so the verifier's
// alg handling can be tested directly rather than inferred.
func signWith(t *testing.T, key *rsa.PrivateKey, alg string, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]any{"typ": "JWT", "alg": alg})
	payload, _ := json.Marshal(claims)
	input := b64(header) + "." + b64(payload)
	digest := sha256.Sum256([]byte(input))

	var sig []byte
	var err error
	switch alg {
	case "RS256":
		sig, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	case "PS256":
		sig, err = rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:],
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	case "HS256":
		// The classic confusion attack: sign symmetrically using the PUBLIC key
		// bytes as the shared secret. A verifier that trusted the header's alg
		// blindly would accept this from anyone who can read the public key.
		pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
		m := hmac.New(sha256.New, pub)
		m.Write([]byte(input))
		sig = m.Sum(nil)
	case "none":
		sig = nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// TestVerifyClientJWSAlgorithms covers what the emulator ACCEPTS from a client.
// PS256 is not optional: MSAL Go signs client assertions with it by default, so
// an RS256-only verifier rejects Microsoft's own Go client.
func TestVerifyClientJWSAlgorithms(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"iss": "client", "sub": "client"}

	t.Run("RS256 verifies", func(t *testing.T) {
		got, err := VerifyClientJWS(&key.PublicKey, signWith(t, key, "RS256", claims))
		if err != nil {
			t.Fatalf("RS256 rejected: %v", err)
		}
		if got["iss"] != "client" {
			t.Fatalf("claims not returned: %v", got)
		}
	})

	t.Run("PS256 verifies — MSAL Go's default", func(t *testing.T) {
		got, err := VerifyClientJWS(&key.PublicKey, signWith(t, key, "PS256", claims))
		if err != nil {
			t.Fatalf("PS256 rejected: %v", err)
		}
		if got["sub"] != "client" {
			t.Fatalf("claims not returned: %v", got)
		}
	})

	t.Run("a signature from a different key is refused", func(t *testing.T) {
		other, _ := rsa.GenerateKey(rand.Reader, 2048)
		for _, alg := range []string{"RS256", "PS256"} {
			if _, err := VerifyClientJWS(&key.PublicKey, signWith(t, other, alg, claims)); err == nil {
				t.Errorf("%s: a token signed by an unrelated key was accepted", alg)
			}
		}
	})

	// Widening the accepted algs must not widen them to the dangerous ones.
	t.Run("none and HMAC algs are refused", func(t *testing.T) {
		for _, alg := range []string{"none", "HS256", "RS512", ""} {
			_, err := VerifyClientJWS(&key.PublicKey, signWith(t, key, alg, claims))
			if err == nil {
				t.Errorf("alg %q was accepted", alg)
				continue
			}
			if !strings.Contains(err.Error(), "unsupported") {
				t.Errorf("alg %q: want an unsupported-alg error, got %v", alg, err)
			}
		}
	})
}
