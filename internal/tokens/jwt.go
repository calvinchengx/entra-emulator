package tokens

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// SignRS256 builds a compact JWS over the given claims using the RS256
// algorithm, stamping the signing key id into the header.
func SignRS256(key *rsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	header := map[string]any{"typ": "JWT", "alg": "RS256", "kid": kid}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64(headerJSON) + "." + b64(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyRS256 checks a compact JWS signature against the public key and
// returns the decoded claims. It does not validate registered claims.
func VerifyRS256(pub *rsa.PublicKey, token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("jwt: malformed token")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("jwt: bad signature encoding: %w", err)
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return nil, fmt.Errorf("jwt: signature verification failed: %w", err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("jwt: bad payload encoding: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("jwt: bad payload JSON: %w", err)
	}
	return claims, nil
}

// DecodeUnverified returns the claims of a compact JWS without checking the
// signature. Callers must verify separately.
func DecodeUnverified(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("jwt: malformed token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
