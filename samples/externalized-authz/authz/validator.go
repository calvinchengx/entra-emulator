package authz

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// TokenValidator verifies emulator-issued RS256 access tokens against the
// tenant's JWKS. This is the "authentication" half of the pattern — it answers
// "who is the caller and is the token genuine?", never "may they do X?" (that
// is the PDP's job). Keep the two strictly separate.
type TokenValidator struct {
	JWKSURL  string
	Issuer   string   // expected iss
	Audience string   // expected aud (this resource's identifier)
	Client   *http.Client
	Now      func() time.Time // injectable clock (defaults to time.Now)

	mu   sync.Mutex
	keys map[string]*rsa.PublicKey // kid -> key, lazily fetched
}

// Claims is the validated subset the resource server acts on.
type Claims struct {
	OID    string   // stable user object id (the subject principal)
	Sub    string   // pairwise subject
	Scopes []string // scp values (delegated)
	Groups []string // group object ids from the groups claim
	Raw    map[string]any
}

func (v *TokenValidator) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *TokenValidator) client() *http.Client {
	if v.Client != nil {
		return v.Client
	}
	return http.DefaultClient
}

// Validate parses and verifies a bearer token, returning its claims or an error.
func (v *TokenValidator) Validate(bearer string) (*Claims, error) {
	parts := strings.Split(bearer, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed token")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &hdr); err != nil {
		return nil, fmt.Errorf("bad header: %w", err)
	}
	if hdr.Alg != "RS256" {
		return nil, fmt.Errorf("unexpected alg %q", hdr.Alg)
	}

	key, err := v.keyForKid(hdr.Kid)
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("bad signature encoding: %w", err)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	var raw map[string]any
	if err := decodeSegment(parts[1], &raw); err != nil {
		return nil, fmt.Errorf("bad payload: %w", err)
	}
	if err := v.checkStandardClaims(raw); err != nil {
		return nil, err
	}
	return toClaims(raw), nil
}

func (v *TokenValidator) checkStandardClaims(raw map[string]any) error {
	if iss, _ := raw["iss"].(string); iss != v.Issuer {
		return fmt.Errorf("issuer mismatch: %q", iss)
	}
	if !audienceMatches(raw["aud"], v.Audience) {
		return fmt.Errorf("audience mismatch: %v", raw["aud"])
	}
	now := v.now().Unix()
	if exp, ok := raw["exp"].(float64); ok && now >= int64(exp) {
		return fmt.Errorf("token expired")
	}
	if nbf, ok := raw["nbf"].(float64); ok && now < int64(nbf) {
		return fmt.Errorf("token not yet valid")
	}
	return nil
}

func (v *TokenValidator) keyForKid(kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	if k := v.keys[kid]; k != nil {
		v.mu.Unlock()
		return k, nil
	}
	v.mu.Unlock()

	if err := v.refreshKeys(); err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if k := v.keys[kid]; k != nil {
		return k, nil
	}
	return nil, fmt.Errorf("no JWKS key for kid %q", kid)
}

// refreshKeys fetches the JWKS and rebuilds the kid→key cache. Called on a
// cache miss so key rotation is picked up automatically.
func (v *TokenValidator) refreshKeys() error {
	resp, err := v.client().Get(v.JWKSURL)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return fmt.Errorf("decode JWKS: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		eb := make([]byte, 8)
		copy(eb[8-len(eBytes):], eBytes)
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(binary.BigEndian.Uint64(eb))}
	}
	v.mu.Lock()
	v.keys = keys
	v.mu.Unlock()
	return nil
}

func decodeSegment(seg string, into any) error {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, into)
}

func audienceMatches(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		for _, x := range a {
			if s, _ := x.(string); s == want {
				return true
			}
		}
	}
	return false
}

func toClaims(raw map[string]any) *Claims {
	c := &Claims{Raw: raw}
	c.OID, _ = raw["oid"].(string)
	c.Sub, _ = raw["sub"].(string)
	if scp, ok := raw["scp"].(string); ok {
		c.Scopes = strings.Fields(scp)
	}
	if groups, ok := raw["groups"].([]any); ok {
		for _, g := range groups {
			if s, _ := g.(string); s != "" {
				c.Groups = append(c.Groups, s)
			}
		}
	}
	return c
}
