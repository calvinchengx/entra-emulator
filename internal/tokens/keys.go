// Package tokens implements the emulator's token service: RSA signing keys,
// JWKS, Entra v2.0 claim assembly, and grant-artifact issuance/redemption
// (docs/07-token-service.md).
package tokens

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// publicJWK is the published RSA public key shape.
type publicJWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// Signer is the active signing key, parsed and ready to sign.
type Signer struct {
	Kid        string
	PrivateKey *rsa.PrivateKey
}

// EnsureActiveKey loads the tenant's active signing key, generating and
// persisting a fresh RSA-2048 key on first boot (stable kid thereafter).
func EnsureActiveKey(st *store.Store, tenantID string) (*Signer, error) {
	if k, err := st.GetActiveSigningKey(tenantID); err == nil {
		priv, err := parsePrivatePEM(k.PrivatePKCS8)
		if err != nil {
			return nil, fmt.Errorf("tokens: persisted key %s: %w", k.Kid, err)
		}
		return &Signer{Kid: k.Kid, PrivateKey: priv}, nil
	} else if err != store.ErrNotFound {
		return nil, err
	}

	return generateAndActivate(st, tenantID)
}

// generateAndActivate mints, persists (as the active key), and returns a fresh
// RSA-2048 signing key.
func generateAndActivate(st *store.Store, tenantID string) (*Signer, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("tokens: generate signing key: %w", err)
	}
	kid, jwkJSON, err := publicJWKFor(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err := st.InsertSigningKey(&store.SigningKey{
		Kid: kid, TenantID: tenantID, Alg: "RS256",
		PublicJWK: jwkJSON, PrivatePKCS8: pemStr, IsActive: true, CreatedAt: st.Now(),
	}); err != nil {
		return nil, err
	}
	return &Signer{Kid: kid, PrivateKey: priv}, nil
}

// publicJWKFor builds the published JWK and its RFC 7638 thumbprint kid.
func publicJWKFor(pub *rsa.PublicKey) (kid, jwkJSON string, err error) {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	// RFC 7638: thumbprint over the lexicographically-ordered required members.
	canonical := fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, e, n)
	sum := sha256.Sum256([]byte(canonical))
	kid = base64.RawURLEncoding.EncodeToString(sum[:])
	raw, err := json.Marshal(publicJWK{Kty: "RSA", Use: "sig", Alg: "RS256", Kid: kid, N: n, E: e})
	return kid, string(raw), err
}

// JWKS renders the JWK Set for the tenant (active + unexpired retired keys).
func JWKS(st *store.Store, tenantID string) ([]byte, error) {
	keys, err := st.ListPublishableKeys(tenantID, st.Now())
	if err != nil {
		return nil, err
	}
	set := struct {
		Keys []json.RawMessage `json:"keys"`
	}{Keys: []json.RawMessage{}}
	for _, k := range keys {
		set.Keys = append(set.Keys, json.RawMessage(k.PublicJWK))
	}
	return json.Marshal(set)
}

// VerificationKey resolves the RSA public key for a kid.
func VerificationKey(st *store.Store, kid string) (*rsa.PublicKey, error) {
	k, err := st.GetSigningKey(kid)
	if err != nil {
		return nil, err
	}
	var jwk publicJWK
	if err := json.Unmarshal([]byte(k.PublicJWK), &jwk); err != nil {
		return nil, err
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}, nil
}

func parsePrivatePEM(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("invalid private key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key")
	}
	return rsaKey, nil
}
