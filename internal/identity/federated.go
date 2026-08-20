package identity

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// Workload identity federation. A workload running somewhere else (a GitHub
// Actions job, a Kubernetes pod, another cloud) already holds an OIDC token
// from ITS OWN issuer. Rather than store an Entra secret next to it, the app
// registers a federated credential naming that issuer + subject, and the
// workload presents its external token as the client_assertion. Entra verifies
// the token against the EXTERNAL issuer's JWKS and mints an app-only token.
//
// That is what makes this worth emulating: the whole point is that no secret
// exists, so a test that stubs it out tests nothing. Here the signature really
// is verified against keys fetched from the issuer's published JWKS.

// federationHTTP fetches external issuer metadata. Short timeout: an
// unreachable issuer must fail the exchange quickly, not hang the token
// endpoint.
var federationHTTP = &http.Client{Timeout: 5 * time.Second}

// issuerKeyCache memoises issuer -> kid -> key, refreshed on an unknown kid so
// external key rotation is picked up without a restart.
type issuerKeyCache struct {
	mu   sync.Mutex
	keys map[string]map[string]*rsa.PublicKey
}

var extKeys = &issuerKeyCache{keys: map[string]map[string]*rsa.PublicKey{}}

func (c *issuerKeyCache) get(issuer, kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	if k := c.keys[issuer][kid]; k != nil {
		c.mu.Unlock()
		return k, nil
	}
	c.mu.Unlock()

	fetched, err := fetchIssuerKeys(issuer)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.keys[issuer] = fetched
	c.mu.Unlock()

	if k := fetched[kid]; k != nil {
		return k, nil
	}
	return nil, fmt.Errorf("issuer %q publishes no key with kid %q", issuer, kid)
}

// fetchIssuerKeys resolves the issuer's discovery document, then its JWKS.
func fetchIssuerKeys(issuer string) (map[string]*rsa.PublicKey, error) {
	disco := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	resp, err := federationHTTP.Get(disco)
	if err != nil {
		return nil, fmt.Errorf("fetch issuer metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("issuer metadata returned %d", resp.StatusCode)
	}
	var meta struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil || meta.JWKSURI == "" {
		return nil, fmt.Errorf("issuer metadata has no jwks_uri")
	}

	jresp, err := federationHTTP.Get(meta.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf("fetch issuer JWKS: %w", err)
	}
	defer jresp.Body.Close()
	if jresp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("issuer JWKS returned %d", jresp.StatusCode)
	}
	var set struct {
		Keys []struct{ Kid, Kty, N, E string } `json:"keys"`
	}
	if err := json.NewDecoder(jresp.Body).Decode(&set); err != nil {
		return nil, fmt.Errorf("decode issuer JWKS: %w", err)
	}
	out := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" {
			continue
		}
		nb, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eb, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		padded := make([]byte, 8)
		copy(padded[8-len(eb):], eb)
		out[k.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nb),
			E: int(binary.BigEndian.Uint64(padded)),
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("issuer JWKS contains no usable RSA keys")
	}
	return out, nil
}

// isFederatedAssertion reports whether an assertion looks like an EXTERNAL
// workload token rather than the app's own private_key_jwt. Entra's own rule:
// a client assertion is self-issued (iss == sub == client_id); anything else is
// a federated credential presentation.
func isFederatedAssertion(claims map[string]any, appID string) bool {
	iss, _ := claims["iss"].(string)
	sub, _ := claims["sub"].(string)
	return iss != appID || sub != appID
}

// verifyFederatedAssertion authenticates an app via workload identity
// federation: match a registered credential on issuer/subject/audience, then
// verify the assertion's signature against that issuer's published keys.
func (i *Identity) verifyFederatedAssertion(app *store.App, assertion string, claims map[string]any) *httpx.OAuthError {
	iss, _ := claims["iss"].(string)
	sub, _ := claims["sub"].(string)
	if iss == "" || sub == "" {
		return &httpx.OAuthError{Error: "invalid_client",
			ErrorDescription: "AADSTS700213: The federated assertion is missing iss or sub."}
	}

	// aud may be a string or an array; any one match is enough.
	var auds []string
	switch a := claims["aud"].(type) {
	case string:
		auds = []string{a}
	case []any:
		for _, v := range a {
			if s, ok := v.(string); ok {
				auds = append(auds, s)
			}
		}
	}

	var cred *store.FederatedCredential
	for _, aud := range auds {
		c, err := i.Store.MatchFederatedCredential(app.ID, iss, sub, aud)
		if err == nil {
			cred = c
			break
		}
	}
	if cred == nil {
		return &httpx.OAuthError{Error: "invalid_client",
			ErrorDescription: "AADSTS700213: No matching federated identity record found for " +
				"issuer '" + iss + "' and subject '" + sub + "'."}
	}

	// Signature against the EXTERNAL issuer's keys — the step that makes this
	// federation rather than a claim anyone could assert.
	kid, err := assertionKid(assertion)
	if err != nil {
		return &httpx.OAuthError{Error: "invalid_client",
			ErrorDescription: "AADSTS700213: " + err.Error()}
	}
	key, err := extKeys.get(iss, kid)
	if err != nil {
		return &httpx.OAuthError{Error: "invalid_client",
			ErrorDescription: "AADSTS700213: Could not validate against the issuer's keys: " + err.Error()}
	}
	verified, err := tokens.VerifyRS256(key, assertion)
	if err != nil {
		return &httpx.OAuthError{Error: "invalid_client",
			ErrorDescription: "AADSTS700213: Federated assertion signature validation failed."}
	}

	now := i.Store.Now()
	if exp, ok := verified["exp"].(float64); ok && now >= int64(exp) {
		return &httpx.OAuthError{Error: "invalid_client",
			ErrorDescription: "AADSTS700213: The federated assertion has expired."}
	}
	if nbf, ok := verified["nbf"].(float64); ok && now < int64(nbf) {
		return &httpx.OAuthError{Error: "invalid_client",
			ErrorDescription: "AADSTS700213: The federated assertion is not yet valid."}
	}
	return nil
}

// assertionKid reads the `kid` from a compact JWS header.
func assertionKid(assertion string) (string, error) {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("malformed assertion")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("malformed assertion header")
	}
	var h struct{ Kid, Alg string }
	if err := json.Unmarshal(raw, &h); err != nil {
		return "", fmt.Errorf("malformed assertion header")
	}
	if h.Alg != "RS256" {
		return "", fmt.Errorf("unsupported assertion alg %q", h.Alg)
	}
	return h.Kid, nil
}
