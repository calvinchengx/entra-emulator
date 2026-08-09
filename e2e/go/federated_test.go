// Workload identity federation, driven by azidentity's ClientAssertionCredential.
//
// The point of WIF is that NO SECRET EXISTS: a workload elsewhere already holds
// an OIDC token from its own issuer, and presents that instead. So the test
// stands up a real external issuer — its own RSA key, its own discovery
// document, its own JWKS — and the emulator must fetch those keys and verify
// the signature against them. A test that stubbed the issuer would be asserting
// that we trust ourselves.
package e2e

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/calvinchengx/entra-emulator/emulator"
)

const federationAudience = "api://AzureADTokenExchange"

func policyTokenRequest(scope string) policy.TokenRequestOptions {
	return policy.TokenRequestOptions{Scopes: []string{scope}}
}

// containsAll reports whether s contains every substring — used so a refutation
// asserts WHY it failed, not merely that it did.
func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

// externalIssuer is a minimal OIDC issuer: discovery + JWKS + a signer. Plain
// HTTP because the emulator fetches issuer metadata with its own client, which
// trusts the public roots rather than the emulator's cert.
type externalIssuer struct {
	srv *httptest.Server
	key *rsa.PrivateKey
	kid string
}

func newExternalIssuer(t *testing.T) *externalIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ei := &externalIssuer{key: key, kid: "ext-key-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   ei.srv.URL,
			"jwks_uri": ei.srv.URL + "/keys",
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA", "use": "sig", "alg": "RS256", "kid": ei.kid, "n": n, "e": e,
			}},
		})
	})
	ei.srv = httptest.NewServer(mux)
	t.Cleanup(ei.srv.Close)
	return ei
}

// mintAs signs an RS256 assertion with THIS issuer's key while claiming `iss`.
// Passing another issuer's URL is how the forgery case is built: a well-formed
// token naming the trusted issuer, signed by a key that issuer never published.
func (ei *externalIssuer) mintAs(t *testing.T, issuer, subject, audience string) string {
	t.Helper()
	now := time.Now().Unix()
	header, _ := json.Marshal(map[string]any{"typ": "JWT", "alg": "RS256", "kid": ei.kid})
	payload, _ := json.Marshal(map[string]any{
		"iss": issuer, "sub": subject, "aud": audience,
		"iat": now, "nbf": now, "exp": now + 600, "jti": "e2e-assertion",
	})
	b64 := base64.RawURLEncoding.EncodeToString
	input := b64(header) + "." + b64(payload)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, ei.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64(sig)
}

// federatedCred registers the trust on the app, over Graph.
func federatedCred(t *testing.T, emu *emulator.Emulator, tok, appID, issuer, subject string) {
	t.Helper()
	graphPost(t, emu, tok, "/applications/"+appID+"/federatedIdentityCredentials", map[string]any{
		"name": "e2e-workload", "issuer": issuer, "subject": subject,
		"audiences": []string{federationAudience},
	})
}

// assertionCredential builds azidentity's ClientAssertionCredential pointed at
// the emulator. This is Microsoft's own client: it decides the grant shape,
// the client_assertion_type, and how the assertion is carried.
func assertionCredential(t *testing.T, emu *emulator.Emulator, assertion string) *azidentity.ClientAssertionCredential {
	t.Helper()
	cred, err := azidentity.NewClientAssertionCredential(
		emulator.TenantID, emulator.DaemonClientID,
		func(context.Context) (string, error) { return assertion, nil },
		&azidentity.ClientAssertionCredentialOptions{
			ClientOptions: azcore.ClientOptions{
				Transport: emu.HTTPClient(),
				Cloud: cloud.Configuration{
					ActiveDirectoryAuthorityHost: emu.Origin,
					Services:                     map[cloud.ServiceName]cloud.ServiceConfiguration{},
				},
			},
			DisableInstanceDiscovery: true,
		})
	if err != nil {
		t.Fatal(err)
	}
	return cred
}

func TestAzidentityWorkloadIdentityFederation(t *testing.T) {
	emu := emulator.StartT(t, emulator.WithTLS())
	tok := graphToken(t, emu)
	ext := newExternalIssuer(t)

	const subject = "repo:contoso/widgets:ref:refs/heads/main"
	federatedCred(t, emu, tok, emulator.DaemonClientID, ext.srv.URL, subject)

	scope := "api://" + emulator.DaemonClientID + "/.default"

	t.Run("a federated assertion mints an app-only token", func(t *testing.T) {
		cred := assertionCredential(t, emu, ext.mintAs(t, ext.srv.URL, subject, federationAudience))
		out, err := cred.GetToken(context.Background(),
			policyTokenRequest(scope))
		if err != nil {
			t.Fatalf("azidentity could not exchange the federated assertion: %v", err)
		}
		claims := oboClaims(t, out.Token)
		if claims["appid"] != emulator.DaemonClientID {
			t.Errorf("appid = %v, want the federated app", claims["appid"])
		}
		// App-only: no user was involved anywhere in this flow.
		if _, hasOID := claims["oid"]; hasOID {
			t.Errorf("federated token carries oid %v — it should be app-only", claims["oid"])
		}
	})

	// The subject is the whole access-control decision: it names WHICH workload
	// at that issuer may act as this app. A different branch is a different
	// subject, and must not be accepted.
	t.Run("a different subject at the same issuer is refused", func(t *testing.T) {
		cred := assertionCredential(t, emu,
			ext.mintAs(t, ext.srv.URL, "repo:contoso/widgets:ref:refs/heads/attacker", federationAudience))
		_, err := cred.GetToken(context.Background(), policyTokenRequest(scope))
		if err == nil {
			t.Fatal("an unregistered subject was accepted")
		}
		if !containsAll(err.Error(), "invalid_client", "No matching federated identity record") {
			t.Fatalf("refused, but not by the subject match: %v", err)
		}
	})

	// Signature verification against the issuer's published keys is what makes
	// this federation rather than an unverified claim. A well-formed assertion
	// from an impostor issuer key must not pass.
	t.Run("an assertion signed by a key the issuer never published is refused", func(t *testing.T) {
		impostor := newExternalIssuer(t)
		// Same iss/sub as the registered trust, different signing key.
		forged := impostor.mintAs(t, ext.srv.URL, subject, federationAudience)
		cred := assertionCredential(t, emu, forged)
		_, err := cred.GetToken(context.Background(), policyTokenRequest(scope))
		if err == nil {
			t.Fatal("an assertion signed by an unpublished key was accepted")
		}
		// Specifically by SIGNATURE. `invalid_client` alone would also be
		// returned by the subject check above, so asserting only that would let
		// this pass while signature verification was disabled entirely — the
		// one property this subtest exists to prove.
		if !containsAll(err.Error(), "invalid_client", "signature validation failed") {
			t.Fatalf("refused, but not by signature verification: %v", err)
		}
	})
}
