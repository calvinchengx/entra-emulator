package server

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// fakeIssuer is a stand-in for an external OIDC provider — GitHub Actions,
// a Kubernetes API server, another cloud. It publishes real discovery + JWKS
// documents and signs real RS256 tokens, so the emulator's federation path
// verifies a genuine signature against genuinely fetched keys.
type fakeIssuer struct {
	*httptest.Server
	key *rsa.PrivateKey
	kid string
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fi := &fakeIssuer{key: key, kid: "ext-key-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   fi.URL,
			"jwks_uri": fi.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{"kty": "RSA", "use": "sig", "kid": fi.kid, "n": n, "e": e}},
		})
	})
	fi.Server = httptest.NewServer(mux)
	t.Cleanup(fi.Close)
	return fi
}

// mint signs a workload token the way an external IdP would.
func (fi *fakeIssuer) mint(t *testing.T, sub, aud string, exp int64) string {
	t.Helper()
	tok, err := tokens.SignRS256(fi.key, fi.kid, map[string]any{
		"iss": fi.URL, "sub": sub, "aud": aud, "exp": exp, "iat": exp - 600,
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// exchange presents a federated assertion at the token endpoint.
func exchange(t *testing.T, hts, clientID, assertion string) (int, map[string]any) {
	t.Helper()
	resp, body := postForm(t, http.DefaultClient, hts+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {clientID},
		"scope":                 {"https://graph.microsoft.com/.default"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion},
	})
	return resp.StatusCode, body
}

// TestWorkloadIdentityFederation covers the whole point of WIF: an external
// workload authenticates with NO stored secret, and the emulator really
// verifies the assertion against the external issuer's published keys.
func TestWorkloadIdentityFederation(t *testing.T) {
	hts, _, st := newTestServer(t)
	iss := newFakeIssuer(t)
	subject := "repo:calvinchengx/entra-emulator:ref:refs/heads/main"
	now := st.Now()

	// Register the trust the way a platform team would.
	code, cred := postJSON(t, hts.URL+"/admin/api/apps/"+daemonID+"/federated-credentials",
		map[string]any{
			"name": "github-main", "issuer": iss.URL, "subject": subject,
			"audiences": []string{store.DefaultFederatedAudience},
		})
	if code != http.StatusCreated {
		t.Fatalf("register federated credential: %d %v", code, cred)
	}

	t.Run("external token exchanges for an emulator token", func(t *testing.T) {
		assertion := iss.mint(t, subject, store.DefaultFederatedAudience, now+600)
		status, body := exchange(t, hts.URL, daemonID, assertion)
		if status != http.StatusOK {
			t.Fatalf("federated exchange: want 200, got %d %v", status, body)
		}
		access, _ := body["access_token"].(string)
		if access == "" {
			t.Fatalf("no access_token in response: %v", body)
		}
		// The minted token is a normal app-only token for the app.
		claims := decodeJWTPayload(t, access)
		if claims["appid"] != daemonID && claims["azp"] != daemonID {
			t.Fatalf("token not issued to the federated app: %v", claims)
		}
		if claims["oid"] != nil && claims["idtyp"] != "app" {
			t.Logf("claims: %v", claims) // app-only shape is asserted elsewhere
		}
	})

	t.Run("a different subject is refused", func(t *testing.T) {
		assertion := iss.mint(t, "repo:someone/else:ref:refs/heads/main", store.DefaultFederatedAudience, now+600)
		status, body := exchange(t, hts.URL, daemonID, assertion)
		if status == http.StatusOK {
			t.Fatalf("an unregistered subject must not authenticate: %v", body)
		}
		if body["error"] != "invalid_client" {
			t.Fatalf("want invalid_client, got %v", body)
		}
	})

	t.Run("a wrong audience is refused", func(t *testing.T) {
		assertion := iss.mint(t, subject, "api://SomethingElse", now+600)
		if status, body := exchange(t, hts.URL, daemonID, assertion); status == http.StatusOK {
			t.Fatalf("a mismatched audience must not authenticate: %v", body)
		}
	})

	t.Run("an expired assertion is refused", func(t *testing.T) {
		assertion := iss.mint(t, subject, store.DefaultFederatedAudience, now-60)
		if status, body := exchange(t, hts.URL, daemonID, assertion); status == http.StatusOK {
			t.Fatalf("an expired assertion must not authenticate: %v", body)
		}
	})

	t.Run("a forged signature is refused", func(t *testing.T) {
		// Same claims, signed by a key the issuer does not publish — this is the
		// assertion that must fail, or federation is decorative.
		rogue := newFakeIssuer(t)
		forged, err := tokens.SignRS256(rogue.key, iss.kid, map[string]any{
			"iss": iss.URL, "sub": subject,
			"aud": store.DefaultFederatedAudience, "exp": now + 600,
		})
		if err != nil {
			t.Fatal(err)
		}
		status, body := exchange(t, hts.URL, daemonID, forged)
		if status == http.StatusOK {
			t.Fatalf("a forged signature must not authenticate: %v", body)
		}
	})

	t.Run("revoking the credential revokes the access", func(t *testing.T) {
		id, _ := cred["id"].(string)
		if code := deleteStatus(t, hts.URL+"/admin/api/apps/"+daemonID+"/federated-credentials/"+id); code != http.StatusNoContent {
			t.Fatalf("delete credential: %d", code)
		}
		assertion := iss.mint(t, subject, store.DefaultFederatedAudience, now+600)
		if status, body := exchange(t, hts.URL, daemonID, assertion); status == http.StatusOK {
			t.Fatalf("a deleted credential must stop authenticating: %v", body)
		}
	})
}
