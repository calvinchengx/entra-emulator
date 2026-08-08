package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// registerAppKey generates a keypair, registers the public half on the app, and
// returns the private key for signing request objects.
func registerAppKey(t *testing.T, hts, appID string) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if code, body := postJSON(t, hts+"/admin/api/apps/"+appID+"/keyCredentials",
		map[string]any{"publicKey": pubPEM, "displayName": "jar"}); code != http.StatusCreated {
		t.Fatalf("register app key: %d %v", code, body)
	}
	return key
}

// TestRequestObjectJAR covers JAR by reference (RFC 9101). The load-bearing
// property is the SSRF guard: an authorize endpoint that fetches a
// caller-supplied URL must only reach origins the tenant already trusted.
func TestRequestObjectJAR(t *testing.T) {
	hts, _, _ := newTestServer(t)
	key := registerAppKey(t, hts.URL, spaID)

	sign := func(t *testing.T, claims map[string]any) string {
		t.Helper()
		obj, err := tokens.SignRS256(key, "jar-key", claims)
		if err != nil {
			t.Fatal(err)
		}
		return obj
	}

	// The SPA's registered redirect URI is https://localhost:3000, so only that
	// ORIGIN may host a request object. httptest gives us a different one.
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(sign(t, map[string]any{
			"iss": spaID, "response_type": "code", "scope": "openid",
			"redirect_uri": redirect, "state": "from-object",
		})))
	}))
	defer foreign.Close()

	authorizeGET := func(t *testing.T, q url.Values) (int, string) {
		t.Helper()
		resp, err := noRedirectJar().Get(hts.URL + "/" + tenant + "/oauth2/v2.0/authorize?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body := make([]byte, 2048)
		n, _ := resp.Body.Read(body)
		return resp.StatusCode, string(body[:n])
	}

	t.Run("a request_uri off an untrusted origin is refused", func(t *testing.T) {
		status, body := authorizeGET(t, url.Values{
			"client_id": {spaID}, "request_uri": {foreign.URL + "/obj"},
		})
		if status != http.StatusBadRequest {
			t.Fatalf("untrusted origin must be refused, got %d", status)
		}
		if !strings.Contains(body, "registered redirect-URI origin") {
			t.Errorf("the refusal should name the reason, got: %s", body)
		}
	})

	// The positive case. Without it, every assertion above would still pass if
	// the feature simply refused everything — so trust the ORIGIN by
	// registering it as a redirect URI, and prove the object is really applied.
	t.Run("a trusted origin is fetched and its parameters take effect", func(t *testing.T) {
		if code, body := postJSON(t, hts.URL+"/admin/api/apps/"+spaID+"/redirectUris",
			map[string]any{"uri": foreign.URL + "/cb", "type": "web"}); code != http.StatusCreated {
			t.Fatalf("register redirect uri: %d %v", code, body)
		}
		// Nothing but client_id and request_uri on the wire: every other
		// parameter has to come from inside the signed object.
		status, body := authorizeGET(t, url.Values{
			"client_id": {spaID}, "request_uri": {foreign.URL + "/obj"},
		})
		if status == http.StatusBadRequest {
			t.Fatalf("a trusted origin must be fetched, got 400: %s", body)
		}
		// The object named state=from-object, so seeing it proves the object's
		// parameters were applied rather than defaulted.
		if !strings.Contains(body, "from-object") && !strings.Contains(body, "__ee_state") {
			t.Fatalf("the request object's parameters were not applied: %d %s", status, body)
		}
	})

	t.Run("inline request is refused — Entra does not advertise it", func(t *testing.T) {
		obj := sign(t, map[string]any{"iss": spaID, "response_type": "code"})
		status, body := authorizeGET(t, url.Values{"client_id": {spaID}, "request": {obj}})
		if status != http.StatusBadRequest || !strings.Contains(body, "not supported") {
			t.Fatalf("inline request must be refused, got %d %s", status, body)
		}
	})

	t.Run("discovery advertises request_uri, not request", func(t *testing.T) {
		_, doc := getJSON(t, hts.URL+"/"+tenant+"/v2.0/.well-known/openid-configuration")
		if doc["request_uri_parameter_supported"] != true {
			t.Errorf("request_uri_parameter_supported should be advertised")
		}
		if _, present := doc["request_parameter_supported"]; present {
			t.Errorf("request_parameter_supported must stay absent, as in real Entra")
		}
	})

	t.Run("a request_uri with no client_id is refused", func(t *testing.T) {
		// Without it there is no app whose origins could authorise the fetch.
		if status, _ := authorizeGET(t, url.Values{"request_uri": {foreign.URL + "/obj"}}); status != http.StatusBadRequest {
			t.Fatalf("request_uri without client_id must be refused, got %d", status)
		}
	})
}
