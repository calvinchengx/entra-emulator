package server

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// verifyAgainstJWKS fetches the tenant's JWKS, finds the key matching the
// token header's kid, and verifies the RS256 signature. It fails the test if
// the token does not verify, proving per-tenant signing keys are real.
func verifyAgainstJWKS(t *testing.T, origin, tenantSeg, jwt string) {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", jwt)
	}
	var hdr struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	rawHdr, _ := base64.RawURLEncoding.DecodeString(parts[0])
	_ = json.Unmarshal(rawHdr, &hdr)

	resp, err := http.Get(origin + "/" + tenantSeg + "/discovery/v2.0/keys")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&set)

	var pub *rsa.PublicKey
	for _, k := range set.Keys {
		if k.Kid != hdr.Kid {
			continue
		}
		nBytes, _ := base64.RawURLEncoding.DecodeString(k.N)
		eBytes, _ := base64.RawURLEncoding.DecodeString(k.E)
		eb := make([]byte, 8)
		copy(eb[8-len(eBytes):], eBytes)
		pub = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(binary.BigEndian.Uint64(eb))}
		break
	}
	if pub == nil {
		t.Fatalf("kid %q not published in tenant %s JWKS", hdr.Kid, tenantSeg)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("token failed to verify against tenant %s JWKS: %v", tenantSeg, err)
	}
}

// TestMultiTenantIsolation exercises roadmap #15b: a second tenant with its
// own tid, GUID-form issuer, and signing key, isolated from the home tenant.
func TestMultiTenantIsolation(t *testing.T) {
	hts := func() string { h, _, _ := newTestServer(t); return h.URL }()

	// --- Home tenant is unchanged: CC token carries the home tid/issuer. ---
	_, homeBody := postForm(t, http.DefaultClient, hts+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type": {"client_credentials"}, "client_id": {daemonID},
		"client_secret": {store.SeedDaemonSecret}, "scope": {"https://graph.microsoft.com/.default"},
	})
	homeTok, _ := homeBody["access_token"].(string)
	if homeTok == "" {
		t.Fatalf("home CC failed: %v", homeBody)
	}
	homeClaims := decodeJWTPayload(t, homeTok)
	if homeClaims["tid"] != tenant {
		t.Fatalf("home tid = %v, want %s", homeClaims["tid"], tenant)
	}
	verifyAgainstJWKS(t, hts, tenant, homeTok)

	// --- Create tenant B with gofakeit-generated metadata. ---
	status, tb := postJSON(t, hts+"/admin/api/tenants", map[string]any{"displayName": "Contoso Manufacturing"})
	if status != 201 {
		t.Fatalf("create tenant: %d %v", status, tb)
	}
	tidB, _ := tb["id"].(string)
	if tidB == "" || tidB == tenant {
		t.Fatalf("tenant B id invalid: %v", tb)
	}
	domain, _ := tb["initialDomain"].(string)
	if !strings.HasSuffix(domain, ".onmicrosoft.com") {
		t.Fatalf("initialDomain %q is not an onmicrosoft.com domain", domain)
	}
	if iss, _ := tb["issuer"].(string); !strings.HasSuffix(iss, "/"+tidB+"/v2.0") {
		t.Fatalf("tenant B issuer %q not GUID-form for %s", iss, tidB)
	}
	if isHome, _ := tb["isHome"].(bool); isHome {
		t.Fatal("tenant B should not be flagged home")
	}

	// --- Register a confidential app in tenant B and give it a secret. ---
	status, appB := postJSON(t, hts+"/admin/api/apps", map[string]any{
		"displayName": "B Daemon", "tenantId": tidB, "isConfidential": true,
	})
	if status != 201 {
		t.Fatalf("create app in B: %d %v", status, appB)
	}
	appBID, _ := appB["id"].(string)
	status, secretResp := postJSON(t, hts+"/admin/api/apps/"+appBID+"/secrets", map[string]any{"displayName": "cc"})
	if status != 201 {
		t.Fatalf("add secret: %d %v", status, secretResp)
	}
	secretB, _ := secretResp["secretText"].(string)

	// --- client_credentials in tenant B → tid=B, iss=B, B's signing key. ---
	resp, ccB := postForm(t, http.DefaultClient, hts+"/"+tidB+"/oauth2/v2.0/token", url.Values{
		"grant_type": {"client_credentials"}, "client_id": {appBID},
		"client_secret": {secretB}, "scope": {"https://graph.microsoft.com/.default"},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("CC in tenant B: %d %v", resp.StatusCode, ccB)
	}
	tokB, _ := ccB["access_token"].(string)
	claimsB := decodeJWTPayload(t, tokB)
	if claimsB["tid"] != tidB {
		t.Fatalf("tenant B tid = %v, want %s", claimsB["tid"], tidB)
	}
	if iss, _ := claimsB["iss"].(string); !strings.HasSuffix(iss, "/"+tidB+"/v2.0") {
		t.Fatalf("tenant B token iss = %q, want GUID-form for %s", iss, tidB)
	}
	verifyAgainstJWKS(t, hts, tidB, tokB)

	// Tenant B's signing key is distinct from home's.
	if kidB, kidHome := jwtHeaderKid(t, tokB), jwtHeaderKid(t, homeTok); kidB == kidHome {
		t.Fatalf("tenant B reused the home signing key %s", kidB)
	}

	// Isolation: the home signing key must not appear in tenant B's JWKS.
	if bKids := tenantKids(t, hts, tidB); contains(bKids, jwtHeaderKid(t, homeTok)) {
		t.Fatal("home signing key leaked into tenant B JWKS")
	}

	// --- Unknown tenant is rejected at discovery. ---
	if r, _ := http.Get(hts + "/" + store.NewGUID() + "/v2.0/.well-known/openid-configuration"); r.StatusCode != 404 {
		t.Fatalf("unknown tenant discovery: want 404, got %d", r.StatusCode)
	}

	// --- Deleting tenant B removes it; home cannot be deleted. ---
	if code := deleteStatus(t, hts+"/admin/api/tenants/"+tidB); code != 204 {
		t.Fatalf("delete tenant B: want 204, got %d", code)
	}
	if r, _ := http.Get(hts + "/" + tidB + "/v2.0/.well-known/openid-configuration"); r.StatusCode != 404 {
		t.Fatalf("deleted tenant discovery: want 404, got %d", r.StatusCode)
	}
	if code := deleteStatus(t, hts+"/admin/api/tenants/"+tenant); code != 400 {
		t.Fatalf("home tenant delete: want 400, got %d", code)
	}
}

func tenantKids(t *testing.T, origin, tenantSeg string) []string {
	t.Helper()
	resp, err := http.Get(origin + "/" + tenantSeg + "/discovery/v2.0/keys")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&set)
	out := make([]string, 0, len(set.Keys))
	for _, k := range set.Keys {
		out = append(out, k.Kid)
	}
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func deleteStatus(t *testing.T, url string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodDelete, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}
