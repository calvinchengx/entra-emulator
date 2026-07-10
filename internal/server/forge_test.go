package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

// postJSON is a small helper for admin JSON calls.
func postJSON(t *testing.T, url string, body map[string]any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func graphMe(t *testing.T, origin, bearer string) int {
	t.Helper()
	req, _ := http.NewRequest("GET", origin+"/graph/v1.0/me", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestTokenForgeValidDelegated(t *testing.T) {
	hts, _, _ := newTestServer(t)

	// Default forge: a valid access token for Alice, Graph audience.
	status, body := postJSON(t, hts.URL+"/admin/api/tokens", map[string]any{
		"userId": aliceID,
		"scopes": []string{"User.Read"},
	})
	if status != 200 {
		t.Fatalf("forge: want 200, got %d %v", status, body)
	}
	token := body["token"].(string)
	claims := decodeJWTPayload(t, token)
	if claims["oid"] != aliceID || claims["scp"] != "User.Read" {
		t.Fatalf("unexpected forged claims: %v", claims)
	}
	// A forged valid token must be accepted by Graph.
	if code := graphMe(t, hts.URL, token); code != 200 {
		t.Fatalf("forged valid token rejected by Graph: %d", code)
	}
}

func TestTokenForgeExpired(t *testing.T) {
	hts, _, _ := newTestServer(t)

	status, body := postJSON(t, hts.URL+"/admin/api/tokens", map[string]any{
		"userId":           aliceID,
		"expiresInSeconds": -300, // expired 5 minutes ago
	})
	if status != 200 {
		t.Fatalf("forge: want 200, got %d %v", status, body)
	}
	claims := decodeJWTPayload(t, body["token"].(string))
	exp, iat := claims["exp"].(float64), claims["iat"].(float64)
	if exp >= iat {
		t.Fatalf("expected exp < iat for an expired token: exp=%v iat=%v", exp, iat)
	}
	// Graph must reject an expired token.
	if code := graphMe(t, hts.URL, body["token"].(string)); code != 401 {
		t.Fatalf("expired forged token: want 401, got %d", code)
	}
}

func TestTokenForgeWrongAudience(t *testing.T) {
	hts, _, _ := newTestServer(t)

	status, body := postJSON(t, hts.URL+"/admin/api/tokens", map[string]any{
		"userId":   aliceID,
		"audience": "api://some-other-resource",
	})
	if status != 200 {
		t.Fatalf("forge: %d %v", status, body)
	}
	// Graph accepts only its own audience.
	if code := graphMe(t, hts.URL, body["token"].(string)); code != 401 {
		t.Fatalf("wrong-audience forged token: want 401, got %d", code)
	}
}

func TestTokenForgeBadSignature(t *testing.T) {
	hts, _, _ := newTestServer(t)

	status, body := postJSON(t, hts.URL+"/admin/api/tokens", map[string]any{
		"userId":    aliceID,
		"signature": "invalid",
	})
	if status != 200 {
		t.Fatalf("forge: %d %v", status, body)
	}
	// The header keeps the real kid but the signature won't verify.
	if code := graphMe(t, hts.URL, body["token"].(string)); code != 401 {
		t.Fatalf("bad-signature forged token: want 401, got %d", code)
	}
}

func TestTokenForgeAppOnlyWithRoles(t *testing.T) {
	hts, _, _ := newTestServer(t)

	status, body := postJSON(t, hts.URL+"/admin/api/tokens", map[string]any{
		"clientId": daemonID,
		"roles":    []string{"Tasks.Read.All", "Tasks.Write.All"},
	})
	if status != 200 {
		t.Fatalf("forge: %d %v", status, body)
	}
	claims := decodeJWTPayload(t, body["token"].(string))
	if claims["sub"] != daemonID {
		t.Fatalf("app-only sub should be the appId, got %v", claims["sub"])
	}
	if _, hasOID := claims["oid"]; hasOID {
		t.Fatal("app-only forged token must not carry oid")
	}
	roles, _ := json.Marshal(claims["roles"])
	if string(roles) != `["Tasks.Read.All","Tasks.Write.All"]` {
		t.Fatalf("roles not preserved: %s", roles)
	}
}

func TestTokenForgeExtraClaimsOverride(t *testing.T) {
	hts, _, _ := newTestServer(t)

	status, body := postJSON(t, hts.URL+"/admin/api/tokens", map[string]any{
		"userId":      aliceID,
		"extraClaims": map[string]any{"ipaddr": "10.0.0.5", "tid": "overridden"},
	})
	if status != 200 {
		t.Fatalf("forge: %d %v", status, body)
	}
	claims := decodeJWTPayload(t, body["token"].(string))
	if claims["ipaddr"] != "10.0.0.5" {
		t.Fatalf("extra claim not injected: %v", claims["ipaddr"])
	}
	if claims["tid"] != "overridden" {
		t.Fatalf("extraClaims must override base claims: %v", claims["tid"])
	}
}

func TestTokenForgeIDToken(t *testing.T) {
	hts, _, _ := newTestServer(t)

	status, body := postJSON(t, hts.URL+"/admin/api/tokens", map[string]any{
		"tokenType": "id",
		"clientId":  spaID,
		"userId":    aliceID,
		"nonce":     "n-forge",
	})
	if status != 200 {
		t.Fatalf("forge: %d %v", status, body)
	}
	claims := decodeJWTPayload(t, body["token"].(string))
	if claims["aud"] != spaID || claims["nonce"] != "n-forge" {
		t.Fatalf("unexpected id-token claims: %v", claims)
	}
	if claims["preferred_username"] != "alice@entraemulator.dev" {
		t.Fatalf("id token missing preferred_username: %v", claims)
	}
}

func TestTokenForgeUnknownClient(t *testing.T) {
	hts, _, _ := newTestServer(t)

	status, body := postJSON(t, hts.URL+"/admin/api/tokens", map[string]any{
		"clientId": "00000000-0000-0000-0000-000000000000",
	})
	if status != 400 {
		t.Fatalf("unknown client: want 400, got %d %v", status, body)
	}
}
