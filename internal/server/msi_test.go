package server

import (
	"encoding/json"
	"net/http"
	"testing"
)

const msiSecret = "managed-identity-secret" // default dev value

func msiGet(t *testing.T, origin, query, header string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("GET", origin+"/msi/token"+query, nil)
	if header != "" {
		req.Header.Set("X-IDENTITY-HEADER", header)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestMSIMissingHeader(t *testing.T) {
	hts, _, _ := newTestServer(t)
	if code, _ := msiGet(t, hts.URL, "?resource=https://management.azure.com/", ""); code != 401 {
		t.Fatalf("missing header: want 401, got %d", code)
	}
	if code, _ := msiGet(t, hts.URL, "?resource=https://management.azure.com/", "wrong"); code != 401 {
		t.Fatalf("wrong header: want 401, got %d", code)
	}
}

func TestMSIMissingResource(t *testing.T) {
	hts, _, _ := newTestServer(t)
	if code, _ := msiGet(t, hts.URL, "", msiSecret); code != 400 {
		t.Fatalf("missing resource: want 400, got %d", code)
	}
}

func TestMSISystemAssigned(t *testing.T) {
	hts, _, _ := newTestServer(t)
	code, body := msiGet(t, hts.URL,
		"?api-version=2019-08-01&resource=https://management.azure.com/", msiSecret)
	if code != 200 {
		t.Fatalf("system-assigned: want 200, got %d %v", code, body)
	}
	// App Service response shape.
	for _, k := range []string{"access_token", "expires_on", "resource", "token_type", "client_id"} {
		if body[k] == nil {
			t.Fatalf("MSI response missing %q: %v", k, body)
		}
	}
	if body["token_type"] != "Bearer" {
		t.Fatalf("token_type: %v", body["token_type"])
	}
	// expires_on is a string (App Service format).
	if _, ok := body["expires_on"].(string); !ok {
		t.Fatalf("expires_on must be a string, got %T", body["expires_on"])
	}
	// The default identity is the seeded daemon app; token is app-only.
	if body["client_id"] != daemonID {
		t.Fatalf("system-assigned identity should be the daemon app, got %v", body["client_id"])
	}
	claims := decodeJWTPayload(t, body["access_token"].(string))
	if claims["aud"] != "https://management.azure.com/" {
		t.Fatalf("aud should be the requested resource: %v", claims["aud"])
	}
	if claims["sub"] != daemonID {
		t.Fatalf("app-only sub should be the identity appId: %v", claims["sub"])
	}
	if _, hasOID := claims["oid"]; hasOID {
		t.Fatal("managed-identity token is app-only; must not carry oid")
	}
}

func TestMSIUserAssignedByClientID(t *testing.T) {
	hts, _, _ := newTestServer(t)
	// Select the SPA app as a user-assigned identity via client_id.
	code, body := msiGet(t, hts.URL,
		"?resource=api://"+daemonID+"&client_id="+spaID, msiSecret)
	if code != 200 {
		t.Fatalf("user-assigned: want 200, got %d %v", code, body)
	}
	if body["client_id"] != spaID {
		t.Fatalf("user-assigned identity should be the SPA, got %v", body["client_id"])
	}
	claims := decodeJWTPayload(t, body["access_token"].(string))
	// Resource resolves to the daemon app → its Application role is auto-granted.
	roles, _ := json.Marshal(claims["roles"])
	if string(roles) == "[]" || string(roles) == "null" {
		t.Fatalf("expected auto-granted roles from the resource app, got %s", roles)
	}
}

func TestMSIUnknownIdentity(t *testing.T) {
	hts, _, _ := newTestServer(t)
	code, _ := msiGet(t, hts.URL,
		"?resource=https://management.azure.com/&client_id=00000000-0000-0000-0000-000000000000",
		msiSecret)
	if code != 400 {
		t.Fatalf("unknown identity: want 400, got %d", code)
	}
}
