package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

// postJSONAuth POSTs a JSON body with a bearer token (the Graph write surface).
func postJSONAuth(t *testing.T, url, bearer string, body any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// forgeGraphToken mints a Graph-audience token with the given delegated scopes
// (userID set) or app roles (userID empty), via the admin token forge.
func forgeGraphToken(t *testing.T, hts, userID string, scopes, roles []string) string {
	t.Helper()
	body := map[string]any{}
	if userID != "" {
		body["userId"] = userID
	}
	if scopes != nil {
		body["scopes"] = scopes
	}
	if roles != nil {
		body["roles"] = roles
	}
	code, out := postJSON(t, hts+"/admin/api/tokens", body)
	tok, _ := out["token"].(string)
	if code != http.StatusOK || tok == "" {
		t.Fatalf("forge token: %d %v", code, out)
	}
	return tok
}

// TestGraphPermissionsOffByDefault pins the backward-compatible default: with
// GRAPH_PERMISSIONS unset, any valid Graph-audience token authorizes any
// operation — the emulator's long-standing behaviour.
func TestGraphPermissionsOffByDefault(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	if cfg.GraphPermissions {
		t.Fatal("GraphPermissions must default to false")
	}
	// An app-only token carrying NO roles still reads and writes.
	tok := forgeGraphToken(t, hts.URL, "", nil, nil)
	if status, body := graphGet(t, hts.URL, "/graph/v1.0/users", tok); status != http.StatusOK {
		t.Fatalf("default-off read: want 200, got %d %v", status, body)
	}
}

// TestGraphPermissionsEnforced covers the real Entra gate once enabled:
// delegated calls need the scope in `scp`, app-only calls the role in `roles`,
// and Directory.* acts as the superset. Denials are 403
// Authorization_RequestDenied, matching Graph.
func TestGraphPermissionsEnforced(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	cfg.GraphPermissions = true // cfg is shared with the live handlers

	get := func(path, tok string) (int, map[string]any) {
		return graphGet(t, hts.URL, path, tok)
	}

	t.Run("app-only without roles is denied", func(t *testing.T) {
		tok := forgeGraphToken(t, hts.URL, "", nil, nil)
		status, body := get("/graph/v1.0/users", tok)
		if status != http.StatusForbidden {
			t.Fatalf("want 403, got %d %v", status, body)
		}
		errObj, _ := body["error"].(map[string]any)
		if errObj["code"] != "Authorization_RequestDenied" {
			t.Fatalf("want Authorization_RequestDenied, got %v", body)
		}
	})

	t.Run("app-only with the read role is allowed", func(t *testing.T) {
		tok := forgeGraphToken(t, hts.URL, "", nil, []string{"User.Read.All"})
		if status, body := get("/graph/v1.0/users", tok); status != http.StatusOK {
			t.Fatalf("want 200, got %d %v", status, body)
		}
	})

	t.Run("read role does not grant writes", func(t *testing.T) {
		tok := forgeGraphToken(t, hts.URL, "", nil, []string{"User.Read.All"})
		code, body := postJSONAuth(t, hts.URL+"/graph/v1.0/users", tok, map[string]any{
			"userPrincipalName": "perm-denied@entraemulator.dev", "displayName": "Denied",
		})
		if code != http.StatusForbidden {
			t.Fatalf("write with a read-only role: want 403, got %d %v", code, body)
		}
	})

	t.Run("Directory.ReadWrite.All is a superset that grants writes", func(t *testing.T) {
		tok := forgeGraphToken(t, hts.URL, "", nil, []string{"Directory.ReadWrite.All"})
		code, body := postJSONAuth(t, hts.URL+"/graph/v1.0/users", tok, map[string]any{
			"userPrincipalName": "perm-allowed@entraemulator.dev", "displayName": "Allowed",
		})
		if code != http.StatusCreated {
			t.Fatalf("write with Directory.ReadWrite.All: want 201, got %d %v", code, body)
		}
	})

	t.Run("delegated User.Read reaches /me but not the directory", func(t *testing.T) {
		tok := forgeGraphToken(t, hts.URL, aliceID, []string{"User.Read"}, nil)
		if status, body := get("/graph/v1.0/me", tok); status != http.StatusOK {
			t.Fatalf("/me with User.Read: want 200, got %d %v", status, body)
		}
		if status, _ := get("/graph/v1.0/users", tok); status != http.StatusForbidden {
			t.Fatalf("/users with only User.Read: want 403, got %d", status)
		}
	})

	t.Run("delegated User.Read.All reaches the directory", func(t *testing.T) {
		tok := forgeGraphToken(t, hts.URL, aliceID, []string{"User.Read.All"}, nil)
		if status, body := get("/graph/v1.0/users", tok); status != http.StatusOK {
			t.Fatalf("want 200, got %d %v", status, body)
		}
	})

	t.Run("group permissions are gated separately from user ones", func(t *testing.T) {
		tok := forgeGraphToken(t, hts.URL, "", nil, []string{"User.Read.All"})
		if status, _ := get("/graph/v1.0/groups", tok); status != http.StatusForbidden {
			t.Fatalf("groups with only User.Read.All: want 403, got %d", status)
		}
		tok = forgeGraphToken(t, hts.URL, "", nil, []string{"Group.Read.All"})
		if status, body := get("/graph/v1.0/groups", tok); status != http.StatusOK {
			t.Fatalf("groups with Group.Read.All: want 200, got %d %v", status, body)
		}
	})
}
