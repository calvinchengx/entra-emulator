package server

import (
	"bytes"
	"net/http"
	"testing"
)

// postRaw sends a raw (possibly malformed) body to exercise decode-error paths.
func postRaw(t *testing.T, method, url, body string) int {
	t.Helper()
	req, _ := http.NewRequest(method, url, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// TestAdminErrorPaths sweeps the not-found / validation / malformed-body
// branches of the admin handlers that the happy-path suite doesn't reach.
func TestAdminErrorPaths(t *testing.T) {
	hts, _, _ := newTestServer(t)
	base := hts.URL + "/admin/api"
	missing := "00000000-0000-0000-0000-0000000000ff"

	// A real app + group to hang sub-resource error cases off of.
	_, app := postJSON(t, base+"/apps", map[string]any{"displayName": "ErrApp"})
	appID := app["id"].(string)
	_, grp := postJSON(t, base+"/groups", map[string]any{"displayName": "ErrGroup"})
	gid := grp["id"].(string)

	// --- Users ---
	expect(t, "GET user missing", get(t, base+"/users/"+missing), 404)
	expect(t, "PATCH user missing", patch(t, base+"/users/"+missing, `{"displayName":"x"}`), 404)
	expect(t, "DELETE user missing", deleteStatus(t, base+"/users/"+missing), 404)
	expect(t, "POST user malformed", postRaw(t, "POST", base+"/users", `{bad`), 400)
	if code, _ := patchJSON(t, base+"/users/"+aliceID, map[string]any{"mail": "not-an-email"}); code != 400 {
		t.Fatalf("patch invalid mail: want 400, got %d", code)
	}
	expect(t, "GET user groups missing", get(t, base+"/users/"+missing+"/groups"), 404)
	expect(t, "GET user passkeys missing", get(t, base+"/users/"+missing+"/passkeys"), 404)

	// --- Groups ---
	expect(t, "GET group missing", get(t, base+"/groups/"+missing), 404)
	expect(t, "PATCH group missing", patch(t, base+"/groups/"+missing, `{"description":"x"}`), 404)
	expect(t, "DELETE group missing", deleteStatus(t, base+"/groups/"+missing), 404)
	if code, _ := postJSON(t, base+"/groups", map[string]any{}); code != 400 {
		t.Fatalf("create group no name: want 400, got %d", code)
	}
	expect(t, "PATCH group malformed", postRaw(t, "PATCH", base+"/groups/"+gid, `{bad`), 400)
	expect(t, "members of missing group", get(t, base+"/groups/"+missing+"/members"), 404)
	if code, _ := postJSON(t, base+"/groups/"+missing+"/members", map[string]any{"userId": aliceID}); code != 404 {
		t.Fatalf("add member to missing group: want 404, got %d", code)
	}
	if code, _ := postJSON(t, base+"/groups/"+gid+"/members", map[string]any{"userId": missing}); code != 400 {
		t.Fatalf("add missing user to group: want 400, got %d", code)
	}
	// RemoveGroupMember is idempotent (no requireRow) → 204 even if absent.
	expect(t, "remove missing member (idempotent)", deleteStatus(t, base+"/groups/"+gid+"/members/"+missing), 204)

	// --- Apps + sub-resources (all GetApp-guarded → 404 on bad app) ---
	expect(t, "GET app missing", get(t, base+"/apps/"+missing), 404)
	expect(t, "PATCH app missing", patch(t, base+"/apps/"+missing, `{"displayName":"x"}`), 404)
	expect(t, "DELETE app missing", deleteStatus(t, base+"/apps/"+missing), 404)
	if code, _ := postJSON(t, base+"/apps", map[string]any{}); code != 400 {
		t.Fatalf("create app no name: want 400, got %d", code)
	}
	// redirect URIs
	if code, _ := postJSON(t, base+"/apps/"+missing+"/redirectUris", map[string]any{"uri": "https://x"}); code != 404 {
		t.Fatalf("redirect on missing app: want 404, got %d", code)
	}
	if code, _ := postJSON(t, base+"/apps/"+appID+"/redirectUris", map[string]any{}); code != 400 {
		t.Fatalf("redirect no uri: want 400, got %d", code)
	}
	expect(t, "bad redirect id", deleteStatus(t, base+"/apps/"+appID+"/redirectUris/not-an-int"), 400)
	// secrets
	if code, _ := postJSON(t, base+"/apps/"+missing+"/secrets", map[string]any{}); code != 404 {
		t.Fatalf("secret on missing app: want 404, got %d", code)
	}
	expect(t, "delete missing secret", deleteStatus(t, base+"/apps/"+appID+"/secrets/"+missing), 404)
	// scopes
	if code, _ := postJSON(t, base+"/apps/"+missing+"/scopes", map[string]any{"value": "x"}); code != 404 {
		t.Fatalf("scope on missing app: want 404, got %d", code)
	}
	if code, _ := postJSON(t, base+"/apps/"+appID+"/scopes", map[string]any{}); code != 400 {
		t.Fatalf("scope no value: want 400, got %d", code)
	}
	if code, _ := patchJSON(t, base+"/apps/"+appID+"/scopes/"+missing, map[string]any{"isEnabled": false}); code != 404 {
		t.Fatalf("patch missing scope: want 404, got %d", code)
	}
	expect(t, "delete missing scope", deleteStatus(t, base+"/apps/"+appID+"/scopes/"+missing), 404)
	// roles
	if code, _ := postJSON(t, base+"/apps/"+missing+"/roles", map[string]any{"value": "x"}); code != 404 {
		t.Fatalf("role on missing app: want 404, got %d", code)
	}
	if code, _ := postJSON(t, base+"/apps/"+appID+"/roles", map[string]any{}); code != 400 {
		t.Fatalf("role no value: want 400, got %d", code)
	}
	if code, _ := patchJSON(t, base+"/apps/"+appID+"/roles/"+missing, map[string]any{"isEnabled": false}); code != 404 {
		t.Fatalf("patch missing role: want 404, got %d", code)
	}
	expect(t, "delete missing role", deleteStatus(t, base+"/apps/"+appID+"/roles/"+missing), 404)
	// key credentials
	expect(t, "list keycreds missing app", get(t, base+"/apps/"+missing+"/keyCredentials"), 404)
	if code, _ := postJSON(t, base+"/apps/"+missing+"/keyCredentials", map[string]any{"publicKey": "x"}); code != 404 {
		t.Fatalf("keycred on missing app: want 404, got %d", code)
	}
	if code, _ := postJSON(t, base+"/apps/"+appID+"/keyCredentials", map[string]any{}); code != 400 {
		t.Fatalf("keycred no publicKey: want 400, got %d", code)
	}
	expect(t, "delete missing keycred", deleteStatus(t, base+"/apps/"+appID+"/keyCredentials/"+missing), 404)
	// custom extension
	if code, _ := putJSON(t, base+"/apps/"+missing+"/custom-extension", map[string]any{"endpoint": "https://x"}); code != 404 {
		t.Fatalf("custom-ext on missing app: want 404, got %d", code)
	}
	if code, _ := putJSON(t, base+"/apps/"+appID+"/custom-extension", map[string]any{}); code != 400 {
		t.Fatalf("custom-ext no endpoint: want 400, got %d", code)
	}

	// --- Fabric workspace identities ---
	if code, _ := patchJSON(t, base+"/workspace-identities/"+missing, map[string]any{"state": "Active"}); code != 404 {
		t.Fatalf("patch missing WI: want 404, got %d", code)
	}
	expect(t, "delete missing WI", deleteStatus(t, base+"/workspace-identities/"+missing), 404)

	// --- Import: malformed + structurally-invalid snapshot ---
	expect(t, "import malformed", postRaw(t, "POST", base+"/import", `{bad`), 400)
}

// small helpers to keep the sweep terse.
func get(t *testing.T, url string) int      { c, _ := getJSON(t, url); return c }
func patch(t *testing.T, url, body string) int { return postRaw(t, "PATCH", url, body) }
func expect(t *testing.T, name string, got, want int) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: want %d, got %d", name, want, got)
	}
}
