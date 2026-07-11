package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

func exportDirectory(t *testing.T, origin string) map[string]any {
	t.Helper()
	code, body := getJSON(t, origin+"/admin/api/export")
	if code != 200 {
		t.Fatalf("export: %d", code)
	}
	return body
}

func importDirectory(t *testing.T, origin string, snapshot map[string]any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(snapshot)
	resp, err := http.Post(origin+"/admin/api/import", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestDirectoryExportShape(t *testing.T) {
	hts, _, _ := newTestServer(t)
	snap := exportDirectory(t, hts.URL)

	users, _ := snap["users"].([]any)
	apps, _ := snap["apps"].([]any)
	if len(users) != 2 || len(apps) != 2 {
		t.Fatalf("export should have 2 seeded users + 2 apps, got %d users %d apps", len(users), len(apps))
	}
}

// TestDirectoryRoundTripRestoresState exports, mutates, then re-imports and
// asserts the original state is back — the shareable-fixture use case.
func TestDirectoryRoundTripRestoresState(t *testing.T) {
	hts, _, _ := newTestServer(t)
	snap := exportDirectory(t, hts.URL)

	// Mutate: delete Bob and create a throwaway user.
	deleteReq(t, hts.URL+"/admin/api/users/"+store.SeedUserBobID)
	postJSON(t, hts.URL+"/admin/api/users", map[string]any{
		"userPrincipalName": "temp@entraemulator.dev", "displayName": "Temp",
	})

	// Re-import the original snapshot → replace.
	if code, out := importDirectory(t, hts.URL, snap); code != 200 {
		t.Fatalf("import: %d %v", code, out)
	}

	// Bob is back; the throwaway user is gone.
	code, page := getJSON(t, hts.URL+"/admin/api/users?top=200")
	if code != 200 {
		t.Fatal("list users failed")
	}
	upns := map[string]bool{}
	for _, u := range page["value"].([]any) {
		upns[u.(map[string]any)["userPrincipalName"].(string)] = true
	}
	if !upns["bob@entraemulator.dev"] {
		t.Fatal("import should have restored Bob")
	}
	if upns["temp@entraemulator.dev"] {
		t.Fatal("import should have removed the throwaway user")
	}
}

// TestImportPreservesSecretAuth proves the daemon secret still authenticates
// after an export/import cycle (the hash is preserved).
func TestImportPreservesSecretAuth(t *testing.T) {
	hts, _, _ := newTestServer(t)
	snap := exportDirectory(t, hts.URL)

	if code, _ := importDirectory(t, hts.URL, snap); code != 200 {
		t.Fatalf("import failed: %d", code)
	}

	resp, body := postForm(t, http.DefaultClient, hts.URL+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {daemonID},
		"client_secret": {"daemon-app-secret"},
		"scope":         {"https://graph.microsoft.com/.default"},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("daemon secret should still work after import: %d %v", resp.StatusCode, body)
	}
}
