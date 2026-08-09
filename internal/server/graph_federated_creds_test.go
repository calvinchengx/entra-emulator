package server

import (
	"net/http"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// TestGraphFederatedIdentityCredentials covers the Graph route for workload
// identity federation trusts. CRUD returning 201 would prove almost nothing on
// its own — the assertion that matters is that a credential created HERE is the
// same row the token endpoint matches, so an external workload can immediately
// exchange its own token against it.
func TestGraphFederatedIdentityCredentials(t *testing.T) {
	hts, _, st := newTestServer(t)
	app := appGraphToken(t, hts.URL)
	iss := newFakeIssuer(t)
	subject := "repo:acme/widgets:ref:refs/heads/main"
	base := hts.URL + "/graph/v1.0/applications/" + daemonID + "/federatedIdentityCredentials"

	code, created := postJSONAuth(t, base, app, map[string]any{
		"name": "gh-main", "issuer": iss.URL, "subject": subject,
		"audiences":   []string{store.DefaultFederatedAudience},
		"description": "GitHub Actions main branch",
	})
	if code != http.StatusCreated {
		t.Fatalf("create via Graph: %d %v", code, created)
	}
	ficID, _ := created["id"].(string)
	if created["name"] != "gh-main" || created["issuer"] != iss.URL {
		t.Fatalf("credential shape: %v", created)
	}

	t.Run("lists and reads back", func(t *testing.T) {
		status, list := graphGet(t, hts.URL,
			"/graph/v1.0/applications/"+daemonID+"/federatedIdentityCredentials", app)
		if status != http.StatusOK || len(list["value"].([]any)) != 1 {
			t.Fatalf("list: %d %v", status, list)
		}
		if status, one := graphGet(t, hts.URL,
			"/graph/v1.0/applications/"+daemonID+"/federatedIdentityCredentials/"+ficID, app); status != 200 || one["id"] != ficID {
			t.Fatalf("get: %d %v", status, one)
		}
	})

	// The point of the whole feature.
	t.Run("a Graph-created trust really authenticates a workload", func(t *testing.T) {
		assertion := iss.mint(t, subject, store.DefaultFederatedAudience, st.Now()+600)
		status, body := exchange(t, hts.URL, daemonID, assertion)
		if status != http.StatusOK {
			t.Fatalf("a credential created over Graph must work at the token endpoint: %d %v", status, body)
		}
		if tok, _ := body["access_token"].(string); tok == "" {
			t.Fatalf("no access_token: %v", body)
		}
	})

	t.Run("PATCHing the subject changes who can authenticate", func(t *testing.T) {
		newSubject := "repo:acme/widgets:ref:refs/heads/release"
		if code, _ := patchJSONAuth(t, base+"/"+ficID, app, map[string]any{"subject": newSubject}); code != http.StatusNoContent {
			t.Fatalf("patch: %d", code)
		}
		// The old subject stops working…
		old := iss.mint(t, subject, store.DefaultFederatedAudience, st.Now()+600)
		if status, _ := exchange(t, hts.URL, daemonID, old); status == http.StatusOK {
			t.Fatal("the previous subject must stop authenticating after a PATCH")
		}
		// …and the new one starts.
		fresh := iss.mint(t, newSubject, store.DefaultFederatedAudience, st.Now()+600)
		if status, body := exchange(t, hts.URL, daemonID, fresh); status != http.StatusOK {
			t.Fatalf("the patched subject must authenticate: %d %v", status, body)
		}
	})

	t.Run("DELETE revokes the trust", func(t *testing.T) {
		if code := deleteAuthStatus(t, base+"/"+ficID, app); code != http.StatusNoContent {
			t.Fatalf("delete: %d", code)
		}
		assertion := iss.mint(t, "repo:acme/widgets:ref:refs/heads/release", store.DefaultFederatedAudience, st.Now()+600)
		if status, _ := exchange(t, hts.URL, daemonID, assertion); status == http.StatusOK {
			t.Fatal("a deleted credential must stop authenticating")
		}
	})

	t.Run("validation and unknown ids", func(t *testing.T) {
		if code, _ := postJSONAuth(t, base, app, map[string]any{"name": "incomplete"}); code != http.StatusBadRequest {
			t.Errorf("missing issuer/subject: want 400, got %d", code)
		}
		unknownApp := hts.URL + "/graph/v1.0/applications/" + store.NewGUID() + "/federatedIdentityCredentials"
		if status, _ := graphGet(t, hts.URL, "/graph/v1.0/applications/"+store.NewGUID()+"/federatedIdentityCredentials", app); status != http.StatusNotFound {
			t.Errorf("unknown application: want 404, got %d", status)
		}
		if code, _ := postJSONAuth(t, unknownApp, app, map[string]any{
			"name": "x", "issuer": "https://i", "subject": "s",
		}); code != http.StatusNotFound {
			t.Errorf("create under unknown application: want 404, got %d", code)
		}
	})
}
