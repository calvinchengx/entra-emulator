package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// graphGet issues an authenticated Graph GET and returns status + decoded body.
func graphGet(t *testing.T, origin, path, bearer string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("GET", origin+path, nil)
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

func appGraphToken(t *testing.T, hts string) string {
	t.Helper()
	_, cc := postForm(t, http.DefaultClient, hts+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type": {"client_credentials"}, "client_id": {daemonID},
		"client_secret": {store.SeedDaemonSecret}, "scope": {"https://graph.microsoft.com/.default"},
	})
	tok, _ := cc["access_token"].(string)
	if tok == "" {
		t.Fatalf("no app graph token: %v", cc)
	}
	return tok
}

// TestGraphMeMemberOf proves /me/memberOf returns the signed-in user's groups
// as directory objects (roadmap #17).
func TestGraphMeMemberOf(t *testing.T) {
	hts, _, _ := newTestServer(t)
	body := driveAuthCode(t, hts, "verifier-memberof-0123456789abcdefghi")
	access := body["access_token"].(string)

	status, resp := graphGet(t, hts.URL, "/graph/v1.0/me/memberOf", access)
	if status != 200 {
		t.Fatalf("/me/memberOf: %d %v", status, resp)
	}
	vals, _ := resp["value"].([]any)
	found := false
	for _, v := range vals {
		g, _ := v.(map[string]any)
		if g["displayName"] == "Engineering" {
			found = true
			if g["@odata.type"] != "#microsoft.graph.group" {
				t.Fatalf("memberOf group missing @odata.type: %v", g)
			}
		}
	}
	if !found {
		t.Fatalf("Engineering group not in /me/memberOf: %v", vals)
	}

	// /users/{id}/memberOf works with an app-only token too.
	app := appGraphToken(t, hts.URL)
	status, resp = graphGet(t, hts.URL, "/graph/v1.0/users/"+aliceID+"/memberOf", app)
	if status != 200 || len(resp["value"].([]any)) == 0 {
		t.Fatalf("/users/{id}/memberOf app-only: %d %v", status, resp)
	}
}

// TestGraphODataSelectFilterCount exercises $select, $filter, and $count.
func TestGraphODataSelectFilterCount(t *testing.T) {
	hts, _, _ := newTestServer(t)
	app := appGraphToken(t, hts.URL)

	// $select projects to id + selected fields only.
	status, resp := graphGet(t, hts.URL, "/graph/v1.0/users?"+url.Values{"$select": {"displayName"}}.Encode(), app)
	if status != 200 {
		t.Fatalf("$select: %d %v", status, resp)
	}
	first := resp["value"].([]any)[0].(map[string]any)
	if _, ok := first["displayName"]; !ok {
		t.Fatalf("$select dropped displayName: %v", first)
	}
	if _, ok := first["userPrincipalName"]; ok {
		t.Fatalf("$select should have dropped userPrincipalName: %v", first)
	}
	if _, ok := first["id"]; !ok {
		t.Fatalf("$select must always keep id: %v", first)
	}

	// $filter eq on a string field.
	status, resp = graphGet(t, hts.URL, "/graph/v1.0/users?"+url.Values{"$filter": {"displayName eq 'Alice Example'"}}.Encode(), app)
	if status != 200 {
		t.Fatalf("$filter eq: %d %v", status, resp)
	}
	if n := len(resp["value"].([]any)); n != 1 {
		t.Fatalf("$filter eq 'Alice Example' → %d results, want 1", n)
	}

	// $filter startswith.
	status, resp = graphGet(t, hts.URL, "/graph/v1.0/users?"+url.Values{"$filter": {"startswith(displayName,'Bob')"}}.Encode(), app)
	if status != 200 || len(resp["value"].([]any)) != 1 {
		t.Fatalf("$filter startswith Bob: %d %v", status, resp)
	}

	// $count adds @odata.count = total matching.
	status, resp = graphGet(t, hts.URL, "/graph/v1.0/users?"+url.Values{"$count": {"true"}}.Encode(), app)
	if status != 200 {
		t.Fatalf("$count: %d %v", status, resp)
	}
	cnt, ok := resp["@odata.count"].(float64)
	if !ok || int(cnt) != len(resp["value"].([]any)) {
		t.Fatalf("@odata.count mismatch: %v vs %d", resp["@odata.count"], len(resp["value"].([]any)))
	}

	// Combined $filter + $count: count reflects filtered set.
	status, resp = graphGet(t, hts.URL, "/graph/v1.0/users?"+url.Values{
		"$filter": {"startswith(displayName,'Alice')"}, "$count": {"true"},
	}.Encode(), app)
	if status != 200 || int(resp["@odata.count"].(float64)) != 1 {
		t.Fatalf("$filter+$count: %d %v", status, resp)
	}

	// Malformed $filter → 400 BadRequest.
	status, resp = graphGet(t, hts.URL, "/graph/v1.0/users?"+url.Values{"$filter": {"displayName lol 'x'"}}.Encode(), app)
	if status != 400 {
		t.Fatalf("bad $filter: want 400, got %d %v", status, resp)
	}
}
