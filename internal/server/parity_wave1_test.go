package server

import (
	"net/http"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// memberIDs pulls the member "value" ids out of a SCIM group resource.
func memberIDs(g map[string]any) map[string]bool {
	out := map[string]bool{}
	members, _ := g["members"].([]any)
	for _, m := range members {
		mm, _ := m.(map[string]any)
		if v, _ := mm["value"].(string); v != "" {
			out[v] = true
		}
	}
	return out
}

// TestSCIMReplaceGroup covers PUT /Groups/{id} (RFC 7644 §3.5.1): the resource
// is replaced wholesale — displayName is overwritten and membership becomes
// exactly the submitted set, so members absent from the body are removed.
func TestSCIMReplaceGroup(t *testing.T) {
	hts, _, _ := newTestServer(t)
	base := hts.URL + "/scim/v2/Groups"

	// Create a group holding Alice.
	code, created := scimReq(t, "POST", base, map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "Replace Me",
		"members":     []map[string]any{{"value": aliceID}},
	})
	if code != http.StatusCreated {
		t.Fatalf("create group: %d %v", code, created)
	}
	gid, _ := created["id"].(string)
	if !memberIDs(created)[aliceID] {
		t.Fatalf("created group should hold Alice: %v", created)
	}

	// PUT replaces it: new displayName, and Bob replaces Alice entirely.
	code, replaced := scimReq(t, "PUT", base+"/"+gid, map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "Replaced",
		"members":     []map[string]any{{"value": store.SeedUserBobID}},
	})
	if code != http.StatusOK {
		t.Fatalf("PUT group: %d %v", code, replaced)
	}
	if replaced["displayName"] != "Replaced" {
		t.Fatalf("displayName not replaced: %v", replaced["displayName"])
	}
	got := memberIDs(replaced)
	if !got[store.SeedUserBobID] {
		t.Fatalf("Bob should be a member after PUT: %v", replaced)
	}
	if got[aliceID] {
		t.Fatalf("Alice should have been removed by the wholesale replace: %v", replaced)
	}

	// The change persisted (re-read), and id is stable.
	code, reread := scimReq(t, "GET", base+"/"+gid, nil)
	if code != http.StatusOK || reread["displayName"] != "Replaced" || reread["id"] != gid {
		t.Fatalf("re-read after PUT: %d %v", code, reread)
	}
	if ids := memberIDs(reread); ids[aliceID] || !ids[store.SeedUserBobID] {
		t.Fatalf("persisted membership wrong: %v", reread)
	}

	// PUT without displayName is a 400; PUT on an unknown id is a 404.
	if code, _ := scimReq(t, "PUT", base+"/"+gid, map[string]any{"schemas": []string{}}); code != http.StatusBadRequest {
		t.Fatalf("PUT without displayName: want 400, got %d", code)
	}
	if code, _ := scimReq(t, "PUT", base+"/"+store.NewGUID(), map[string]any{"displayName": "x"}); code != http.StatusNotFound {
		t.Fatalf("PUT unknown group: want 404, got %d", code)
	}
}

// TestDiscoveryCloudInstanceMetadata covers the cloud-instance metadata fields
// real Entra advertises. The emulator must serve them pointing at its OWN
// origins — a client that reads them must never be sent to the real cloud.
func TestDiscoveryCloudInstanceMetadata(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	code, doc := getJSON(t, hts.URL+"/"+tenant+"/v2.0/.well-known/openid-configuration")
	if code != http.StatusOK {
		t.Fatalf("discovery: %d", code)
	}

	for _, f := range []string{
		"tenant_region_scope", "cloud_instance_name",
		"cloud_graph_host_name", "msgraph_host", "rbac_url",
	} {
		if v, _ := doc[f].(string); v == "" {
			t.Errorf("discovery missing cloud-instance field %q", f)
		}
	}

	// Never leak real-cloud coordinates.
	for _, f := range []string{"cloud_instance_name", "cloud_graph_host_name", "msgraph_host", "rbac_url"} {
		v, _ := doc[f].(string)
		for _, bad := range []string{"microsoftonline.com", "graph.microsoft.com", "windows.net"} {
			if v == bad || (len(v) > len(bad) && v[len(v)-len(bad):] == bad) {
				t.Errorf("%s = %q points at the real cloud, not the emulator", f, v)
			}
		}
	}

	// The graph-derived fields track the configured Graph origin.
	wantHost := hostOnly(cfg.Origins.Graph)
	if got, _ := doc["msgraph_host"].(string); got != wantHost {
		t.Errorf("msgraph_host = %q, want the emulator Graph host %q", got, wantHost)
	}
	if got, _ := doc["cloud_graph_host_name"].(string); got != wantHost {
		t.Errorf("cloud_graph_host_name = %q, want %q", got, wantHost)
	}
}

// hostOnly strips the scheme from an origin for host comparisons.
func hostOnly(origin string) string {
	for _, p := range []string{"https://", "http://"} {
		if len(origin) > len(p) && origin[:len(p)] == p {
			return origin[len(p):]
		}
	}
	return origin
}
