package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// mockSCIM is a stateful downstream SCIM target: it records requests, requires
// the bearer token, and remembers created users/groups so existence probes work.
type mockSCIM struct {
	*httptest.Server
	token       string
	mu          sync.Mutex
	users       map[string]string // userName -> id
	groups      map[string]string // displayName -> id
	reqs        []string          // "METHOD path"
	patch       []string          // user PATCH bodies
	groupBodies []map[string]any  // group POST/PATCH bodies
}

func newMockSCIM(token string) *mockSCIM {
	m := &mockSCIM{token: token, users: map[string]string{}, groups: map[string]string{}}
	m.Server = httptest.NewServer(http.HandlerFunc(m.handle))
	return m
}

func (m *mockSCIM) handle(w http.ResponseWriter, r *http.Request) {
	if strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") != m.token {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	m.mu.Lock()
	m.reqs = append(m.reqs, r.Method+" "+r.URL.Path)
	m.mu.Unlock()

	switch {
	case r.Method == "GET" && r.URL.Path == "/Users":
		upn := filterValue(r, "userName eq ")
		m.mu.Lock()
		id, ok := m.users[upn]
		m.mu.Unlock()
		writeResources(w, ok, map[string]any{"id": id, "userName": upn})
	case r.Method == "POST" && r.URL.Path == "/Users":
		body := decodeBodyMap(r)
		upn, _ := body["userName"].(string)
		id := "target-" + upn
		m.mu.Lock()
		m.users[upn] = id
		m.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id})
	case r.Method == "PATCH" && strings.HasPrefix(r.URL.Path, "/Users/"):
		raw, _ := io.ReadAll(r.Body)
		m.mu.Lock()
		m.patch = append(m.patch, string(raw))
		m.mu.Unlock()
		_, _ = w.Write([]byte("{}"))
	case r.Method == "GET" && r.URL.Path == "/Groups":
		dn := filterValue(r, "displayName eq ")
		m.mu.Lock()
		id, ok := m.groups[dn]
		m.mu.Unlock()
		writeResources(w, ok, map[string]any{"id": id})
	case r.Method == "POST" && r.URL.Path == "/Groups":
		body := decodeBodyMap(r)
		dn, _ := body["displayName"].(string)
		id := "grp-" + dn
		m.mu.Lock()
		m.groups[dn] = id
		m.groupBodies = append(m.groupBodies, body)
		m.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id})
	case r.Method == "PATCH" && strings.HasPrefix(r.URL.Path, "/Groups/"):
		m.mu.Lock()
		m.groupBodies = append(m.groupBodies, decodeBodyMap(r))
		m.mu.Unlock()
		_, _ = w.Write([]byte("{}"))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func filterValue(r *http.Request, prefix string) string {
	return strings.Trim(strings.TrimPrefix(r.URL.Query().Get("filter"), prefix), `"`)
}
func writeResources(w http.ResponseWriter, found bool, res map[string]any) {
	list := []any{}
	if found {
		list = []any{res}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"Resources": list})
}
func decodeBodyMap(r *http.Request) map[string]any {
	var b map[string]any
	_ = json.NewDecoder(r.Body).Decode(&b)
	return b
}

func (m *mockSCIM) count(methodPath string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, r := range m.reqs {
		if r == methodPath {
			n++
		}
	}
	return n
}
func (m *mockSCIM) reset() {
	m.mu.Lock()
	m.reqs, m.patch, m.groupBodies = nil, nil, nil
	m.mu.Unlock()
}
func (m *mockSCIM) sawDeprovision() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.patch {
		if strings.Contains(p, `"active"`) && strings.Contains(p, "false") {
			return true
		}
	}
	return false
}

// lastGroupMemberValues returns the member ids in the most recent group body.
func (m *mockSCIM) lastGroupMemberValues() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.groupBodies) == 0 {
		return nil
	}
	body := m.groupBodies[len(m.groupBodies)-1]
	// POST: members at top level; PATCH: Operations[0].value.
	members, ok := body["members"].([]any)
	if !ok {
		if ops, ok := body["Operations"].([]any); ok && len(ops) > 0 {
			members, _ = ops[0].(map[string]any)["value"].([]any)
		}
	}
	var vals []string
	for _, mem := range members {
		if v, ok := mem.(map[string]any)["value"].(string); ok {
			vals = append(vals, v)
		}
	}
	return vals
}

func configureTarget(t *testing.T, hts *httptest.Server, endpoint string) {
	t.Helper()
	if code, _ := postJSON(t, hts.URL+"/admin/api/scim/target", map[string]any{
		"endpoint": endpoint, "token": "target-secret",
	}); code != 200 {
		t.Fatalf("set target: %d", code)
	}
}

func TestSCIMProvisioningClient(t *testing.T) {
	hts, _, st := newTestServer(t)
	mock := newMockSCIM("target-secret")
	defer mock.Close()

	// Sync with no target configured → 400.
	if code, _ := postJSON(t, hts.URL+"/admin/api/scim/sync", map[string]any{}); code != 400 {
		t.Fatalf("sync without target: want 400, got %d", code)
	}
	configureTarget(t, hts, mock.URL)

	// Initial sync: probe + create each active user, then create groups with
	// member-correlated ids.
	code, res := postJSON(t, hts.URL+"/admin/api/scim/sync", map[string]any{"mode": "initial"})
	if code != 200 {
		t.Fatalf("initial sync: %d %v", code, res)
	}
	if int(res["created"].(float64)) < 2 {
		t.Fatalf("expected >=2 user creates, got %v", res)
	}
	if int(res["groupsCreated"].(float64)) < 1 {
		t.Fatalf("expected a group create, got %v", res)
	}
	if mock.count("GET /Users") < 2 || mock.count("POST /Users") < 2 {
		t.Fatalf("missing user probes/creates: %v", mock.reqs)
	}
	// The seeded Engineering group's members were correlated to target ids.
	members := mock.lastGroupMemberValues()
	if !contains(members, "target-alice@entraemulator.dev") || !contains(members, "target-bob@entraemulator.dev") {
		t.Fatalf("group members not correlated to target ids: %v", members)
	}

	// Disable Alice → re-sync → PATCH active:false (deprovision).
	alice, _ := st.GetUser(aliceID)
	alice.AccountEnabled = false
	if err := st.UpdateUser(alice); err != nil {
		t.Fatal(err)
	}
	_, res2 := postJSON(t, hts.URL+"/admin/api/scim/sync", map[string]any{"mode": "initial"})
	if int(res2["deprovisioned"].(float64)) < 1 || !mock.sawDeprovision() {
		t.Fatalf("expected a deprovision, got %v patches=%v", res2, mock.patch)
	}

	if _, logResp := getJSON(t, hts.URL+"/admin/api/scim/log"); len(logResp["value"].([]any)) == 0 {
		t.Fatal("provisioning log is empty")
	}
}

func TestSCIMProvisioningIncremental(t *testing.T) {
	hts, _, st := newTestServer(t)
	mock := newMockSCIM("target-secret")
	defer mock.Close()

	// Controlled clock, above the seeded rows' timestamps.
	var clk int64 = 9_000_000_000
	st.Now = func() int64 { return clk }
	configureTarget(t, hts, mock.URL)

	// Initial sync creates everyone; watermark := clk.
	postJSON(t, hts.URL+"/admin/api/scim/sync", map[string]any{"mode": "initial"})
	mock.reset()

	// Advance the clock and touch exactly one user.
	clk = 9_000_000_100
	alice, _ := st.GetUser(aliceID)
	alice.DisplayName = "Alice Renamed"
	if err := st.UpdateUser(alice); err != nil { // UpdatedAt := 9_000_000_100
		t.Fatal(err)
	}

	// Incremental: only Alice is newer than the watermark → one update, others skipped.
	_, res := postJSON(t, hts.URL+"/admin/api/scim/sync", map[string]any{"mode": "incremental"})
	if int(res["updated"].(float64)) != 1 {
		t.Fatalf("incremental should update exactly Alice, got %v", res)
	}
	if int(res["skipped"].(float64)) < 1 {
		t.Fatalf("incremental should skip unchanged users, got %v", res)
	}
	// User-sync touched only Alice: no creates, exactly one PATCH (to her).
	if mock.count("POST /Users") != 0 {
		t.Fatalf("incremental created users unexpectedly: %v", mock.reqs)
	}
	if mock.count("PATCH /Users/target-alice@entraemulator.dev") != 1 {
		t.Fatalf("incremental should PATCH only Alice: %v", mock.reqs)
	}
}

// TestSCIMProvisioningSameSecondChangeIsNotLost pins the watermark boundary.
//
// The watermark is Unix SECONDS, and a sync records it as the moment the sync
// started. A change committed in that same second — after ListUsers already read
// the row, so the sync could not have seen it — lands with UpdatedAt exactly
// equal to the watermark. Comparing with <= then skips it on the next
// incremental sync, and on every sync after that, because the watermark only
// moves forward. The change is not delayed, it is lost permanently.
//
// The window is small in wall-clock terms and unbounded in consequence, which is
// why it survived: a real client syncing twice inside one second silently drops
// whatever changed between the read and the clock tick.
//
// The fix is at-least-once rather than at-most-once. Re-sending is harmless here
// because every send probes the target first and turns a create into an update,
// so the worst case is one redundant PATCH. Dropping a change has no such floor.
func TestSCIMProvisioningSameSecondChangeIsNotLost(t *testing.T) {
	hts, _, st := newTestServer(t)
	mock := newMockSCIM("target-secret")
	defer mock.Close()

	// A clock that does NOT advance: every timestamp in this test is the same
	// second, which is the boundary being tested rather than an approximation
	// of it.
	var clk int64 = 9_000_000_000
	st.Now = func() int64 { return clk }
	configureTarget(t, hts, mock.URL)

	// Initial sync creates everyone and sets watermark := clk.
	postJSON(t, hts.URL+"/admin/api/scim/sync", map[string]any{"mode": "initial"})
	mock.reset()

	// Change Alice in the SAME second the sync recorded. UpdatedAt == watermark.
	alice, err := st.GetUser(aliceID)
	if err != nil {
		t.Fatal(err)
	}
	alice.DisplayName = "Alice Changed In The Same Second"
	if err := st.UpdateUser(alice); err != nil {
		t.Fatal(err)
	}
	if alice.UpdatedAt != clk {
		t.Fatalf("test setup is not exercising the boundary: UpdatedAt=%d clk=%d", alice.UpdatedAt, clk)
	}

	// The change must reach the target. Asserting the count alone would pass on
	// a PATCH to somebody else, so assert it went to Alice.
	_, res := postJSON(t, hts.URL+"/admin/api/scim/sync", map[string]any{"mode": "incremental"})
	if n := mock.count("PATCH /Users/target-alice@entraemulator.dev"); n != 1 {
		t.Fatalf("a change made in the watermark's own second was lost: want 1 PATCH to Alice, got %d (sync result %v, requests %v)",
			n, res, mock.reqs)
	}
}
