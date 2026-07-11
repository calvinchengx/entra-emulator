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
