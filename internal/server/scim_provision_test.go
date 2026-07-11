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
// the bearer token, and remembers created users so existence probes work.
type mockSCIM struct {
	*httptest.Server
	token string
	mu    sync.Mutex
	users map[string]string // userName -> id
	reqs  []string          // "METHOD path"
	patch []string          // PATCH bodies
}

func newMockSCIM(token string) *mockSCIM {
	m := &mockSCIM{token: token, users: map[string]string{}}
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
		upn := strings.Trim(strings.TrimPrefix(r.URL.Query().Get("filter"), "userName eq "), `"`)
		m.mu.Lock()
		id, ok := m.users[upn]
		m.mu.Unlock()
		res := []any{}
		if ok {
			res = []any{map[string]any{"id": id, "userName": upn}}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"Resources": res})
	case r.Method == "POST" && r.URL.Path == "/Users":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
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
	default:
		w.WriteHeader(http.StatusNotFound)
	}
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

func TestSCIMProvisioningClient(t *testing.T) {
	hts, _, st := newTestServer(t)
	mock := newMockSCIM("target-secret")
	defer mock.Close()

	// Sync with no target configured → 400.
	if code, _ := postJSON(t, hts.URL+"/admin/api/scim/sync", map[string]any{}); code != 400 {
		t.Fatalf("sync without target: want 400, got %d", code)
	}

	// Configure the target.
	if code, _ := postJSON(t, hts.URL+"/admin/api/scim/target", map[string]any{
		"endpoint": mock.URL, "token": "target-secret",
	}); code != 200 {
		t.Fatalf("set target: %d", code)
	}

	// Initial sync: target empty → probe + POST create each active seeded user.
	code, res := postJSON(t, hts.URL+"/admin/api/scim/sync", map[string]any{"mode": "initial"})
	if code != 200 {
		t.Fatalf("initial sync: %d %v", code, res)
	}
	if int(res["created"].(float64)) < 2 {
		t.Fatalf("expected >=2 creates, got %v", res)
	}
	if mock.count("GET /Users") < 2 {
		t.Fatalf("expected existence probes, reqs=%v", mock.reqs)
	}
	if mock.count("POST /Users") < 2 {
		t.Fatalf("expected POST creates, reqs=%v", mock.reqs)
	}

	// Disable Alice, re-sync → probe finds her → PATCH active:false (deprovision).
	alice, err := st.GetUser(aliceID)
	if err != nil {
		t.Fatal(err)
	}
	alice.AccountEnabled = false
	if err := st.UpdateUser(alice); err != nil {
		t.Fatal(err)
	}
	_, res2 := postJSON(t, hts.URL+"/admin/api/scim/sync", map[string]any{"mode": "incremental"})
	if int(res2["deprovisioned"].(float64)) < 1 {
		t.Fatalf("expected a deprovision, got %v", res2)
	}
	if !mock.sawDeprovision() {
		t.Fatalf("expected an active:false PATCH, patches=%v", mock.patch)
	}

	// Provisioning log records the outbound requests.
	if _, logResp := getJSON(t, hts.URL+"/admin/api/scim/log"); len(logResp["value"].([]any)) == 0 {
		t.Fatal("provisioning log is empty")
	}
}
