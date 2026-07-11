package customext

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// ---- Store CRUD ----

func TestStoreCRUD(t *testing.T) {
	s := NewStore()

	if _, ok := s.Get("app-1"); ok {
		t.Fatal("Get on empty store should report not-found")
	}

	cfg := Config{Endpoint: "https://hook.example/one", Claims: []string{"roles"}, TimeoutMs: 500}
	s.Set("app-1", cfg)

	got, ok := s.Get("app-1")
	if !ok {
		t.Fatal("Get after Set should find the config")
	}
	if got.Endpoint != cfg.Endpoint || got.TimeoutMs != cfg.TimeoutMs || len(got.Claims) != 1 {
		t.Fatalf("Get returned %+v, want %+v", got, cfg)
	}

	s.Set("app-2", Config{Endpoint: "https://hook.example/two"})
	all := s.All()
	if len(all) != 2 {
		t.Fatalf("All returned %d entries, want 2", len(all))
	}
	if all["app-1"].Endpoint != cfg.Endpoint {
		t.Fatalf("All missing app-1: %v", all)
	}

	// All must return a copy: mutating it must not affect the store.
	delete(all, "app-1")
	if _, ok := s.Get("app-1"); !ok {
		t.Fatal("mutating All()'s map affected the store")
	}

	s.Delete("app-1")
	if _, ok := s.Get("app-1"); ok {
		t.Fatal("Get after Delete should report not-found")
	}
	if len(s.All()) != 1 {
		t.Fatalf("All after Delete returned %d entries, want 1", len(s.All()))
	}
}

// ---- allowSet / statusError helpers ----

func TestAllowSet(t *testing.T) {
	if allowSet(nil) != nil {
		t.Fatal("allowSet(nil) should be nil (allow-all)")
	}
	if allowSet([]string{}) != nil {
		t.Fatal("allowSet(empty) should be nil (allow-all)")
	}
	m := allowSet([]string{"a", "b"})
	if !m["a"] || !m["b"] || m["c"] {
		t.Fatalf("allowSet built wrong set: %v", m)
	}
}

func TestStatusError(t *testing.T) {
	err := errStatus(503)
	if err == nil {
		t.Fatal("errStatus should return a non-nil error")
	}
	if err.Error() != "custom extension returned non-200" {
		t.Fatalf("unexpected message: %q", err.Error())
	}
	if se, ok := err.(statusError); !ok || int(se) != 503 {
		t.Fatalf("errStatus should carry the code, got %#v", err)
	}
}

// ---- Invoker ----

// responseData is the documented onTokenIssuanceStartResponseData shape.
func responseData(claims map[string]any, odataType string) map[string]any {
	return map[string]any{
		"data": map[string]any{
			"@odata.type": "microsoft.graph.onTokenIssuanceStartResponseData",
			"actions": []map[string]any{{
				"@odata.type": odataType,
				"claims":      claims,
			}},
		},
	}
}

const provideClaims = "microsoft.graph.tokenIssuanceStart.provideClaimsForToken"

func testApp() *store.App {
	return &store.App{ID: "app-abc", DisplayName: "My App"}
}

func testUser() *store.User {
	return &store.User{
		ID:                "user-123",
		DisplayName:       "Alice Example",
		GivenName:         "Alice",
		Surname:           "Example",
		Mail:              "alice@example.com",
		UserPrincipalName: "alice@example.com",
	}
}

func TestInvokeSuccessMergesClaims(t *testing.T) {
	var gotType, gotBearer, gotUPN, gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var req map[string]any
		_ = json.Unmarshal(raw, &req)
		gotType, _ = req["type"].(string)
		gotBearer = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		if data, ok := req["data"].(map[string]any); ok {
			if ac, ok := data["authenticationContext"].(map[string]any); ok {
				if u, ok := ac["user"].(map[string]any); ok {
					gotUPN, _ = u["userPrincipalName"].(string)
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(responseData(
			map[string]any{"CustomRole": "Writer", "DateOfBirth": "01/01/2000"}, provideClaims))
	}))
	defer srv.Close()

	iv := &Invoker{
		Client:       srv.Client(),
		TenantID:     "tenant-1",
		BearerMinter: func(aud string) string { return "sys-token-for-" + aud },
	}
	merged, err := iv.Invoke(Config{Endpoint: srv.URL}, testApp(), testUser())
	if err != nil {
		t.Fatalf("Invoke error: %v", err)
	}
	if merged["CustomRole"] != "Writer" || merged["DateOfBirth"] != "01/01/2000" {
		t.Fatalf("claims not merged: %v", merged)
	}
	if gotType != "microsoft.graph.authenticationEvent.tokenIssuanceStart" {
		t.Fatalf("wrong event type: %q", gotType)
	}
	if gotContentType != "application/json" {
		t.Fatalf("wrong content-type: %q", gotContentType)
	}
	if gotUPN != "alice@example.com" {
		t.Fatalf("wrong user upn: %q", gotUPN)
	}
	if gotBearer != "Bearer sys-token-for-"+srv.URL {
		t.Fatalf("wrong bearer: %q", gotBearer)
	}
}

func TestInvokeNoBearerMinter(t *testing.T) {
	var gotBearer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBearer = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(responseData(map[string]any{"x": "y"}, provideClaims))
	}))
	defer srv.Close()

	iv := &Invoker{Client: srv.Client(), TenantID: "tenant-1"} // BearerMinter nil
	merged, err := iv.Invoke(Config{Endpoint: srv.URL}, testApp(), testUser())
	if err != nil {
		t.Fatalf("Invoke error: %v", err)
	}
	if gotBearer != "" {
		t.Fatalf("no Authorization header expected when BearerMinter is nil, got %q", gotBearer)
	}
	if merged["x"] != "y" {
		t.Fatalf("claims not merged: %v", merged)
	}
}

func TestInvokeAllowlist(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(responseData(
			map[string]any{"Wanted": "yes", "Unwanted": "no"}, provideClaims))
	}))
	defer srv.Close()

	iv := &Invoker{Client: srv.Client(), TenantID: "t"}
	merged, err := iv.Invoke(Config{Endpoint: srv.URL, Claims: []string{"Wanted"}}, testApp(), testUser())
	if err != nil {
		t.Fatalf("Invoke error: %v", err)
	}
	if merged["Wanted"] != "yes" {
		t.Fatal("allowlisted claim should be merged")
	}
	if _, present := merged["Unwanted"]; present {
		t.Fatalf("non-allowlisted claim must be dropped: %v", merged)
	}
}

func TestInvokeSkipsUnknownActionType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Action with a non-provideClaims @odata.type must be skipped entirely.
		_ = json.NewEncoder(w).Encode(responseData(
			map[string]any{"Ignored": "true"}, "microsoft.graph.some.otherAction"))
	}))
	defer srv.Close()

	iv := &Invoker{Client: srv.Client(), TenantID: "t"}
	merged, err := iv.Invoke(Config{Endpoint: srv.URL}, testApp(), testUser())
	if err != nil {
		t.Fatalf("Invoke error: %v", err)
	}
	if len(merged) != 0 {
		t.Fatalf("claims from an unrecognized action type must be skipped: %v", merged)
	}
}

func TestInvokeEmptyActionTypeStillMerges(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Empty @odata.type is treated as provideClaims (the "" guard clause).
		_ = json.NewEncoder(w).Encode(responseData(map[string]any{"K": "V"}, ""))
	}))
	defer srv.Close()

	iv := &Invoker{Client: srv.Client(), TenantID: "t"}
	merged, err := iv.Invoke(Config{Endpoint: srv.URL}, testApp(), testUser())
	if err != nil {
		t.Fatalf("Invoke error: %v", err)
	}
	if merged["K"] != "V" {
		t.Fatalf("claims with empty action type should merge: %v", merged)
	}
}

func TestInvokeNon2xxMapsToStatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	iv := &Invoker{Client: srv.Client(), TenantID: "t"}
	merged, err := iv.Invoke(Config{Endpoint: srv.URL}, testApp(), testUser())
	if err == nil {
		t.Fatal("non-2xx response should return an error")
	}
	if merged != nil {
		t.Fatalf("no claims should be returned on error, got %v", merged)
	}
	se, ok := err.(statusError)
	if !ok || int(se) != http.StatusInternalServerError {
		t.Fatalf("expected statusError(500), got %#v", err)
	}
}

func TestInvokeMalformedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, "{not valid json")
	}))
	defer srv.Close()

	iv := &Invoker{Client: srv.Client(), TenantID: "t"}
	_, err := iv.Invoke(Config{Endpoint: srv.URL}, testApp(), testUser())
	if err == nil {
		t.Fatal("malformed JSON response should return a decode error")
	}
}

func TestInvokeTimeout(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block // never respond until the test closes the channel
	}))
	defer srv.Close()
	defer close(block)

	iv := &Invoker{Client: srv.Client(), TenantID: "t"}
	// TimeoutMs override triggers a fast context deadline.
	_, err := iv.Invoke(Config{Endpoint: srv.URL, TimeoutMs: 100}, testApp(), testUser())
	if err == nil {
		t.Fatal("a hanging webhook should surface a timeout error")
	}
}

func TestInvokeBadEndpointURL(t *testing.T) {
	iv := &Invoker{TenantID: "t"} // nil Client -> http.DefaultClient path
	// A control character in the URL makes http.NewRequestWithContext fail.
	_, err := iv.Invoke(Config{Endpoint: "http://\x7f invalid"}, testApp(), testUser())
	if err == nil {
		t.Fatal("an invalid endpoint URL should return a request-build error")
	}
}

func TestInvokeConnectionError(t *testing.T) {
	// Start then immediately close a server to get an address nothing listens on.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	iv := &Invoker{Client: &http.Client{Timeout: time.Second}, TenantID: "t"}
	_, err := iv.Invoke(Config{Endpoint: url}, testApp(), testUser())
	if err == nil {
		t.Fatal("a dead endpoint should return a transport error")
	}
}

func TestInvokeNilClientUsesDefault(t *testing.T) {
	// A nil Invoker.Client must fall back to http.DefaultClient and still work.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(responseData(map[string]any{"def": "client"}, provideClaims))
	}))
	defer srv.Close()

	iv := &Invoker{TenantID: "t"} // Client is nil
	merged, err := iv.Invoke(Config{Endpoint: srv.URL}, testApp(), testUser())
	if err != nil {
		t.Fatalf("Invoke with nil client error: %v", err)
	}
	if merged["def"] != "client" {
		t.Fatalf("claims not merged via default client: %v", merged)
	}
}

func TestDefaultTimeoutUsedWhenUnset(t *testing.T) {
	// Sanity: a config without TimeoutMs still succeeds against a fast server,
	// exercising the DefaultTimeout branch.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(responseData(map[string]any{"ok": true}, provideClaims))
	}))
	defer srv.Close()

	if DefaultTimeout != 2*time.Second {
		t.Fatalf("DefaultTimeout = %v, want 2s", DefaultTimeout)
	}
	iv := &Invoker{Client: srv.Client(), TenantID: "t"}
	merged, err := iv.Invoke(Config{Endpoint: srv.URL}, testApp(), testUser())
	if err != nil {
		t.Fatalf("Invoke error: %v", err)
	}
	if merged["ok"] != true {
		t.Fatalf("claims not merged: %v", merged)
	}
}
