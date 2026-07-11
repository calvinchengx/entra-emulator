package graph

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/config"
	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// ---- Test harness ----

const (
	aliceID = store.SeedUserAliceID
	bobID   = store.SeedUserBobID
	engID   = store.SeedGroupEngID
	spaID   = store.SeedAppSPAID
)

// newTestGraph builds a Graph over an ephemeral, seeded store (compat origin so
// contextURL/nextLink exercise the /graph collapse branch).
func newTestGraph(t *testing.T) *Graph {
	t.Helper()
	dir := t.TempDir()
	getenv := func(k string) string {
		switch k {
		case "DB_PATH":
			return filepath.Join(dir, "test.db")
		case "TLS_ENABLED":
			return "false"
		case "ORIGIN_MODE":
			return "compat"
		case "PORT":
			return "8443"
		}
		return ""
	}
	cfg, err := config.Load(getenv)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.Seed(cfg.TenantID, cfg.Issuer); err != nil {
		t.Fatal(err)
	}
	signer, err := tokens.EnsureActiveKey(st, cfg.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	ts := &tokens.Service{Store: st, Signer: signer, Cfg: cfg}
	return New(cfg, st, ts)
}

func req(method, target string) *http.Request {
	return httptest.NewRequest(method, target, nil)
}

func reqBody(method, target, body string) *http.Request {
	return httptest.NewRequest(method, target, strings.NewReader(body))
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	return m
}

func userTok(oid string) *tokens.ValidatedToken {
	return &tokens.ValidatedToken{OID: oid, Sub: "sub-" + oid, Claims: map[string]any{}}
}

// ---- Pure OData helpers ----

func TestLiteralValue(t *testing.T) {
	cases := []struct {
		raw       string
		wantVal   any
		wantIsStr bool
		wantOK    bool
	}{
		{"'hello'", "hello", true, true},
		{"''", "", true, true},
		{"true", true, false, true},
		{"FALSE", false, false, true},
		{"null", nil, false, true},
		{"bareword", nil, false, false},
		{"42", nil, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			val, isStr, ok := literalValue(tc.raw)
			if val != tc.wantVal || isStr != tc.wantIsStr || ok != tc.wantOK {
				t.Fatalf("literalValue(%q) = (%v,%v,%v), want (%v,%v,%v)",
					tc.raw, val, isStr, ok, tc.wantVal, tc.wantIsStr, tc.wantOK)
			}
		})
	}
}

func TestValueEquals(t *testing.T) {
	cases := []struct {
		name      string
		got, want any
		wantIsStr bool
		expect    bool
	}{
		{"str match", "x", "x", true, true},
		{"str mismatch", "x", "y", true, false},
		{"nil got empty want", nil, "", true, true},
		{"nil got nonempty want", nil, "x", true, false},
		{"nonstr got coerced", 42, "42", true, true},
		{"bool match", true, true, false, true},
		{"bool mismatch", true, false, false, false},
		{"null match", nil, nil, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := valueEquals(tc.got, tc.want, tc.wantIsStr); got != tc.expect {
				t.Fatalf("valueEquals(%v,%v,%v) = %v, want %v", tc.got, tc.want, tc.wantIsStr, got, tc.expect)
			}
		})
	}
}

func TestFieldString(t *testing.T) {
	shape := map[string]any{"a": "x", "b": nil, "n": 7}
	if got := fieldString(shape, "a"); got != "x" {
		t.Fatalf("present = %q", got)
	}
	if got := fieldString(shape, "missing"); got != "" {
		t.Fatalf("missing = %q", got)
	}
	if got := fieldString(shape, "b"); got != "" {
		t.Fatalf("nil = %q", got)
	}
	if got := fieldString(shape, "n"); got != "7" {
		t.Fatalf("int = %q", got)
	}
}

func TestApplySelect(t *testing.T) {
	shape := map[string]any{"id": "1", "displayName": "Alice", "mail": "a@x"}
	if got := applySelect(shape, nil); len(got) != 3 {
		t.Fatalf("empty fields should return full shape, got %v", got)
	}
	got := applySelect(shape, []string{"displayName", "absent"})
	if got["id"] != "1" || got["displayName"] != "Alice" {
		t.Fatalf("select missing id/displayName: %v", got)
	}
	if _, ok := got["mail"]; ok {
		t.Fatalf("mail should be projected out: %v", got)
	}
	if _, ok := got["absent"]; ok {
		t.Fatalf("absent field should not appear: %v", got)
	}
	// Shape without id: id retention is a no-op.
	noID := applySelect(map[string]any{"x": "1"}, []string{"x"})
	if _, ok := noID["id"]; ok {
		t.Fatalf("no id present should not fabricate one: %v", noID)
	}
}

func TestParseFilter(t *testing.T) {
	shapeA := map[string]any{"displayName": "Alice", "accountEnabled": true, "mail": nil}
	shapeB := map[string]any{"displayName": "Bob", "accountEnabled": false, "mail": "b@x"}

	mustPred := func(expr string) func(map[string]any) bool {
		p, err := parseFilter(expr)
		if err != nil {
			t.Fatalf("parseFilter(%q) error: %v", expr, err)
		}
		return p
	}

	if p := mustPred("startswith(displayName,'Al')"); !p(shapeA) || p(shapeB) {
		t.Fatal("startswith mismatch")
	}
	if p := mustPred("endswith(displayName,'ob')"); p(shapeA) || !p(shapeB) {
		t.Fatal("endswith mismatch")
	}
	if p := mustPred("displayName eq 'Alice'"); !p(shapeA) || p(shapeB) {
		t.Fatal("eq string mismatch")
	}
	if p := mustPred("displayName ne 'Alice'"); p(shapeA) || !p(shapeB) {
		t.Fatal("ne string mismatch")
	}
	if p := mustPred("accountEnabled eq true"); !p(shapeA) || p(shapeB) {
		t.Fatal("eq bool mismatch")
	}
	if p := mustPred("mail eq null"); !p(shapeA) || p(shapeB) {
		t.Fatal("eq null mismatch")
	}

	if _, err := parseFilter("displayName eq bogus"); err == nil {
		t.Fatal("unparseable literal should error")
	}
	if _, err := parseFilter("displayName gt 5"); err == nil {
		t.Fatal("unsupported operator should error")
	}
}

func TestParseODataAndPaging(t *testing.T) {
	q, err := parseOData(req("GET", "/users?$select=displayName,mail&$count=true&$top=5&$skiptoken=2&$filter=displayName+eq+'Alice'"))
	if err != nil {
		t.Fatal(err)
	}
	if len(q.Select) != 2 || q.Select[0] != "displayName" {
		t.Fatalf("select = %v", q.Select)
	}
	if !q.Count {
		t.Fatal("count should be true")
	}
	if q.Top != 5 || q.Skip != 2 {
		t.Fatalf("top/skip = %d/%d", q.Top, q.Skip)
	}
	if q.Filter == nil || !q.Filter(map[string]any{"displayName": "Alice"}) {
		t.Fatal("filter not parsed")
	}

	// Bad filter surfaces an error.
	if _, err := parseOData(req("GET", "/users?$filter=displayName+gt+5")); err == nil {
		t.Fatal("bad filter should error")
	}

	// paging defaults & clamping.
	if top, skip := paging(req("GET", "/users")); top != 100 || skip != 0 {
		t.Fatalf("defaults top/skip = %d/%d", top, skip)
	}
	if top, _ := paging(req("GET", "/users?$top=2000")); top != 999 {
		t.Fatalf("top clamp = %d", top)
	}
	if top, _ := paging(req("GET", "/users?$top=0")); top != 100 {
		t.Fatalf("nonpositive top ignored, got %d", top)
	}
}

func TestSelectEntity(t *testing.T) {
	g := &Graph{}
	shape := map[string]any{"id": "1", "displayName": "Alice", "mail": "a@x"}
	if got := g.selectEntity(req("GET", "/x"), shape); len(got) != 3 {
		t.Fatalf("no select returns full shape: %v", got)
	}
	got := g.selectEntity(req("GET", "/x?$select=displayName"), shape)
	if got["displayName"] != "Alice" || got["id"] != "1" {
		t.Fatalf("selected = %v", got)
	}
	if _, ok := got["mail"]; ok {
		t.Fatalf("mail should be gone: %v", got)
	}
}

func TestContextURLAndNextLink(t *testing.T) {
	// Non-compat: distinct graph origin, no /graph prefix.
	nc := &Graph{Cfg: &config.Config{Origins: config.Origins{
		Graph: "https://graph.example", Login: "https://login.example",
	}}}
	if got := nc.contextURL("users"); got != "https://graph.example/v1.0/$metadata#users" {
		t.Fatalf("non-compat context = %q", got)
	}
	if got := nc.nextLink(req("GET", "/v1.0/users?$top=5"), 5); !strings.HasPrefix(got, "https://graph.example/v1.0/users?") || !strings.Contains(got, "%24skiptoken=5") {
		t.Fatalf("non-compat nextLink = %q", got)
	}

	// Compat: single collapsed origin gets a /graph prefix.
	cp := &Graph{Cfg: &config.Config{Origins: config.Origins{
		Graph: "http://localhost:8443", Login: "http://localhost:8443",
	}}}
	if got := cp.contextURL("groups"); got != "http://localhost:8443/graph/v1.0/$metadata#groups" {
		t.Fatalf("compat context = %q", got)
	}
	if got := cp.nextLink(req("GET", "/v1.0/groups"), 3); !strings.HasPrefix(got, "http://localhost:8443/graph/v1.0/groups?") {
		t.Fatalf("compat nextLink = %q", got)
	}
	// Compat but path already prefixed: no double /graph.
	if got := cp.nextLink(req("GET", "/graph/v1.0/groups"), 3); strings.Contains(got, "/graph/graph/") {
		t.Fatalf("double prefix: %q", got)
	}
}

func TestWriteCollection(t *testing.T) {
	g := &Graph{Cfg: &config.Config{Origins: config.Origins{
		Graph: "https://graph.example", Login: "https://login.example",
	}}}
	shapes := []map[string]any{
		{"id": "1", "displayName": "Alice", "mail": "a@x"},
		{"id": "2", "displayName": "Bob", "mail": "b@x"},
		{"id": "3", "displayName": "Carol", "mail": "c@x"},
	}
	// Filter keeps 2, page size 1 (nextLink expected), count requested, select projects.
	q := odataQuery{
		Select: []string{"displayName"},
		Filter: func(s map[string]any) bool { return s["displayName"] != "Alice" },
		Top:    1,
		Skip:   0,
		Count:  true,
	}
	rec := httptest.NewRecorder()
	g.writeCollection(rec, req("GET", "/v1.0/users?$top=1"), "users", shapes, q)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := decodeBody(t, rec)
	if body["@odata.count"].(float64) != 2 {
		t.Fatalf("count = %v", body["@odata.count"])
	}
	if _, ok := body["@odata.nextLink"]; !ok {
		t.Fatal("nextLink expected when page < count")
	}
	value := body["value"].([]any)
	if len(value) != 1 {
		t.Fatalf("page len = %d", len(value))
	}
	first := value[0].(map[string]any)
	if _, ok := first["mail"]; ok {
		t.Fatalf("mail should be projected out: %v", first)
	}

	// Skip beyond count clamps to empty page, no nextLink.
	rec2 := httptest.NewRecorder()
	g.writeCollection(rec2, req("GET", "/v1.0/users"), "users", shapes, odataQuery{Top: 100, Skip: 99})
	body2 := decodeBody(t, rec2)
	if len(body2["value"].([]any)) != 0 {
		t.Fatalf("expected empty page, got %v", body2["value"])
	}
	if _, ok := body2["@odata.nextLink"]; ok {
		t.Fatal("no nextLink when fully consumed")
	}
}

// ---- Shape / DTO builders ----

func TestShapeBuilders(t *testing.T) {
	u := &store.User{ID: "u1", DisplayName: "Alice", UserPrincipalName: "alice@x",
		Mail: "", GivenName: "Alice", Surname: "", AccountEnabled: true}
	us := userShape(u)
	if us["mail"] != nil || us["surname"] != nil {
		t.Fatalf("empty strings should be null: %v", us)
	}
	if us["givenName"] != "Alice" || us["accountEnabled"] != true {
		t.Fatalf("user shape wrong: %v", us)
	}

	gr := &store.Group{ID: "g1", DisplayName: "Eng", Description: ""}
	gs := groupShape(gr)
	if gs["description"] != nil || gs["mailEnabled"] != false || gs["securityEnabled"] != true {
		t.Fatalf("group shape wrong: %v", gs)
	}

	if nullable("") != nil {
		t.Fatal("nullable empty")
	}
	if nullable("x") != "x" {
		t.Fatal("nullable nonempty")
	}
}

func TestSplitCSV(t *testing.T) {
	got := splitCSV(" Application , User ,, ")
	if len(got) != 2 || got[0] != "Application" || got[1] != "User" {
		t.Fatalf("splitCSV = %v", got)
	}
	if len(splitCSV("")) != 0 {
		t.Fatal("empty csv should be empty slice")
	}
}

func TestRefTailID(t *testing.T) {
	if got := refTailID("https://graph/v1.0/directoryObjects/abc"); got != "abc" {
		t.Fatalf("url tail = %q", got)
	}
	if got := refTailID("  bare  "); got != "bare" {
		t.Fatalf("bare = %q", got)
	}
	if got := refTailID("   "); got != "" {
		t.Fatalf("empty = %q", got)
	}
}

func TestDTOBuilders(t *testing.T) {
	g := newTestGraph(t)
	// Seeded SPA app has an appIDURI + a scope; exercise the populated branches.
	app, err := g.Store.GetApp(spaID)
	if err != nil {
		t.Fatal(err)
	}
	adto := g.applicationDTO(app)
	uris := adto["identifierUris"].([]string)
	if len(uris) != 1 {
		t.Fatalf("expected identifierUris, got %v", uris)
	}
	if scopes := adto["api"].(map[string]any)["oauth2PermissionScopes"].([]map[string]any); len(scopes) == 0 {
		t.Fatal("expected seeded oauth2 scopes")
	}
	spdto := g.servicePrincipalDTO(app)
	if names := spdto["servicePrincipalNames"].([]string); len(names) != 2 {
		t.Fatalf("SP names = %v", names)
	}

	// App with no appIDURI and a role: empty uris branch + appRoleShapes loop.
	roleApp := &store.App{ID: store.NewGUID(), TenantID: g.Cfg.TenantID,
		DisplayName: "RoleApp", CreatedAt: g.Store.Now()}
	if err := g.Store.CreateApp(roleApp); err != nil {
		t.Fatal(err)
	}
	if err := g.Store.AddRole(&store.AppRole{ID: store.NewGUID(), AppID: roleApp.ID,
		Value: "Task.Read", DisplayName: "Read", AllowedMemberTypes: "Application,User", IsEnabled: true}); err != nil {
		t.Fatal(err)
	}
	adto2 := g.applicationDTO(roleApp)
	if len(adto2["identifierUris"].([]string)) != 0 {
		t.Fatalf("no uri app should have empty identifierUris: %v", adto2["identifierUris"])
	}
	roles := adto2["appRoles"].([]map[string]any)
	if len(roles) != 1 || roles[0]["value"] != "Task.Read" {
		t.Fatalf("app roles = %v", roles)
	}
	if amt := roles[0]["allowedMemberTypes"].([]string); len(amt) != 2 {
		t.Fatalf("allowedMemberTypes = %v", amt)
	}
	spNoURI := g.servicePrincipalDTO(roleApp)
	if names := spNoURI["servicePrincipalNames"].([]string); len(names) != 1 {
		t.Fatalf("SP names for no-uri app = %v", names)
	}
}

// ---- Read handlers (direct calls, bypassing auth middleware) ----

func TestHandleMe(t *testing.T) {
	g := newTestGraph(t)
	rec := httptest.NewRecorder()
	g.handleMe(rec, req("GET", "/v1.0/me?$select=displayName"), userTok(aliceID))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body)
	}
	body := decodeBody(t, rec)
	if body["displayName"] != "Alice Example" {
		t.Fatalf("me = %v", body)
	}
	if !strings.Contains(body["@odata.context"].(string), "users/$entity") {
		t.Fatalf("context = %v", body["@odata.context"])
	}

	rec2 := httptest.NewRecorder()
	g.handleMe(rec2, req("GET", "/v1.0/me"), userTok("nonexistent"))
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("missing user status = %d", rec2.Code)
	}
}

func TestHandleUsers(t *testing.T) {
	g := newTestGraph(t)
	rec := httptest.NewRecorder()
	g.handleUsers(rec, req("GET", "/v1.0/users?$count=true"), userTok(aliceID))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := decodeBody(t, rec)
	if body["@odata.count"].(float64) < 2 {
		t.Fatalf("seeded users count = %v", body["@odata.count"])
	}

	// Bad $filter -> 400 (parseOData error branch).
	rec2 := httptest.NewRecorder()
	g.handleUsers(rec2, req("GET", "/v1.0/users?$filter=displayName+gt+5"), userTok(aliceID))
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("bad filter status = %d", rec2.Code)
	}
}

func TestHandleUserByID(t *testing.T) {
	g := newTestGraph(t)
	// By GUID.
	rec := httptest.NewRecorder()
	r := req("GET", "/v1.0/users/x")
	r.SetPathValue("id", aliceID)
	g.handleUserByID(rec, r, userTok(aliceID))
	if rec.Code != http.StatusOK {
		t.Fatalf("by guid status = %d", rec.Code)
	}
	// By UPN (fallback path).
	rec2 := httptest.NewRecorder()
	r2 := req("GET", "/v1.0/users/x")
	r2.SetPathValue("id", "alice@entraemulator.dev")
	g.handleUserByID(rec2, r2, userTok(aliceID))
	if rec2.Code != http.StatusOK {
		t.Fatalf("by upn status = %d body=%s", rec2.Code, rec2.Body)
	}
	// Not found.
	rec3 := httptest.NewRecorder()
	r3 := req("GET", "/v1.0/users/x")
	r3.SetPathValue("id", "nope")
	g.handleUserByID(rec3, r3, userTok(aliceID))
	if rec3.Code != http.StatusNotFound {
		t.Fatalf("missing status = %d", rec3.Code)
	}
}

func TestHandleGroups(t *testing.T) {
	g := newTestGraph(t)
	rec := httptest.NewRecorder()
	g.handleGroups(rec, req("GET", "/v1.0/groups"), userTok(aliceID))
	if rec.Code != http.StatusOK {
		t.Fatalf("groups status = %d", rec.Code)
	}
	// Bad filter.
	rec2 := httptest.NewRecorder()
	g.handleGroups(rec2, req("GET", "/v1.0/groups?$filter=x+gt+1"), userTok(aliceID))
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("bad filter = %d", rec2.Code)
	}

	// By id + not found.
	rec3 := httptest.NewRecorder()
	r := req("GET", "/v1.0/groups/x")
	r.SetPathValue("id", engID)
	g.handleGroupByID(rec3, r, userTok(aliceID))
	if rec3.Code != http.StatusOK {
		t.Fatalf("group by id = %d", rec3.Code)
	}
	rec4 := httptest.NewRecorder()
	r4 := req("GET", "/v1.0/groups/x")
	r4.SetPathValue("id", "nope")
	g.handleGroupByID(rec4, r4, userTok(aliceID))
	if rec4.Code != http.StatusNotFound {
		t.Fatalf("missing group = %d", rec4.Code)
	}
}

func TestHandleGroupMembers(t *testing.T) {
	g := newTestGraph(t)
	rec := httptest.NewRecorder()
	r := req("GET", "/v1.0/groups/x/members")
	r.SetPathValue("id", engID)
	g.handleGroupMembers(rec, r, userTok(aliceID))
	if rec.Code != http.StatusOK {
		t.Fatalf("members status = %d", rec.Code)
	}
	body := decodeBody(t, rec)
	if len(body["value"].([]any)) < 2 {
		t.Fatalf("expected seeded members: %v", body["value"])
	}

	// Missing group.
	rec2 := httptest.NewRecorder()
	r2 := req("GET", "/v1.0/groups/x/members")
	r2.SetPathValue("id", "nope")
	g.handleGroupMembers(rec2, r2, userTok(aliceID))
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("missing group members = %d", rec2.Code)
	}

	// Bad filter.
	rec3 := httptest.NewRecorder()
	r3 := req("GET", "/v1.0/groups/x/members?$filter=x+gt+1")
	r3.SetPathValue("id", engID)
	g.handleGroupMembers(rec3, r3, userTok(aliceID))
	if rec3.Code != http.StatusBadRequest {
		t.Fatalf("bad filter members = %d", rec3.Code)
	}
}

func TestHandleMemberOf(t *testing.T) {
	g := newTestGraph(t)
	// /me/memberOf (id from token).
	rec := httptest.NewRecorder()
	g.handleMemberOf(rec, req("GET", "/v1.0/me/memberOf"), userTok(aliceID))
	if rec.Code != http.StatusOK {
		t.Fatalf("me memberOf = %d", rec.Code)
	}
	body := decodeBody(t, rec)
	if len(body["value"].([]any)) < 1 {
		t.Fatalf("alice should belong to a group: %v", body["value"])
	}

	// /users/{id}/memberOf.
	rec2 := httptest.NewRecorder()
	r := req("GET", "/v1.0/users/x/memberOf")
	r.SetPathValue("id", bobID)
	g.handleMemberOf(rec2, r, userTok(aliceID))
	if rec2.Code != http.StatusOK {
		t.Fatalf("user memberOf = %d", rec2.Code)
	}

	// Missing user.
	rec3 := httptest.NewRecorder()
	r3 := req("GET", "/v1.0/users/x/memberOf")
	r3.SetPathValue("id", "nope")
	g.handleMemberOf(rec3, r3, userTok(aliceID))
	if rec3.Code != http.StatusNotFound {
		t.Fatalf("missing user memberOf = %d", rec3.Code)
	}

	// Bad filter.
	rec4 := httptest.NewRecorder()
	g.handleMemberOf(rec4, req("GET", "/v1.0/me/memberOf?$filter=x+gt+1"), userTok(aliceID))
	if rec4.Code != http.StatusBadRequest {
		t.Fatalf("bad filter memberOf = %d", rec4.Code)
	}
}

func TestHandleUserInfo(t *testing.T) {
	g := newTestGraph(t)
	rec := httptest.NewRecorder()
	g.handleUserInfo(rec, req("GET", "/oidc/userinfo"), userTok(aliceID))
	if rec.Code != http.StatusOK {
		t.Fatalf("userinfo status = %d", rec.Code)
	}
	body := decodeBody(t, rec)
	if body["preferred_username"] != "alice@entraemulator.dev" {
		t.Fatalf("userinfo = %v", body)
	}
	if body["given_name"] == nil || body["family_name"] == nil || body["email"] == nil {
		t.Fatalf("optional claims missing: %v", body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("cache-control header expected")
	}

	// Missing user -> 401.
	rec2 := httptest.NewRecorder()
	g.handleUserInfo(rec2, req("GET", "/oidc/userinfo"), userTok("nope"))
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("missing userinfo = %d", rec2.Code)
	}
}

func TestReadApplicationsAndSPs(t *testing.T) {
	g := newTestGraph(t)
	for _, tc := range []struct {
		name    string
		handler handler
		suffix  string
	}{
		{"applications", g.listApplications, "applications"},
		{"servicePrincipals", g.listServicePrincipals, "servicePrincipals"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.handler(rec, req("GET", "/v1.0/"+tc.suffix), userTok(aliceID))
			if rec.Code != http.StatusOK {
				t.Fatalf("list status = %d", rec.Code)
			}
			// Bad filter.
			rec2 := httptest.NewRecorder()
			tc.handler(rec2, req("GET", "/v1.0/"+tc.suffix+"?$filter=x+gt+1"), userTok(aliceID))
			if rec2.Code != http.StatusBadRequest {
				t.Fatalf("bad filter = %d", rec2.Code)
			}
		})
	}

	// getApplication + getServicePrincipal, found and missing.
	for _, tc := range []struct {
		name    string
		handler handler
	}{
		{"getApplication", g.getApplication},
		{"getServicePrincipal", g.getServicePrincipal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			r := req("GET", "/v1.0/x/y")
			r.SetPathValue("id", spaID)
			tc.handler(rec, r, userTok(aliceID))
			if rec.Code != http.StatusOK {
				t.Fatalf("get status = %d", rec.Code)
			}
			rec2 := httptest.NewRecorder()
			r2 := req("GET", "/v1.0/x/y")
			r2.SetPathValue("id", "nope")
			tc.handler(rec2, r2, userTok(aliceID))
			if rec2.Code != http.StatusNotFound {
				t.Fatalf("missing status = %d", rec2.Code)
			}
		})
	}
}

// ---- Write handlers ----

func TestCreateUpdateDeleteUser(t *testing.T) {
	g := newTestGraph(t)
	tok := &tokens.ValidatedToken{OID: aliceID, Claims: map[string]any{"tid": g.Cfg.TenantID}}

	// Create with password.
	rec := httptest.NewRecorder()
	g.createUser(rec, reqBody("POST", "/v1.0/users",
		`{"displayName":"New User","userPrincipalName":"new@x.dev","accountEnabled":false,"givenName":"New","surname":"User","mail":"new@x.dev","passwordProfile":{"password":"P@ssw0rd!"}}`), tok)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", rec.Code, rec.Body)
	}
	newID := decodeBody(t, rec)["id"].(string)

	// Missing required fields.
	rec2 := httptest.NewRecorder()
	g.createUser(rec2, reqBody("POST", "/v1.0/users", `{"displayName":"x"}`), tok)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("missing upn = %d", rec2.Code)
	}

	// Bad JSON (decodeGraph false).
	rec3 := httptest.NewRecorder()
	g.createUser(rec3, reqBody("POST", "/v1.0/users", `{not json`), tok)
	if rec3.Code != http.StatusBadRequest {
		t.Fatalf("bad json = %d", rec3.Code)
	}

	// Conflict: duplicate UPN -> writeStoreErrGraph ErrConflict.
	rec4 := httptest.NewRecorder()
	g.createUser(rec4, reqBody("POST", "/v1.0/users",
		`{"displayName":"Dup","userPrincipalName":"new@x.dev"}`), tok)
	if rec4.Code != http.StatusBadRequest {
		t.Fatalf("conflict status = %d", rec4.Code)
	}

	// Update.
	rec5 := httptest.NewRecorder()
	r5 := reqBody("PATCH", "/v1.0/users/x",
		`{"displayName":"Renamed","givenName":"R","surname":"S","mail":"r@x","userPrincipalName":"renamed@x.dev","accountEnabled":true,"passwordProfile":{"password":"New1!"}}`)
	r5.SetPathValue("id", newID)
	g.updateUser(rec5, r5, tok)
	if rec5.Code != http.StatusNoContent {
		t.Fatalf("update status = %d body=%s", rec5.Code, rec5.Body)
	}

	// Update missing user.
	rec6 := httptest.NewRecorder()
	r6 := reqBody("PATCH", "/v1.0/users/x", `{"displayName":"x"}`)
	r6.SetPathValue("id", "nope")
	g.updateUser(rec6, r6, tok)
	if rec6.Code != http.StatusNotFound {
		t.Fatalf("update missing = %d", rec6.Code)
	}

	// Update bad JSON.
	rec7 := httptest.NewRecorder()
	r7 := reqBody("PATCH", "/v1.0/users/x", `{bad`)
	r7.SetPathValue("id", newID)
	g.updateUser(rec7, r7, tok)
	if rec7.Code != http.StatusBadRequest {
		t.Fatalf("update bad json = %d", rec7.Code)
	}

	// Delete + delete missing.
	rec8 := httptest.NewRecorder()
	r8 := req("DELETE", "/v1.0/users/x")
	r8.SetPathValue("id", newID)
	g.deleteUser(rec8, r8, tok)
	if rec8.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d", rec8.Code)
	}
	rec9 := httptest.NewRecorder()
	r9 := req("DELETE", "/v1.0/users/x")
	r9.SetPathValue("id", "nope")
	g.deleteUser(rec9, r9, tok)
	if rec9.Code != http.StatusNotFound {
		t.Fatalf("delete missing = %d", rec9.Code)
	}
}

func TestCreateUpdateDeleteGroup(t *testing.T) {
	g := newTestGraph(t)
	tok := &tokens.ValidatedToken{Claims: map[string]any{}} // no tid -> tenantOf home branch

	rec := httptest.NewRecorder()
	g.createGroup(rec, reqBody("POST", "/v1.0/groups", `{"displayName":"Sales","description":"Sales team"}`), tok)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create group = %d", rec.Code)
	}
	gid := decodeBody(t, rec)["id"].(string)

	// Missing displayName.
	rec2 := httptest.NewRecorder()
	g.createGroup(rec2, reqBody("POST", "/v1.0/groups", `{}`), tok)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("missing name = %d", rec2.Code)
	}
	// Bad JSON.
	rec3 := httptest.NewRecorder()
	g.createGroup(rec3, reqBody("POST", "/v1.0/groups", `{bad`), tok)
	if rec3.Code != http.StatusBadRequest {
		t.Fatalf("bad json = %d", rec3.Code)
	}

	// Update + missing + bad json.
	rec4 := httptest.NewRecorder()
	r4 := reqBody("PATCH", "/v1.0/groups/x", `{"displayName":"Sales EU","description":"EU"}`)
	r4.SetPathValue("id", gid)
	g.updateGroup(rec4, r4, tok)
	if rec4.Code != http.StatusNoContent {
		t.Fatalf("update group = %d", rec4.Code)
	}
	rec5 := httptest.NewRecorder()
	r5 := reqBody("PATCH", "/v1.0/groups/x", `{"displayName":"x"}`)
	r5.SetPathValue("id", "nope")
	g.updateGroup(rec5, r5, tok)
	if rec5.Code != http.StatusNotFound {
		t.Fatalf("update missing group = %d", rec5.Code)
	}
	rec5b := httptest.NewRecorder()
	r5b := reqBody("PATCH", "/v1.0/groups/x", `{bad`)
	r5b.SetPathValue("id", gid)
	g.updateGroup(rec5b, r5b, tok)
	if rec5b.Code != http.StatusBadRequest {
		t.Fatalf("update group bad json = %d", rec5b.Code)
	}

	// Members: add (valid + empty ref + bad json), remove (valid + missing group).
	rec6 := httptest.NewRecorder()
	r6 := reqBody("POST", "/v1.0/groups/x/members/$ref",
		`{"@odata.id":"https://graph/v1.0/directoryObjects/`+aliceID+`"}`)
	r6.SetPathValue("id", gid)
	g.addGroupMember(rec6, r6, tok)
	if rec6.Code != http.StatusNoContent {
		t.Fatalf("add member = %d body=%s", rec6.Code, rec6.Body)
	}
	rec7 := httptest.NewRecorder()
	r7 := reqBody("POST", "/v1.0/groups/x/members/$ref", `{"@odata.id":""}`)
	r7.SetPathValue("id", gid)
	g.addGroupMember(rec7, r7, tok)
	if rec7.Code != http.StatusBadRequest {
		t.Fatalf("empty ref = %d", rec7.Code)
	}
	rec7b := httptest.NewRecorder()
	r7b := reqBody("POST", "/v1.0/groups/x/members/$ref", `{bad`)
	r7b.SetPathValue("id", gid)
	g.addGroupMember(rec7b, r7b, tok)
	if rec7b.Code != http.StatusBadRequest {
		t.Fatalf("add member bad json = %d", rec7b.Code)
	}

	rec8 := httptest.NewRecorder()
	r8 := req("DELETE", "/v1.0/groups/x/members/y/$ref")
	r8.SetPathValue("id", gid)
	r8.SetPathValue("userId", aliceID)
	g.removeGroupMember(rec8, r8, tok)
	if rec8.Code != http.StatusNoContent {
		t.Fatalf("remove member = %d", rec8.Code)
	}
	rec9 := httptest.NewRecorder()
	r9 := req("DELETE", "/v1.0/groups/x/members/y/$ref")
	r9.SetPathValue("id", "nope")
	r9.SetPathValue("userId", aliceID)
	g.removeGroupMember(rec9, r9, tok)
	if rec9.Code != http.StatusNotFound {
		t.Fatalf("remove from missing group = %d", rec9.Code)
	}

	// Delete group + missing.
	rec10 := httptest.NewRecorder()
	r10 := req("DELETE", "/v1.0/groups/x")
	r10.SetPathValue("id", gid)
	g.deleteGroup(rec10, r10, tok)
	if rec10.Code != http.StatusNoContent {
		t.Fatalf("delete group = %d", rec10.Code)
	}
	rec11 := httptest.NewRecorder()
	r11 := req("DELETE", "/v1.0/groups/x")
	r11.SetPathValue("id", "nope")
	g.deleteGroup(rec11, r11, tok)
	if rec11.Code != http.StatusNotFound {
		t.Fatalf("delete missing group = %d", rec11.Code)
	}
}

func TestCreateUpdateDeleteApplication(t *testing.T) {
	g := newTestGraph(t)
	tok := &tokens.ValidatedToken{Claims: map[string]any{"tid": g.Cfg.TenantID}}

	rec := httptest.NewRecorder()
	g.createApplication(rec, reqBody("POST", "/v1.0/applications",
		`{"displayName":"MyApp","identifierUris":["api://myapp"]}`), tok)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create app = %d body=%s", rec.Code, rec.Body)
	}
	appID := decodeBody(t, rec)["id"].(string)

	// Missing displayName.
	rec2 := httptest.NewRecorder()
	g.createApplication(rec2, reqBody("POST", "/v1.0/applications", `{}`), tok)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("missing name = %d", rec2.Code)
	}
	// Bad JSON.
	rec3 := httptest.NewRecorder()
	g.createApplication(rec3, reqBody("POST", "/v1.0/applications", `{bad`), tok)
	if rec3.Code != http.StatusBadRequest {
		t.Fatalf("bad json = %d", rec3.Code)
	}

	// Update: set uris then clear them (both identifierUris branches).
	rec4 := httptest.NewRecorder()
	r4 := reqBody("PATCH", "/v1.0/applications/x", `{"displayName":"MyApp2","identifierUris":["api://myapp2"]}`)
	r4.SetPathValue("id", appID)
	g.updateApplication(rec4, r4, tok)
	if rec4.Code != http.StatusNoContent {
		t.Fatalf("update app = %d", rec4.Code)
	}
	rec5 := httptest.NewRecorder()
	r5 := reqBody("PATCH", "/v1.0/applications/x", `{"identifierUris":[]}`)
	r5.SetPathValue("id", appID)
	g.updateApplication(rec5, r5, tok)
	if rec5.Code != http.StatusNoContent {
		t.Fatalf("clear uris = %d", rec5.Code)
	}
	// Update missing + bad json.
	rec6 := httptest.NewRecorder()
	r6 := reqBody("PATCH", "/v1.0/applications/x", `{"displayName":"x"}`)
	r6.SetPathValue("id", "nope")
	g.updateApplication(rec6, r6, tok)
	if rec6.Code != http.StatusNotFound {
		t.Fatalf("update missing app = %d", rec6.Code)
	}
	rec7 := httptest.NewRecorder()
	r7 := reqBody("PATCH", "/v1.0/applications/x", `{bad`)
	r7.SetPathValue("id", appID)
	g.updateApplication(rec7, r7, tok)
	if rec7.Code != http.StatusBadRequest {
		t.Fatalf("update app bad json = %d", rec7.Code)
	}

	// Delete + missing.
	rec8 := httptest.NewRecorder()
	r8 := req("DELETE", "/v1.0/applications/x")
	r8.SetPathValue("id", appID)
	g.deleteApplication(rec8, r8, tok)
	if rec8.Code != http.StatusNoContent {
		t.Fatalf("delete app = %d", rec8.Code)
	}
	rec9 := httptest.NewRecorder()
	r9 := req("DELETE", "/v1.0/applications/x")
	r9.SetPathValue("id", "nope")
	g.deleteApplication(rec9, r9, tok)
	if rec9.Code != http.StatusNotFound {
		t.Fatalf("delete missing app = %d", rec9.Code)
	}
}

// ---- Auth middleware ----

func TestValidateAndMiddleware(t *testing.T) {
	g := newTestGraph(t)
	// Point advertised issuer/origins at values consistent with tokens the
	// service mints (home issuer). config.Load already set these coherently.

	// No bearer header.
	if tok, msg := g.validate(req("GET", "/x")); tok != nil || msg == "" {
		t.Fatalf("missing bearer should fail: %v %q", tok, msg)
	}
	// Invalid token.
	r := req("GET", "/x")
	r.Header.Set("Authorization", "Bearer not.a.jwt")
	if tok, msg := g.validate(r); tok != nil || msg == "" {
		t.Fatalf("invalid token should fail: %v %q", tok, msg)
	}

	// App-only (system) token: valid, but no OID.
	appOnly := g.Tokens.MintSystemToken(g.Cfg.GraphResourceID)
	rv := req("GET", "/x")
	rv.Header.Set("Authorization", "Bearer "+appOnly)
	tok, msg := g.validate(rv)
	if tok == nil {
		t.Fatalf("system token should validate: %q", msg)
	}
	if tok.OID != "" {
		t.Fatalf("system token should be app-only, oid=%q", tok.OID)
	}

	called := false
	next := func(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) { called = true }

	// requireBearer success.
	recB := httptest.NewRecorder()
	rb := req("GET", "/x")
	rb.Header.Set("Authorization", "Bearer "+appOnly)
	g.requireBearer(next)(recB, rb)
	if !called || recB.Code != http.StatusOK {
		t.Fatalf("requireBearer success: called=%v code=%d", called, recB.Code)
	}
	// requireBearer 401.
	recU := httptest.NewRecorder()
	g.requireBearer(next)(recU, req("GET", "/x"))
	if recU.Code != http.StatusUnauthorized {
		t.Fatalf("requireBearer no token = %d", recU.Code)
	}

	// requireDelegated: app-only -> 403.
	recF := httptest.NewRecorder()
	rf := req("GET", "/me")
	rf.Header.Set("Authorization", "Bearer "+appOnly)
	g.requireDelegated(next)(recF, rf)
	if recF.Code != http.StatusForbidden {
		t.Fatalf("requireDelegated app-only = %d", recF.Code)
	}

	// Delegated token (has oid) for the success path.
	app, _ := g.Store.GetApp(spaID)
	alice, _ := g.Store.GetUser(aliceID)
	resp, err := g.Tokens.BuildDelegatedResponse(tokens.DelegatedGrant{
		App: app, User: alice, Scopes: []string{"openid"},
	})
	if err != nil {
		t.Fatalf("build delegated: %v", err)
	}
	called = false
	recD := httptest.NewRecorder()
	rd := req("GET", "/me")
	rd.Header.Set("Authorization", "Bearer "+resp.AccessToken)
	g.requireDelegated(next)(recD, rd)
	if !called || recD.Code != http.StatusOK {
		t.Fatalf("requireDelegated success: called=%v code=%d", called, recD.Code)
	}

	// requireDelegatedUserInfo: no token -> 401 with WWW-Authenticate.
	recI := httptest.NewRecorder()
	g.requireDelegatedUserInfo(next)(recI, req("GET", "/oidc/userinfo"))
	if recI.Code != http.StatusUnauthorized || !strings.Contains(recI.Header().Get("WWW-Authenticate"), "invalid_token") {
		t.Fatalf("userinfo no token = %d hdr=%q", recI.Code, recI.Header().Get("WWW-Authenticate"))
	}
	// App-only -> 403 insufficient_scope.
	recI2 := httptest.NewRecorder()
	ri2 := req("GET", "/oidc/userinfo")
	ri2.Header.Set("Authorization", "Bearer "+appOnly)
	g.requireDelegatedUserInfo(next)(recI2, ri2)
	if recI2.Code != http.StatusForbidden || !strings.Contains(recI2.Header().Get("WWW-Authenticate"), "insufficient_scope") {
		t.Fatalf("userinfo app-only = %d", recI2.Code)
	}
	// Delegated -> success.
	called = false
	recI3 := httptest.NewRecorder()
	ri3 := req("GET", "/oidc/userinfo")
	ri3.Header.Set("Authorization", "Bearer "+resp.AccessToken)
	g.requireDelegatedUserInfo(next)(recI3, ri3)
	if !called || recI3.Code != http.StatusOK {
		t.Fatalf("userinfo delegated success: called=%v code=%d", called, recI3.Code)
	}
}

// TestStoreClosedErrors exercises the InternalServerError branches (store
// returning a non-sentinel DB error) and writeStoreErrGraph's default arm.
func TestStoreClosedErrors(t *testing.T) {
	g := newTestGraph(t)
	tok := userTok(aliceID)
	if err := g.Store.Close(); err != nil {
		t.Fatal(err)
	}

	// List collection handlers: ListX returns a db error -> 500.
	for _, h := range []struct {
		name    string
		handler handler
		path    string
	}{
		{"users", g.handleUsers, "/v1.0/users"},
		{"groups", g.handleGroups, "/v1.0/groups"},
		{"applications", g.listApplications, "/v1.0/applications"},
		{"servicePrincipals", g.listServicePrincipals, "/v1.0/servicePrincipals"},
	} {
		rec := httptest.NewRecorder()
		h.handler(rec, req("GET", h.path), tok)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("%s closed-store status = %d", h.name, rec.Code)
		}
	}

	// Write paths: the store call returns a non-sentinel db error, exercising
	// writeStoreErrGraph's default arm (500).
	wtok := &tokens.ValidatedToken{Claims: map[string]any{"tid": g.Cfg.TenantID}}
	writeCases := []struct {
		name    string
		call    func(w http.ResponseWriter, r *http.Request)
		request *http.Request
	}{
		{"createUser", func(w http.ResponseWriter, r *http.Request) { g.createUser(w, r, wtok) },
			reqBody("POST", "/v1.0/users", `{"displayName":"X","userPrincipalName":"x@x.dev","passwordProfile":{"password":"P@ss1!"}}`)},
		{"createGroup", func(w http.ResponseWriter, r *http.Request) { g.createGroup(w, r, wtok) },
			reqBody("POST", "/v1.0/groups", `{"displayName":"X"}`)},
		{"createApplication", func(w http.ResponseWriter, r *http.Request) { g.createApplication(w, r, wtok) },
			reqBody("POST", "/v1.0/applications", `{"displayName":"X"}`)},
		{"deleteUser", func(w http.ResponseWriter, r *http.Request) { g.deleteUser(w, r, wtok) },
			pathReq("DELETE", "id", aliceID)},
		{"updateUser", func(w http.ResponseWriter, r *http.Request) { g.updateUser(w, r, wtok) },
			pathBodyReq("PATCH", `{"displayName":"X"}`, "id", aliceID)},
		{"updateGroup", func(w http.ResponseWriter, r *http.Request) { g.updateGroup(w, r, wtok) },
			pathBodyReq("PATCH", `{"displayName":"X"}`, "id", engID)},
		{"updateApplication", func(w http.ResponseWriter, r *http.Request) { g.updateApplication(w, r, wtok) },
			pathBodyReq("PATCH", `{"displayName":"X"}`, "id", spaID)},
		{"addGroupMember", func(w http.ResponseWriter, r *http.Request) { g.addGroupMember(w, r, wtok) },
			pathBodyReq("POST", `{"@odata.id":"x/`+aliceID+`"}`, "id", engID)},
		{"removeGroupMember", func(w http.ResponseWriter, r *http.Request) { g.removeGroupMember(w, r, wtok) },
			pathReq("DELETE", "id", engID)},
	}
	for _, tc := range writeCases {
		rec := httptest.NewRecorder()
		tc.call(rec, tc.request)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("%s closed-store status = %d", tc.name, rec.Code)
		}
	}
}

func pathReq(method, key, val string) *http.Request {
	r := req(method, "/v1.0/x")
	r.SetPathValue(key, val)
	return r
}

func pathBodyReq(method, body, key, val string) *http.Request {
	r := reqBody(method, "/v1.0/x", body)
	r.SetPathValue(key, val)
	return r
}

func TestRegisterRoutes(t *testing.T) {
	g := newTestGraph(t)
	// Register both prefixes to exercise Register/registerReads/registerWrites.
	mux := http.NewServeMux()
	g.Register(mux, "")
	mux2 := http.NewServeMux()
	g.Register(mux2, "/graph")
}
