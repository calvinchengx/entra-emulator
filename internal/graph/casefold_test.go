package graph

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// foldHarness registers a small Graph-shaped route table through a CaseFolder
// and reports, for a request, which pattern answered and what the handler saw.
type foldHarness struct {
	h http.Handler
}

type foldSeen struct {
	route string // the pattern that answered ("" for the mux's own 404/405)
	path  string // r.URL.Path as the handler saw it
	id    string // PathValue("id"), to prove wildcard segments are untouched
}

func newFoldHarness(t *testing.T, prefix string) (*foldHarness, *foldSeen) {
	t.Helper()
	mux := http.NewServeMux()
	f := NewCaseFolder(mux, prefix)
	seen := &foldSeen{}
	handle := func(pattern string) {
		f.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			*seen = foldSeen{route: pattern, path: r.URL.Path, id: r.PathValue("id")}
		})
	}
	handle("GET " + prefix + "/v1.0/users")
	handle("GET " + prefix + "/v1.0/users/{id}")
	handle("GET " + prefix + "/v1.0/users/{id}/memberOf")
	handle("POST " + prefix + "/v1.0/users/{id}/getMemberGroups")
	handle("GET " + prefix + "/v1.0/groups/{id}/members/$ref")
	handle("GET " + prefix + "/v1.0/oauth2PermissionGrants")
	handle("DELETE " + prefix + "/v1.0/oauth2PermissionGrants/{id}")
	// The whole-segment catch-all, as reads.go registers it.
	handle("GET " + prefix + "/v1.0/{key}")
	// Outside /v1.0/: not Graph resource paths, so never folded.
	handle("GET " + prefix + "/oidc/userinfo")
	return &foldHarness{h: f.Wrap(mux)}, seen
}

func (fh *foldHarness) do(method, target string, seen *foldSeen) foldSeen {
	*seen = foldSeen{}
	fh.h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(method, target, nil))
	return *seen
}

func TestCaseFolderCanonicalisesLiteralsAndLeavesWildcardsAlone(t *testing.T) {
	const prefix = "/graph"
	fh, seen := newFoldHarness(t, prefix)

	for _, tc := range []struct {
		name, method, target string
		route, path, id      string
	}{
		{"canonical is untouched", "GET", "/graph/v1.0/users", "GET /graph/v1.0/users", "/graph/v1.0/users", ""},
		{"upper-cased collection", "GET", "/graph/v1.0/USERS", "GET /graph/v1.0/users", "/graph/v1.0/users", ""},
		{"version segment folds too", "GET", "/graph/V1.0/users", "GET /graph/v1.0/users", "/graph/v1.0/users", ""},
		{"the id keeps the caller's case",
			"GET", "/graph/v1.0/USERS/AbCd-EF12", "GET /graph/v1.0/users/{id}", "/graph/v1.0/users/AbCd-EF12", "AbCd-EF12"},
		{"nested relation",
			"GET", "/graph/v1.0/users/AbC/MEMBEROF", "GET /graph/v1.0/users/{id}/memberOf", "/graph/v1.0/users/AbC/memberOf", "AbC"},
		{"action name", "POST", "/graph/v1.0/users/x/GETMEMBERGROUPS",
			"POST /graph/v1.0/users/{id}/getMemberGroups", "/graph/v1.0/users/x/getMemberGroups", "x"},
		{"$ref literal", "GET", "/graph/v1.0/GROUPS/g1/MEMBERS/$REF",
			"GET /graph/v1.0/groups/{id}/members/$ref", "/graph/v1.0/groups/g1/members/$ref", "g1"},
		// The case this whole change exists for.
		{"the formerly special-cased grant spelling", "GET", "/graph/v1.0/oAuth2PermissionGrants",
			"GET /graph/v1.0/oauth2PermissionGrants", "/graph/v1.0/oauth2PermissionGrants", ""},
		{"all-lowercase grant spelling", "DELETE", "/graph/v1.0/oauth2permissiongrants/G-1",
			"DELETE /graph/v1.0/oauth2PermissionGrants/{id}", "/graph/v1.0/oauth2PermissionGrants/G-1", "G-1"},
		// A literal route must beat the catch-all, or every folded collection
		// would be answered by the alternate-key handler.
		{"a literal beats the {key} catch-all", "GET", "/graph/v1.0/USERS",
			"GET /graph/v1.0/users", "/graph/v1.0/users", ""},
		{"an unknown resource still reaches the catch-all untouched", "GET", "/graph/v1.0/NoSuchThing",
			"GET /graph/v1.0/{key}", "/graph/v1.0/NoSuchThing", ""},
		{"an encoded slash in an id survives", "GET", "/graph/v1.0/USERS/a%2Fb",
			"GET /graph/v1.0/users/{id}", "/graph/v1.0/users/a/b", "a/b"},
		// Wrong method: still canonicalised so the mux says 405 about the real
		// path, and no handler runs.
		{"wrong method reaches no handler", "PUT", "/graph/v1.0/USERS", "", "", ""},
		// Not Graph resource paths: exact, as before.
		{"outside /v1.0/ is not folded", "GET", "/graph/OIDC/USERINFO", "", "", ""},
		{"the mounting prefix is not folded", "GET", "/GRAPH/v1.0/users", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := fh.do(tc.method, tc.target, seen)
			if got.route != tc.route || got.path != tc.path || got.id != tc.id {
				t.Errorf("%s %s:\n got  route=%q path=%q id=%q\n want route=%q path=%q id=%q",
					tc.method, tc.target, got.route, got.path, got.id, tc.route, tc.path, tc.id)
			}
		})
	}
}

// The same table on the graph host, where Graph has no prefix at all.
func TestCaseFolderWithoutAPrefix(t *testing.T) {
	fh, seen := newFoldHarness(t, "")
	got := fh.do("GET", "/V1.0/USERS/AbC", seen)
	if got.route != "GET /v1.0/users/{id}" || got.id != "AbC" {
		t.Errorf("got %+v", got)
	}
}

// A pattern the folder cannot represent has to stop registration: mis-parsing
// it would fold wrongly and say nothing.
func TestCaseFolderRefusesPatternsItCannotFold(t *testing.T) {
	for _, pattern := range []string{
		"GET /v1.0/files/{path...}",
		"GET /v1.0/{$}",
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("registering %q did not panic", pattern)
				}
			}()
			NewCaseFolder(http.NewServeMux(), "").HandleFunc(pattern, func(http.ResponseWriter, *http.Request) {})
		}()
	}
}

// No pattern the emulator really registers may be one the folder refuses, and
// none may be spelled with a second casing of another.
func TestRegisteredPatternsAreFoldableAndUnambiguous(t *testing.T) {
	seen := map[string]string{}
	for _, p := range RegisteredPatterns("") {
		NewCaseFolder(http.NewServeMux(), "").learn(p) // panics on an unfoldable pattern
		method, path := "", p
		for i := 0; i < len(p); i++ {
			if p[i] == ' ' {
				method, path = p[:i], p[i+1:]
				break
			}
		}
		key := method + " " + lowerASCII(path)
		if other, dup := seen[key]; dup && other != p {
			t.Errorf("%q and %q differ only in case; case-insensitive paths make them one route", p, other)
		}
		seen[key] = p
	}
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
