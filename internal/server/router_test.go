package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/config"
)

// marker returns a handler that records which surface served the request.
func marker(name string, got *string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { *got = name })
}

// TestHostRouter verifies subdomain-mode routing by Host header — the path the
// compat-mode integration harness never exercises.
func TestHostRouter(t *testing.T) {
	cfg := &config.Config{Origins: config.Origins{
		Login:  "https://login.entra.localhost:8443",
		Graph:  "https://graph.entra.localhost:8443",
		Portal: "https://portal.entra.localhost:8443",
	}}
	var served string
	h := &hostRouter{
		cfg:    cfg,
		login:  marker("login", &served),
		graph:  marker("graph", &served),
		portal: marker("portal", &served),
		compat: marker("compat", &served),
	}

	cases := map[string]string{
		"login.entra.localhost:8443":   "login",
		"graph.entra.localhost:8443":   "graph",
		"portal.entra.localhost:8443":  "portal",
		"unknown.entra.localhost:8443": "compat",
		"127.0.0.1:8443":               "compat",
	}
	for host, want := range cases {
		served = ""
		req := httptest.NewRequest("GET", "http://"+host+"/x", nil)
		req.Host = host
		h.ServeHTTP(httptest.NewRecorder(), req)
		if served != want {
			t.Fatalf("host %q routed to %q, want %q", host, served, want)
		}
	}
}

// TestHostRouterCompatCollapse: when surfaces share an origin (compat), every
// host falls through to the compat handler.
func TestHostRouterCompatCollapse(t *testing.T) {
	origin := "http://localhost:8080"
	cfg := &config.Config{Origins: config.Origins{Login: origin, Graph: origin, Portal: origin}}
	var served string
	h := &hostRouter{cfg: cfg, login: marker("login", &served), graph: marker("graph", &served),
		portal: marker("portal", &served), compat: marker("compat", &served)}
	req := httptest.NewRequest("GET", origin+"/x", nil)
	req.Host = "localhost:8080"
	h.ServeHTTP(httptest.NewRecorder(), req)
	if served != "compat" {
		t.Fatalf("collapsed origins should route to compat, got %q", served)
	}
}

func TestSurfaceDescriptor(t *testing.T) {
	rec := httptest.NewRecorder()
	surfaceDescriptor("login")(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"surface":"login"`) {
		t.Fatalf("surface descriptor: %d %s", rec.Code, rec.Body.String())
	}
}

func TestPortalFallback(t *testing.T) {
	cases := []struct {
		method, path string
		wantCode     int
	}{
		{"GET", "/admin/api/whatever", 404},                             // API prefix → JSON 404
		{"GET", "/11111111-1111-1111-1111-111111111111/oauth2", 404},    // tenant-prefixed → 404
		{"GET", "/common/oauth2/v2.0/authorize", 404},                   // alias-prefixed → 404
		{"POST", "/some/spa/route", 404},                                // non-GET non-API → 404
		{"GET", "/dashboard", 200},                                      // SPA GET → portal
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		portalFallback(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != tc.wantCode {
			t.Fatalf("%s %s: want %d, got %d", tc.method, tc.path, tc.wantCode, rec.Code)
		}
	}
}

func TestLooksLikeGUID(t *testing.T) {
	if !looksLikeGUID("11111111-1111-1111-1111-111111111111") {
		t.Fatal("valid GUID rejected")
	}
	for _, bad := range []string{"", "common", "11111111", "zzzzzzzz-1111-1111-1111-111111111111",
		"111111111-111-1111-1111-111111111111"} {
		if looksLikeGUID(bad) {
			t.Fatalf("invalid GUID accepted: %q", bad)
		}
	}
}
