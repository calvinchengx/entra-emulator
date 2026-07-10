// Package server wires the three surfaces onto one listener with
// Host-header routing (docs/08-tls-and-origins.md).
package server

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/calvinchengx/entra-emulator/internal/admin"
	"github.com/calvinchengx/entra-emulator/internal/config"
	"github.com/calvinchengx/entra-emulator/internal/faults"
	"github.com/calvinchengx/entra-emulator/internal/graph"
	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/identity"
	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tlscert"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

type Server struct {
	Cfg     *config.Config
	Handler http.Handler
	cert    *tlscert.Material
}

// New assembles the full handler stack.
func New(cfg *config.Config, st *store.Store, ts *tokens.Service, cert *tlscert.Material, version string) *Server {
	// One fault-injection store shared between the STS (applies faults) and
	// the admin API (controls them).
	fs := faults.New()
	id := identity.New(cfg, st, ts, fs)
	gr := graph.New(cfg, st, ts)
	ad := admin.New(cfg, st, ts, fs, cert, version)

	// login surface: OIDC only + /health-free root descriptor.
	loginMux := http.NewServeMux()
	id.Register(loginMux)
	id.RegisterMSI(loginMux)
	loginMux.HandleFunc("GET /{$}", surfaceDescriptor("login"))

	// graph surface: unprefixed Graph + userinfo.
	graphMux := http.NewServeMux()
	gr.Register(graphMux, "")
	graphMux.HandleFunc("GET /{$}", surfaceDescriptor("graph"))

	// portal surface: admin API + health + SPA fallback.
	portalMux := http.NewServeMux()
	ad.Register(portalMux)
	portalMux.HandleFunc("/", portalFallback)

	// compat surface: everything (graph under /graph).
	compatMux := http.NewServeMux()
	id.Register(compatMux)
	id.RegisterMSI(compatMux)
	gr.Register(compatMux, "/graph")
	ad.Register(compatMux)
	compatMux.HandleFunc("/", portalFallback)

	root := &hostRouter{
		cfg: cfg, login: loginMux, graph: graphMux, portal: portalMux, compat: compatMux,
	}
	return &Server{Cfg: cfg, Handler: root, cert: cert}
}

// hostRouter selects the surface mux from the Host header; unknown hosts
// (including localhost) get the unrestricted compat surface.
type hostRouter struct {
	cfg                          *config.Config
	login, graph, portal, compat http.Handler
}

func (h *hostRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host[i:], "]") {
		host = host[:i]
	}
	switch {
	case host == originHost(h.cfg.Origins.Login) && h.cfg.Origins.Login != h.cfg.Origins.Portal:
		h.login.ServeHTTP(w, r)
	case host == originHost(h.cfg.Origins.Graph) && h.cfg.Origins.Graph != h.cfg.Origins.Portal:
		h.graph.ServeHTTP(w, r)
	case host == originHost(h.cfg.Origins.Portal) && h.cfg.Origins.Login != h.cfg.Origins.Portal:
		h.portal.ServeHTTP(w, r)
	default:
		h.compat.ServeHTTP(w, r)
	}
}

func originHost(origin string) string {
	u, err := url.Parse(origin)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func surfaceDescriptor(role string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{
			"service": "entra-emulator", "surface": role,
		})
	}
}

// apiPrefixes are never shadowed by the SPA fallback.
var apiPrefixes = []string{"/admin/", "/graph/", "/health"}

// portalFallback serves the portal SPA for non-API GETs and JSON 404s for
// unmatched API paths.
func portalFallback(w http.ResponseWriter, r *http.Request) {
	for _, p := range apiPrefixes {
		if strings.HasPrefix(r.URL.Path, p) {
			httpx.WriteJSON(w, http.StatusNotFound, map[string]any{
				"error": map[string]string{"code": "not_found", "message": "No such API route."}})
			return
		}
	}
	// Tenant-prefixed paths that fell through are unknown OIDC routes.
	if seg := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2); len(seg) == 2 &&
		(seg[0] == "common" || seg[0] == "organizations" || seg[0] == "consumers" || looksLikeGUID(seg[0])) {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]any{
			"error": map[string]string{"code": "not_found", "message": "No such API route."}})
		return
	}
	if r.Method != http.MethodGet {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]any{
			"error": map[string]string{"code": "not_found", "message": "Not found."}})
		return
	}
	servePortal(w, r)
}

func looksLikeGUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

// Listen starts serving (TLS unless disabled) and blocks.
func (s *Server) Listen() error {
	addr := fmt.Sprintf("%s:%d", s.Cfg.Host, s.Cfg.Port)
	srv := &http.Server{Addr: addr, Handler: s.Handler}
	if !s.Cfg.TLSEnabled {
		return srv.ListenAndServe()
	}
	pair, err := s.cert.Certificate()
	if err != nil {
		return err
	}
	srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return srv.ServeTLS(ln, "", "")
}
