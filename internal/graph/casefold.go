package graph

import (
	"net/http"
	"net/url"
	"strings"
)

// Case-insensitive resource paths.
//
// Microsoft documents that "Path URL resource names, query parameters, and
// action parameters and values are case insensitive. However, values you assign,
// entity IDs, and other base64-encoded values are case-sensitive"
// (https://learn.microsoft.com/graph/call-api), and, more broadly, to assume
// "path URL resource names, query parameters, action and function names ... are
// not case-sensitive" (https://learn.microsoft.com/graph/traverse-the-graph).
// Microsoft's own examples use `/me/mailfolders` and `/me/mailFolders` for the
// same request.
//
// http.ServeMux matches paths exactly, so before this the emulator answered
// `/v1.0/USERS` with a 404 where Graph answers it. The previous answer to that
// was to register a second spelling of one collection ("oAuth2PermissionGrants"),
// which covered one accidental casing out of the 2^n a client may send.
//
// HOW IT WORKS. The folder sits in front of the mux and learns every Graph
// pattern as it is registered. For a request it finds the registered pattern the
// path matches when literal segments are compared ignoring case, and rewrites the
// path so those literal segments carry the registered spelling. WILDCARD SEGMENTS
// (ids, alternate-key values) ARE PASSED THROUGH UNTOUCHED, which is what keeps
// "entity IDs are case-sensitive" true.
//
// THE REWRITE HAS TO HAPPEN BEFORE ANY HANDLER RUNS, not merely before routing:
// permissionDenied and resourcePath read the request path and switch on its
// first segment case-sensitively, so a handler that ran on `/v1.0/USERS` would
// find no requirement for "USERS" and skip the permission gate.
//
// Only paths under prefix + "/v1.0/" are folded. The rule Microsoft documents is
// about Graph resource paths; the emulator's own routes (/oidc/userinfo, the
// compat-mode /graph prefix itself, everything on the other surfaces) are left
// exact.

// foldSeg is one segment of a registered pattern.
type foldSeg struct {
	lit  string
	wild bool
}

type foldPattern struct {
	method string // "" when the pattern names no method
	segs   []foldSeg
}

// allows mirrors ServeMux: a GET pattern also serves HEAD.
func (p *foldPattern) allows(method string) bool {
	return p.method == "" || p.method == method || (p.method == http.MethodGet && method == http.MethodHead)
}

// moreSpecific reports whether a beats b, ServeMux-style: at the first segment
// where one is a literal and the other a wildcard, the literal wins. This is why
// `/v1.0/users` beats the whole-segment catch-all `/v1.0/{key}`.
func moreSpecific(a, b *foldPattern) bool {
	for i := range a.segs {
		if a.segs[i].wild != b.segs[i].wild {
			return !a.segs[i].wild
		}
	}
	return false
}

// CaseFolder is a Router that forwards to the mux it wraps and remembers each
// Graph pattern, so Wrap can canonicalise the casing of request paths.
type CaseFolder struct {
	mux    Router
	prefix string
	pats   []foldPattern
}

// NewCaseFolder returns a folder for the Graph surface mounted at prefix ("" or
// "/graph"). Register Graph through it, then Wrap the mux.
func NewCaseFolder(mux Router, prefix string) *CaseFolder {
	return &CaseFolder{mux: mux, prefix: prefix}
}

// HandleFunc implements Router.
func (f *CaseFolder) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	f.mux.HandleFunc(pattern, handler)
	f.learn(pattern)
}

func (f *CaseFolder) learn(pattern string) {
	method, path := "", pattern
	if i := strings.IndexByte(pattern, ' '); i >= 0 {
		method, path = pattern[:i], strings.TrimSpace(pattern[i+1:])
	}
	root := f.prefix + "/v1.0/"
	if !strings.HasPrefix(path, root) {
		return
	}
	// Segments from "v1.0" on: the prefix is the emulator's mounting, not Graph.
	parts := strings.Split(strings.TrimPrefix(path, f.prefix+"/"), "/")
	segs := make([]foldSeg, len(parts))
	for i, s := range parts {
		switch {
		case strings.HasPrefix(s, "{"):
			// Only whole-segment `{name}` wildcards are understood. A silent
			// mis-parse here would fold wrongly, so an unsupported pattern
			// stops registration instead.
			if !strings.HasSuffix(s, "}") || strings.Contains(s, "...") || strings.Contains(s, "$") {
				panic("graph: case folding does not support the pattern " + pattern)
			}
			segs[i] = foldSeg{wild: true}
		default:
			segs[i] = foldSeg{lit: s}
		}
	}
	f.pats = append(f.pats, foldPattern{method: method, segs: segs})
}

// Wrap returns next with request paths canonicalised first.
func (f *CaseFolder) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.fold(r)
		next.ServeHTTP(w, r)
	})
}

// fold rewrites r.URL in place. In place, deliberately: the response recorder
// wraps the whole server and reads the path after the request is served, so it
// records the spelling Microsoft's OpenAPI uses rather than whatever the client
// happened to send.
func (f *CaseFolder) fold(r *http.Request) {
	escaped := r.URL.EscapedPath()
	if !strings.HasPrefix(escaped, f.prefix+"/") {
		return
	}
	rest := strings.TrimPrefix(escaped, f.prefix+"/")
	if len(rest) < len("v1.0/") || !strings.EqualFold(rest[:len("v1.0/")], "v1.0/") {
		return
	}
	segs := strings.Split(rest, "/")

	// A pattern for this method is preferred; failing that, any method's, so a
	// wrong-method request still reaches the mux at a canonical path and gets
	// its own 405 rather than a 404 for a spelling.
	best := f.match(r.Method, segs)
	if best == nil {
		best = f.match("", segs)
	}
	if best == nil {
		return
	}
	out := make([]string, len(segs))
	for i, s := range best.segs {
		if s.wild {
			out[i] = segs[i]
		} else {
			out[i] = s.lit
		}
	}
	canon := f.prefix + "/" + strings.Join(out, "/")
	if canon == escaped {
		return
	}
	decoded, err := url.PathUnescape(canon)
	if err != nil {
		return
	}
	r.URL.Path, r.URL.RawPath = decoded, canon
}

// match returns the most specific pattern the segments match with literals
// compared case-insensitively, or nil.
func (f *CaseFolder) match(method string, segs []string) *foldPattern {
	var best *foldPattern
	for i := range f.pats {
		p := &f.pats[i]
		if len(p.segs) != len(segs) || (method != "" && !p.allows(method)) {
			continue
		}
		ok := true
		for j, s := range p.segs {
			if s.wild {
				continue
			}
			got, err := url.PathUnescape(segs[j])
			if err != nil || !strings.EqualFold(got, s.lit) {
				ok = false
				break
			}
		}
		if ok && (best == nil || moreSpecific(p, best)) {
			best = p
		}
	}
	return best
}
