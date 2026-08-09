package server

import (
	"net/http"
	"testing"
)

// TestOIDCCORS guards the headers a browser SPA needs. Without them MSAL.js
// cannot fetch discovery, the JWKS, or the token endpoint from its own origin,
// so no browser app can authenticate at all — a gap every server-side SDK suite
// missed because none of them is subject to the same-origin policy.
func TestOIDCCORS(t *testing.T) {
	hts, _, _ := newTestServer(t)
	const origin = "http://localhost:4400"

	endpoints := map[string]string{
		"discovery": "/" + tenant + "/v2.0/.well-known/openid-configuration",
		"jwks":      "/" + tenant + "/discovery/v2.0/keys",
		"instance":  "/common/discovery/instance",
	}

	t.Run("metadata endpoints allow the caller's origin", func(t *testing.T) {
		for name, path := range endpoints {
			req, _ := http.NewRequest(http.MethodGet, hts.URL+path, nil)
			req.Header.Set("Origin", origin)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if got := resp.Header.Get("Access-Control-Allow-Origin"); got != origin {
				t.Errorf("%s: Access-Control-Allow-Origin = %q, want %q", name, got, origin)
			}
			if resp.Header.Get("Vary") == "" {
				t.Errorf("%s: reflecting Origin requires Vary: Origin for caches", name)
			}
		}
	})

	t.Run("the token endpoint is preflightable", func(t *testing.T) {
		// Go's ServeMux matches on method, so a POST-only route would 405 the
		// preflight and the real request would never be sent.
		req, _ := http.NewRequest(http.MethodOptions, hts.URL+"/"+tenant+"/oauth2/v2.0/token", nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "POST")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
			t.Fatalf("preflight status = %d", resp.StatusCode)
		}
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != origin {
			t.Errorf("preflight Access-Control-Allow-Origin = %q", got)
		}
		// MSAL.js sends its telemetry headers on the token POST; a preflight
		// that does not allow them fails the real request.
		allowed := resp.Header.Get("Access-Control-Allow-Headers")
		for _, h := range []string{"Content-Type", "x-client-SKU", "client-request-id"} {
			if !containsFold(allowed, h) {
				t.Errorf("preflight does not allow %q (got %q)", h, allowed)
			}
		}
	})

	t.Run("a same-origin request gets no CORS headers", func(t *testing.T) {
		// No Origin header means not a cross-origin request; adding the headers
		// anyway would be noise.
		resp, err := http.Get(hts.URL + "/" + tenant + "/v2.0/.well-known/openid-configuration")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("no Origin sent, but got Access-Control-Allow-Origin = %q", got)
		}
	})
}

// containsFold reports a case-insensitive substring match.
func containsFold(haystack, needle string) bool {
	h, n := []rune(haystack), []rune(needle)
	if len(n) == 0 {
		return true
	}
	lower := func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 32
		}
		return r
	}
	for i := 0; i+len(n) <= len(h); i++ {
		ok := true
		for j := range n {
			if lower(h[i+j]) != lower(n[j]) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
