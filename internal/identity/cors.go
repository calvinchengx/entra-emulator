package identity

import "net/http"

// CORS on the OIDC surface. Without it no browser SPA can authenticate at all:
// MSAL.js fetches the discovery document, the JWKS and the token endpoint with
// XHR from the app's own origin, and the same-origin policy blocks every one of
// them unless the server opts in. Real Entra sets these headers, which is why
// MSAL.js works against it.
//
// This gap was invisible to the server-side SDK suites (msal-node, MSAL Go,
// .NET, Java, Python) because none of them run inside a browser — it took the
// msal-browser witness to surface it.
//
// The token endpoint is gated the way Entra gates it: CORS is granted only when
// the calling origin matches a redirect URI this application registered as type
// `spa`. Being MORE permissive would be worse than useless — an app that works
// locally would fail against real Entra with exactly the error the emulator
// exists to surface early.

// withCORS answers preflight and adds the response headers a browser needs.
func withCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			setCORSHeaders(w, origin)
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

// withTokenCORS grants CORS on the token endpoint only to an origin the app
// registered as an `spa` redirect URI, matching Entra. The client_id is in the
// form body, so the form is parsed here — handleToken's own ParseForm then
// returns the cached values.
func (i *Identity) withTokenCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			_ = r.ParseForm()
			if clientID := r.PostFormValue("client_id"); clientID != "" {
				if ok, err := i.Store.HasSPARedirectOrigin(clientID, origin); err == nil && ok {
					setCORSHeaders(w, origin)
				}
			}
		}
		next(w, r)
	}
}

// registerCORSPreflight mounts OPTIONS handlers for the endpoints a browser
// preflights. Go's ServeMux matches on method, so a POST-only route would
// otherwise 405 the preflight and the real request never happens.
func registerCORSPreflight(mux *http.ServeMux) {
	for _, p := range []string{
		"/{tenant}/v2.0/.well-known/openid-configuration",
		"/{tenant}/discovery/v2.0/keys",
		"/{tenant}/oauth2/v2.0/token",
		"/common/discovery/instance",
	} {
		mux.HandleFunc("OPTIONS "+p, withCORS(func(w http.ResponseWriter, r *http.Request) {}))
	}
}

// setCORSHeaders reflects the caller's origin. Reflecting rather than "*" keeps
// working if a client ever sends credentials, and matches what Entra returns.
func setCORSHeaders(w http.ResponseWriter, origin string) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Add("Vary", "Origin")
	h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	h.Set("Access-Control-Allow-Headers",
		"Authorization, Content-Type, x-client-SKU, x-client-VER, x-client-OS, "+
			"x-client-CPU, client-request-id, x-client-current-telemetry, "+
			"x-client-last-telemetry, x-ms-lib-capability, x-app-name, x-app-ver")
	h.Set("Access-Control-Expose-Headers", "client-request-id, x-ms-request-id")
	h.Set("Access-Control-Max-Age", "86400")
}
