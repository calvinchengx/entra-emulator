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
// Divergence worth knowing: Entra enables CORS on the TOKEN endpoint only for
// applications with a redirect URI registered as type `spa`. The emulator
// allows any origin, which is friendlier locally but will not reproduce the
// "you forgot to register the redirect URI as SPA" failure. See docs/parity.md.

// withCORS answers preflight and adds the response headers a browser needs.
func withCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			h := w.Header()
			// Reflect the origin rather than "*": a reflected origin keeps
			// working if a client ever sends credentials, and matches what
			// Entra returns for the token endpoint.
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
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
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
