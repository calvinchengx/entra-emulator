package identity

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// handleInstanceDiscovery answers MSAL's authority-validation probe
// (GET /common/discovery/instance?api-version=1.1&authorization_endpoint=…).
// MSAL calls this before every token request; a 404 fails the whole login. The
// reply names this emulator as the preferred network for the authority so MSAL
// keeps talking to us, and points tenant discovery at our OIDC document.
func (i *Identity) handleInstanceDiscovery(w http.ResponseWriter, r *http.Request) {
	host := i.Cfg.Origins.Login
	if u, err := url.Parse(i.Cfg.Origins.Login); err == nil && u.Host != "" {
		host = u.Host
	}
	// Derive the tenant discovery endpoint from the requested authorization
	// endpoint (…/{tenant}/oauth2/v2.0/authorize → …/{tenant}/v2.0/.well-known/
	// openid-configuration); fall back to our own login origin + tenant.
	tenantDiscovery := i.Cfg.Origins.Login + "/" + i.Cfg.TenantID + "/v2.0/.well-known/openid-configuration"
	if authz := r.URL.Query().Get("authorization_endpoint"); authz != "" {
		tenantDiscovery = strings.Replace(authz, "/oauth2/v2.0/authorize", "/v2.0/.well-known/openid-configuration", 1)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"tenant_discovery_endpoint": tenantDiscovery,
		"api-version":               "1.1",
		"metadata": []map[string]any{{
			"preferred_network": host,
			"preferred_cache":   host,
			"aliases":           []string{host},
		}},
	})
}

// handleDiscovery serves the MSAL-tuned OIDC discovery document. The issuer
// and endpoints are always GUID-form regardless of the alias requested.
func (i *Identity) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	tid, ok := i.tenantSegment(r)
	if !ok {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]any{
			"error": map[string]string{"code": "invalid_tenant", "message": "Unknown tenant."}})
		return
	}
	login := i.Cfg.Origins.Login
	base := login + "/" + tid
	doc := map[string]any{
		"issuer":                        i.issuerFor(tid),
		"authorization_endpoint":        base + "/oauth2/v2.0/authorize",
		"token_endpoint":                base + "/oauth2/v2.0/token",
		"device_authorization_endpoint": base + "/oauth2/v2.0/devicecode",
		"jwks_uri":                      base + "/discovery/v2.0/keys",
		"userinfo_endpoint":             i.userinfoEndpoint(),
		"end_session_endpoint":          base + "/oauth2/v2.0/logout",
		"response_types_supported":      []string{"code"},
		"response_modes_supported":      []string{"query", "fragment", "form_post"},
		"grant_types_supported": []string{
			"authorization_code", "refresh_token", "client_credentials", "password",
			"urn:ietf:params:oauth:grant-type:device_code",
			"urn:ietf:params:oauth:grant-type:jwt-bearer",
		},
		"subject_types_supported":               []string{"pairwise"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		// private_key_jwt is implemented (see verifyClientAssertion in token.go);
		// advertise it or a spec-driven client never tries certificate auth.
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic", "private_key_jwt"},
		// RP-initiated logout at end_session_endpoint (post_logout_redirect_uri +
		// state) really works, so http_logout_supported is honest. We do NOT
		// advertise frontchannel_logout_supported: that promises the OP calls each
		// RP's frontchannel_logout_uri, which this emulator does not do.
		"http_logout_supported":            true,
		"code_challenge_methods_supported": []string{"S256", "plain"},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "nbf", "tid", "oid",
			"name", "preferred_username", "email", "nonce", "ver",
		},
		// Cloud-instance metadata. Real Entra advertises the sovereign-cloud
		// coordinates here (microsoftonline.com / graph.microsoft.com / pas.windows.net);
		// the emulator advertises its own local origins so a client that reads
		// these fields is pointed back at the emulator rather than the real cloud.
		"tenant_region_scope":   "LOC",
		"cloud_instance_name":   i.cloudInstanceName(),
		"cloud_graph_host_name": hostOf(i.Cfg.Origins.Graph),
		"msgraph_host":          hostOf(i.Cfg.Origins.Graph),
		"rbac_url":              i.Cfg.Origins.Graph,
	}
	w.Header().Set("Cache-Control", "public, max-age=3600")
	httpx.WriteJSON(w, http.StatusOK, doc)
}

// issuerFor returns the GUID-form issuer for a tenant: the configured home
// issuer for the home tenant, or {loginOrigin}/{tid}/v2.0 for others.
func (i *Identity) issuerFor(tid string) string {
	if tid == i.Cfg.TenantID {
		return i.Cfg.Issuer
	}
	return i.Cfg.Origins.Login + "/" + tid + "/v2.0"
}

// userinfoEndpoint lives on the Graph origin; the compat origin serves it
// under the /graph prefix.
func (i *Identity) userinfoEndpoint() string {
	if i.Cfg.Origins.Graph == i.Cfg.Origins.Login {
		return i.Cfg.Origins.Graph + "/graph/oidc/userinfo"
	}
	return i.Cfg.Origins.Graph + "/oidc/userinfo"
}

// hostOf reduces an origin to its host[:port], the shape Entra uses for the
// *_host_name discovery fields. Falls back to the raw value if unparseable.
func hostOf(origin string) string {
	if u, err := url.Parse(origin); err == nil && u.Host != "" {
		return u.Host
	}
	return origin
}

// cloudInstanceName is Entra's `microsoftonline.com` slot — the emulator names
// its own login host so clients resolve back here, never to the real cloud.
func (i *Identity) cloudInstanceName() string {
	return hostOf(i.Cfg.Origins.Login)
}

func (i *Identity) handleJWKS(w http.ResponseWriter, r *http.Request) {
	tid, ok := i.tenantSegment(r)
	if !ok {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]any{
			"error": map[string]string{"code": "invalid_tenant", "message": "Unknown tenant."}})
		return
	}
	// Ensure a non-home tenant has an active signing key before serving JWKS.
	if tid != i.Cfg.TenantID {
		if _, err := i.Tokens.SignerForTenant(tid); err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{
				"error": map[string]string{"code": "internal_error", "message": err.Error()}})
			return
		}
	}
	raw, err := tokens.JWKS(i.Store, tid)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{
			"error": map[string]string{"code": "internal_error", "message": err.Error()}})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
