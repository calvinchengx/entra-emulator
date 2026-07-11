package identity

import (
	"net/http"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// handleDiscovery serves the MSAL-tuned OIDC discovery document. The issuer
// and endpoints are always GUID-form regardless of the alias requested.
func (i *Identity) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	if _, ok := i.tenantSegment(r); !ok {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]any{
			"error": map[string]string{"code": "invalid_tenant", "message": "Unknown tenant."}})
		return
	}
	login := i.Cfg.Origins.Login
	base := login + "/" + i.Cfg.TenantID
	doc := map[string]any{
		"issuer":                        i.Cfg.Issuer,
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
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		"code_challenge_methods_supported":      []string{"S256", "plain"},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "nbf", "tid", "oid",
			"name", "preferred_username", "email", "nonce", "ver",
		},
	}
	w.Header().Set("Cache-Control", "public, max-age=3600")
	httpx.WriteJSON(w, http.StatusOK, doc)
}

// userinfoEndpoint lives on the Graph origin; the compat origin serves it
// under the /graph prefix.
func (i *Identity) userinfoEndpoint() string {
	if i.Cfg.Origins.Graph == i.Cfg.Origins.Login {
		return i.Cfg.Origins.Graph + "/graph/oidc/userinfo"
	}
	return i.Cfg.Origins.Graph + "/oidc/userinfo"
}

func (i *Identity) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if _, ok := i.tenantSegment(r); !ok {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]any{
			"error": map[string]string{"code": "invalid_tenant", "message": "Unknown tenant."}})
		return
	}
	raw, err := tokens.JWKS(i.Store, i.Cfg.TenantID)
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
