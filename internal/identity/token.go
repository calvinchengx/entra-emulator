package identity

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// handleToken multiplexes the token endpoint across the four grants.
func (i *Identity) handleToken(w http.ResponseWriter, r *http.Request) {
	// Fault injection (roadmap #5): apply configured latency, then force an
	// OAuth error if one is armed — before any real work.
	if latencyMs, code, desc, fire := i.Faults.TokenFault(); latencyMs > 0 || fire {
		if latencyMs > 0 {
			time.Sleep(time.Duration(latencyMs) * time.Millisecond)
		}
		if fire {
			if desc == "" {
				desc = "Injected fault (roadmap #5 fault injection)."
			}
			httpx.WriteOAuthError(w, code, desc)
			return
		}
	}
	if _, ok := i.tenantSegment(r); !ok {
		httpx.WriteOAuthError(w, "invalid_request", "AADSTS90002: Unknown tenant.")
		return
	}
	if err := r.ParseForm(); err != nil {
		httpx.WriteOAuthError(w, "invalid_request", "AADSTS900144: Malformed request body.")
		return
	}
	switch r.PostFormValue("grant_type") {
	case "authorization_code":
		i.grantAuthorizationCode(w, r)
	case "refresh_token":
		i.grantRefreshToken(w, r)
	case "client_credentials":
		i.grantClientCredentials(w, r)
	case "urn:ietf:params:oauth:grant-type:jwt-bearer":
		i.grantOnBehalfOf(w, r)
	// The URN is canonical/advertised; msal-node actually polls with the
	// bare value — both dispatch to the same handler.
	case "urn:ietf:params:oauth:grant-type:device_code", "device_code":
		i.grantDeviceCode(w, r)
	default:
		httpx.WriteOAuthError(w, "unsupported_grant_type",
			"AADSTS70003: The grant type is not supported.")
	}
}

// authenticateClient enforces the shared client-auth rules: confidential
// clients present a secret (post or basic); public clients must not.
func (i *Identity) authenticateClient(r *http.Request) (*store.App, *httpx.OAuthError) {
	clientID := r.PostFormValue("client_id")
	secret := r.PostFormValue("client_secret")
	if user, pass, ok := r.BasicAuth(); ok {
		if decoded, err := decodeBasicComponent(user); err == nil {
			user = decoded
		}
		if clientID == "" {
			clientID = user
		}
		if clientID == user && pass != "" {
			secret = pass // Basic wins over post when both present
		}
	}
	if clientID == "" {
		return nil, &httpx.OAuthError{Error: "invalid_request",
			ErrorDescription: "AADSTS900144: client_id is required."}
	}
	app, err := i.Store.GetApp(clientID)
	if err != nil {
		return nil, &httpx.OAuthError{Error: "invalid_client",
			ErrorDescription: "AADSTS700016: Application not found in the directory."}
	}
	if app.IsConfidential {
		if secret == "" {
			return nil, &httpx.OAuthError{Error: "invalid_client",
				ErrorDescription: "AADSTS7000215: A client secret is required for confidential clients."}
		}
		ok, err := i.Store.VerifyAppSecret(app.ID, secret)
		if err != nil || !ok {
			return nil, &httpx.OAuthError{Error: "invalid_client",
				ErrorDescription: "AADSTS7000215: Invalid client secret provided."}
		}
	} else if secret != "" {
		return nil, &httpx.OAuthError{Error: "invalid_client",
			ErrorDescription: "AADSTS700025: Public clients must not send a client secret."}
	}
	return app, nil
}

// decodeBasicComponent undoes application/x-www-form-urlencoded escaping in
// Basic credentials (RFC 6749 §2.3.1); raw value wins on bad escapes.
func decodeBasicComponent(s string) (string, error) {
	decoded, err := url.QueryUnescape(s)
	if err != nil {
		return s, nil
	}
	return decoded, nil
}

func (i *Identity) grantAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	app, authErr := i.authenticateClient(r)
	if authErr != nil {
		httpx.WriteOAuthError(w, authErr.Error, authErr.ErrorDescription)
		return
	}
	code := r.PostFormValue("code")
	redirectURI := r.PostFormValue("redirect_uri")
	if code == "" || redirectURI == "" {
		httpx.WriteOAuthError(w, "invalid_request", "AADSTS900144: code and redirect_uri are required.")
		return
	}
	row, err := i.Tokens.RedeemAuthCode(code, app.ID, redirectURI, r.PostFormValue("code_verifier"))
	if err != nil {
		writeRedeemErr(w, err)
		return
	}
	user, err := i.Store.GetUser(row.UserID)
	if err != nil || !user.AccountEnabled {
		httpx.WriteOAuthError(w, "invalid_grant", "AADSTS50057: The user account is disabled or deleted.")
		return
	}
	grantScopes := strings.Fields(row.Scopes)
	// Optional narrowing on exchange.
	if req := SplitScopes(r.PostFormValue("scope")); len(req) > 0 {
		for _, sc := range req {
			if !containsScope(grantScopes, sc) {
				httpx.WriteOAuthError(w, "invalid_scope",
					"AADSTS70011: Requested scope exceeds the authorized grant.")
				return
			}
		}
		grantScopes = req
	}
	resp, err := i.Tokens.BuildDelegatedResponse(tokens.DelegatedGrant{
		App: app, User: user, Scopes: grantScopes, Resource: row.Resource, Nonce: row.Nonce,
	})
	if err != nil {
		httpx.WriteOAuthError(w, "invalid_request", "AADSTS90002: Token minting failed.")
		return
	}
	httpx.NoStore(w)
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (i *Identity) grantRefreshToken(w http.ResponseWriter, r *http.Request) {
	app, authErr := i.authenticateClient(r)
	if authErr != nil {
		httpx.WriteOAuthError(w, authErr.Error, authErr.ErrorDescription)
		return
	}
	rt := r.PostFormValue("refresh_token")
	if rt == "" {
		httpx.WriteOAuthError(w, "invalid_request", "AADSTS900144: refresh_token is required.")
		return
	}
	redeemed, err := i.Tokens.RedeemRefreshToken(rt, app.ID, SplitScopes(r.PostFormValue("scope")))
	if err != nil {
		writeRedeemErr(w, err)
		return
	}
	user, err := i.Store.GetUser(redeemed.UserID)
	if err != nil || !user.AccountEnabled {
		httpx.WriteOAuthError(w, "invalid_grant", "AADSTS50057: The user account is disabled or deleted.")
		return
	}
	resp, err := i.Tokens.BuildDelegatedResponse(tokens.DelegatedGrant{
		App: app, User: user, Scopes: redeemed.Scopes, Resource: redeemed.Resource,
		SkipRefreshToken: true,
	})
	if err != nil {
		httpx.WriteOAuthError(w, "invalid_request", "AADSTS90002: Token minting failed.")
		return
	}
	// The rotation already produced the successor for this chain.
	resp.RefreshToken = redeemed.NewRefreshToken
	httpx.NoStore(w)
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (i *Identity) grantClientCredentials(w http.ResponseWriter, r *http.Request) {
	clientID := r.PostFormValue("client_id")
	if u, _, ok := r.BasicAuth(); ok && clientID == "" {
		clientID = u
	}
	if app, err := i.Store.GetApp(clientID); err == nil && !app.IsConfidential {
		httpx.WriteOAuthError(w, "invalid_client",
			"AADSTS700025: Client credentials requires a confidential client.")
		return
	}
	app, authErr := i.authenticateClient(r)
	if authErr != nil {
		httpx.WriteOAuthError(w, authErr.Error, authErr.ErrorDescription)
		return
	}
	if !app.IsConfidential {
		httpx.WriteOAuthError(w, "invalid_client",
			"AADSTS700025: Client credentials requires a confidential client.")
		return
	}

	rawScope := strings.TrimSpace(r.PostFormValue("scope"))
	if rawScope == "" {
		httpx.WriteOAuthError(w, "invalid_request", "AADSTS900144: scope is required.")
		return
	}
	// MSAL Go (and azidentity) append the reserved OIDC scopes to
	// client-credentials requests; real Entra ignores them, so filter them
	// out before requiring exactly one <resource>/.default value.
	var scopes []string
	for _, sc := range SplitScopes(rawScope) {
		if !oidcScopes[sc] {
			scopes = append(scopes, sc)
		}
	}
	if len(scopes) != 1 || !strings.HasSuffix(scopes[0], "/.default") {
		httpx.WriteOAuthError(w, "invalid_scope",
			"AADSTS1002012: Client credentials requires exactly one <resource>/.default scope.")
		return
	}
	resource := strings.TrimSuffix(scopes[0], "/.default")

	var aud string
	var roles = []string{}
	switch {
	case resource == i.Cfg.GraphResourceID:
		aud = i.Cfg.GraphResourceID
	default:
		resourceApp := i.findResourceApp(resource)
		if resourceApp == nil {
			httpx.WriteOAuthError(w, "invalid_scope",
				"AADSTS500011: The resource principal was not found in the tenant.")
			return
		}
		if resourceApp.AppIDURI == resource {
			aud = resourceApp.AppIDURI
		} else {
			aud = resourceApp.ID
		}
		// App-role auto-grant: every enabled Application-type role.
		if all, err := i.Store.ListRoles(resourceApp.ID); err == nil {
			for _, role := range all {
				if role.IsEnabled && strings.Contains(role.AllowedMemberTypes, "Application") {
					roles = append(roles, role.Value)
				}
			}
		}
	}

	resp, err := i.Tokens.BuildAppOnlyResponse(app, aud, roles, scopes[0])
	if err != nil {
		httpx.WriteOAuthError(w, "invalid_request", "AADSTS90002: Token minting failed.")
		return
	}
	httpx.NoStore(w)
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// writeRedeemErr maps a token-service redemption error onto the wire.
func writeRedeemErr(w http.ResponseWriter, err error) {
	var re *tokens.RedeemErr
	if errors.As(err, &re) {
		httpx.WriteOAuthError(w, re.Code, re.Description)
		return
	}
	httpx.WriteOAuthError(w, "invalid_request", "AADSTS90002: The request could not be processed.")
}

