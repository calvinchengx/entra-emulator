package identity

import (
	"net/http"
	"strings"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// grantResourceOwnerPassword implements the Resource Owner Password
// Credentials grant (`grant_type=password`, roadmap #12). Deprecated in
// production (no MFA/Conditional Access/consent), but pragmatic for headless
// CI sign-ins. Ref: entra-docs v2-oauth-ropc.
func (i *Identity) grantResourceOwnerPassword(w http.ResponseWriter, r *http.Request) {
	app, authErr := i.authenticateClient(r)
	if authErr != nil {
		httpx.WriteOAuthError(w, authErr.Error, authErr.ErrorDescription)
		return
	}
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")
	if username == "" || password == "" {
		httpx.WriteOAuthError(w, "invalid_request", "AADSTS900144: username and password are required.")
		return
	}
	rawScope := strings.TrimSpace(r.PostFormValue("scope"))
	if rawScope == "" {
		httpx.WriteOAuthError(w, "invalid_scope", "AADSTS70011: scope is required.")
		return
	}
	scopes := SplitScopes(rawScope)
	resolved := i.ResolveDelegatedScopes(scopes)
	if resolved == nil {
		httpx.WriteOAuthError(w, "invalid_scope", "AADSTS70011: A requested scope is not registered.")
		return
	}

	user, err := i.Store.VerifyPassword(username, password)
	if err != nil {
		// Entra returns invalid_grant (AADSTS50126) for a bad credential.
		httpx.WriteOAuthError(w, "invalid_grant",
			"AADSTS50126: Error validating credentials due to invalid username or password.")
		return
	}

	resp, err := i.Tokens.BuildDelegatedResponse(tokens.DelegatedGrant{
		App: app, User: user, Scopes: resolved.Granted, Resource: resolved.Resource, AMR: "pwd",
	})
	if err != nil {
		httpx.WriteOAuthError(w, "invalid_request", "AADSTS90002: Token minting failed.")
		return
	}
	httpx.NoStore(w)
	httpx.WriteJSON(w, http.StatusOK, resp)
}
