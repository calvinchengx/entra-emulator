package identity

import (
	"net/http"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// grantOnBehalfOf implements the OAuth 2.0 On-Behalf-Of flow (roadmap #9,
// grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer). A middle-tier API
// exchanges the user access token it received (whose aud is the middle-tier
// itself) for a new token to call a downstream API as the same user.
//
// entra-docs rule enforced: the assertion's aud MUST be the app making the
// request — a token minted for a different resource (e.g. Graph) cannot be
// redeemed via OBO.
func (i *Identity) grantOnBehalfOf(w http.ResponseWriter, r *http.Request) {
	app, authErr := i.authenticateClient(r)
	if authErr != nil {
		httpx.WriteOAuthError(w, authErr.Error, authErr.ErrorDescription)
		return
	}
	// Cert-based client_assertion is roadmap #13; require a secret for now.
	if !app.IsConfidential {
		httpx.WriteOAuthError(w, "invalid_client",
			"AADSTS700025: On-Behalf-Of requires a confidential client.")
		return
	}

	if r.PostFormValue("requested_token_use") != "on_behalf_of" {
		httpx.WriteOAuthError(w, "invalid_request",
			"AADSTS90014: requested_token_use must be 'on_behalf_of'.")
		return
	}
	assertion := r.PostFormValue("assertion")
	if assertion == "" {
		httpx.WriteOAuthError(w, "invalid_request", "AADSTS900144: assertion is required.")
		return
	}

	// The assertion must be one of our access tokens, addressed to THIS app
	// (aud = the middle-tier's appId or app_id_uri). Reject tokens for other
	// resources.
	accepted := []string{app.ID}
	if app.AppIDURI != "" {
		accepted = append(accepted, app.AppIDURI)
	}
	validated, err := i.Tokens.ValidateAccessToken(assertion, accepted)
	if err != nil {
		httpx.WriteOAuthError(w, "invalid_grant",
			"AADSTS500131: The assertion is invalid or not addressed to this application: "+err.Error())
		return
	}
	if validated.OID == "" {
		httpx.WriteOAuthError(w, "invalid_grant",
			"AADSTS500131: On-Behalf-Of requires a delegated (user) assertion.")
		return
	}
	user, err := i.Store.GetUser(validated.OID)
	if err != nil || !user.AccountEnabled {
		httpx.WriteOAuthError(w, "invalid_grant", "AADSTS50057: The user is disabled or deleted.")
		return
	}

	// Downstream scopes → resolve the target resource.
	resolved := i.ResolveDelegatedScopes(SplitScopes(r.PostFormValue("scope")))
	if resolved == nil {
		httpx.WriteOAuthError(w, "invalid_scope", "AADSTS70011: A requested scope is not registered.")
		return
	}

	// Mint a new delegated token for the same user, now issued to the
	// middle-tier (azp/appid = app), audience = the downstream resource.
	resp, err := i.Tokens.BuildDelegatedResponse(tokens.DelegatedGrant{
		App: app, User: user, Scopes: resolved.Granted, Resource: resolved.Resource,
	})
	if err != nil {
		httpx.WriteOAuthError(w, "invalid_request", "AADSTS90002: Token minting failed.")
		return
	}
	httpx.NoStore(w)
	httpx.WriteJSON(w, http.StatusOK, resp)
}
