package identity

import (
	"fmt"
	"html"
	"net/http"
	"net/url"

	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// authorizeState is the HMAC-signed snapshot of an authorize request that
// survives the interactive sign-in POST.
type authorizeState struct {
	Kind         string `json:"kind"` // "authorize"
	Tenant       string `json:"tenant"`
	ClientID     string `json:"clientId"`
	RedirectURI  string `json:"redirectUri"`
	Scope        string `json:"scope"`
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	Challenge    string `json:"challenge"`
	Method       string `json:"method"`
	ResponseMode string `json:"responseMode"`
}

func (i *Identity) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if _, ok := i.tenantSegment(r); !ok {
		i.renderErrorPage(w, http.StatusBadRequest, "Invalid request", "Unknown tenant.")
		return
	}

	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		if r.PostFormValue(fieldState) != "" {
			i.handleSignInSubmit(w, r)
			return
		}
	}

	param := func(k string) string {
		if r.Method == http.MethodPost {
			return r.PostFormValue(k)
		}
		return r.URL.Query().Get(k)
	}

	st := authorizeState{
		Kind:         "authorize",
		Tenant:       r.PathValue("tenant"),
		ClientID:     param("client_id"),
		RedirectURI:  param("redirect_uri"),
		Scope:        param("scope"),
		State:        param("state"),
		Nonce:        param("nonce"),
		Challenge:    param("code_challenge"),
		Method:       param("code_challenge_method"),
		ResponseMode: param("response_mode"),
	}
	prompt := param("prompt")
	loginHint := param("login_hint")

	// client_id + redirect_uri failures NEVER redirect (open-redirect guard).
	app, err := i.Store.GetApp(st.ClientID)
	if err != nil {
		i.renderErrorPage(w, http.StatusBadRequest, "Invalid request",
			"Unknown client_id: the application is not registered.")
		return
	}
	if ok, _ := i.Store.HasRedirectURI(app.ID, st.RedirectURI); !ok {
		i.renderErrorPage(w, http.StatusBadRequest, "Invalid request",
			"The redirect_uri is not registered for this application.")
		return
	}

	redirectErr := func(code, desc string) {
		i.deliverAuthorizeError(w, st, code, desc)
	}
	if param("response_type") != "code" {
		redirectErr("unsupported_response_type", "Only response_type=code is supported.")
		return
	}
	scopes := SplitScopes(st.Scope)
	if !containsScope(scopes, "openid") {
		redirectErr("invalid_scope", "The openid scope is required.")
		return
	}
	if i.ResolveDelegatedScopes(scopes) == nil {
		redirectErr("invalid_scope", "A requested resource scope is not registered.")
		return
	}
	if !app.IsConfidential && st.Challenge == "" {
		redirectErr("invalid_request", "Public clients must send a PKCE code_challenge.")
		return
	}
	if st.Challenge != "" && st.Method == "" {
		st.Method = "plain"
	}
	if st.Method != "" && st.Method != "S256" && st.Method != "plain" {
		redirectErr("invalid_request", "code_challenge_method must be S256 or plain.")
		return
	}

	// Session / prompt resolution.
	_, user := i.currentSession(r)
	switch {
	case prompt == "none":
		if user == nil {
			redirectErr("login_required", "No active session and prompt=none.")
			return
		}
	case prompt == "login" || prompt == "select_account":
		user = nil // force interaction
	}
	if user != nil {
		i.issueCodeAndDeliver(w, st, app, user)
		return
	}

	i.renderSignIn(w, r, st, loginHint, "")
}

// renderSignIn shows the account picker or password form for the request.
func (i *Identity) renderSignIn(w http.ResponseWriter, r *http.Request, st authorizeState, loginHint, errMsg string) {
	action := "/" + st.Tenant + "/oauth2/v2.0/authorize"
	signed := i.signState(st)
	if i.Cfg.RequirePassword {
		i.renderPasswordForm(w, action, signed, nil, loginHint, errMsg)
		return
	}
	users, _, err := i.Store.ListUsers(100, 0, "")
	if err != nil {
		i.renderErrorPage(w, http.StatusInternalServerError, "Error", "Could not list accounts.")
		return
	}
	enabled := users[:0]
	for _, u := range users {
		if u.AccountEnabled {
			enabled = append(enabled, u)
		}
	}
	// login_hint pre-selection: float the matching user to the top.
	if loginHint != "" {
		for idx, u := range enabled {
			if u.UserPrincipalName == loginHint && idx > 0 {
				enabled[0], enabled[idx] = enabled[idx], enabled[0]
			}
		}
	}
	i.renderAccountPicker(w, action, signed, enabled, nil, errMsg)
}

// handleSignInSubmit consumes the interactive POST from the picker or
// password form, creates the SSO session, and issues the code.
func (i *Identity) handleSignInSubmit(w http.ResponseWriter, r *http.Request) {
	var st authorizeState
	if !i.verifyState(r.PostFormValue(fieldState), &st) || st.Kind != "authorize" {
		i.renderErrorPage(w, http.StatusBadRequest, "Invalid request", "The sign-in state is invalid or expired.")
		return
	}
	app, err := i.Store.GetApp(st.ClientID)
	if err != nil {
		i.renderErrorPage(w, http.StatusBadRequest, "Invalid request", "Unknown client.")
		return
	}

	var user *store.User
	if i.Cfg.RequirePassword {
		upn := r.PostFormValue(fieldUsername)
		user, err = i.Store.VerifyPassword(upn, r.PostFormValue(fieldPassword))
		if err != nil {
			i.renderSignIn(w, r, st, upn, "Incorrect email or password.")
			return
		}
	} else {
		user, err = i.Store.GetUser(r.PostFormValue(fieldUser))
		if err != nil || !user.AccountEnabled {
			i.renderSignIn(w, r, st, "", "Select a valid account.")
			return
		}
	}

	i.createSession(w, user.ID)
	i.issueCodeAndDeliver(w, st, app, user)
}

// issueCodeAndDeliver mints the auth code and returns it per response_mode.
func (i *Identity) issueCodeAndDeliver(w http.ResponseWriter, st authorizeState, app *store.App, user *store.User) {
	resolved := i.ResolveDelegatedScopes(SplitScopes(st.Scope))
	if resolved == nil {
		i.deliverAuthorizeError(w, st, "invalid_scope", "A requested resource scope is not registered.")
		return
	}
	code, err := i.Tokens.IssueAuthCode(tokens.AuthCodeRequest{
		AppID: app.ID, UserID: user.ID, RedirectURI: st.RedirectURI,
		Scopes: resolved.Granted, Resource: resolved.Resource,
		CodeChallenge: st.Challenge, ChallengeMethod: st.Method, Nonce: st.Nonce,
	})
	if err != nil {
		i.renderErrorPage(w, http.StatusInternalServerError, "Error", "Could not issue an authorization code.")
		return
	}
	i.deliverAuthorizeResult(w, st, url.Values{"code": {code}})
}

func (i *Identity) deliverAuthorizeError(w http.ResponseWriter, st authorizeState, code, desc string) {
	i.deliverAuthorizeResult(w, st, url.Values{"error": {code}, "error_description": {desc}})
}

// deliverAuthorizeResult sends params to the validated redirect_uri using
// the requested response_mode (query default, fragment, or form_post).
func (i *Identity) deliverAuthorizeResult(w http.ResponseWriter, st authorizeState, params url.Values) {
	if st.State != "" {
		params.Set("state", st.State)
	}
	switch st.ResponseMode {
	case "form_post":
		fields := ""
		for k, vs := range params {
			fields += fmt.Sprintf(`<input type="hidden" name="%s" value="%s">`,
				html.EscapeString(k), html.EscapeString(vs[0]))
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, `<!doctype html><html><body onload="document.forms[0].submit()">
<form method="post" action="%s">%s<noscript><button type="submit">Continue</button></noscript></form>
</body></html>`, html.EscapeString(st.RedirectURI), fields)
	case "fragment":
		http.Redirect(w, i.dummyReq(), st.RedirectURI+"#"+params.Encode(), http.StatusFound)
	default: // query
		sep := "?"
		if u, err := url.Parse(st.RedirectURI); err == nil && u.RawQuery != "" {
			sep = "&"
		}
		http.Redirect(w, i.dummyReq(), st.RedirectURI+sep+params.Encode(), http.StatusFound)
	}
}

// dummyReq satisfies http.Redirect's request parameter for absolute URLs.
func (i *Identity) dummyReq() *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	return r
}

func containsScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}
