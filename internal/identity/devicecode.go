package identity

import (
	"crypto/rand"
	"fmt"
	"html"
	"math/big"
	"net/http"
	"strings"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// user_code alphabet: ambiguity-reduced consonants (RFC 8628 §6.1 guidance).
const userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

func newUserCode() string {
	var b strings.Builder
	for i := 0; i < 8; i++ {
		if i == 4 {
			b.WriteByte('-')
		}
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(userCodeAlphabet))))
		if err != nil {
			panic(err)
		}
		b.WriteByte(userCodeAlphabet[n.Int64()])
	}
	return b.String()
}

// normalizeUserCode uppercases, strips non-alphabet characters, and regroups.
func normalizeUserCode(raw string) string {
	var letters []byte
	for _, c := range strings.ToUpper(raw) {
		if strings.ContainsRune(userCodeAlphabet, c) {
			letters = append(letters, byte(c))
		}
	}
	if len(letters) != 8 {
		return ""
	}
	return string(letters[:4]) + "-" + string(letters[4:])
}

// deviceApprovalState is the signed state for the approval-page flow. SID is
// required on the decide step (CSRF binding to the live session).
type deviceApprovalState struct {
	Kind     string `json:"kind"` // "device"
	UserCode string `json:"userCode"`
	SID      string `json:"sid"`
}

// handleDeviceAuthorization is RFC 8628 §3.1/3.2 (machine JSON endpoint).
func (i *Identity) handleDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	tenantSeg, ok := i.tenantSegment(r)
	if !ok {
		httpx.WriteOAuthError(w, "invalid_request", "AADSTS90002: Unknown tenant.")
		return
	}
	if err := r.ParseForm(); err != nil {
		httpx.WriteOAuthError(w, "invalid_request", "AADSTS900144: Malformed request body.")
		return
	}
	app, authErr := i.authenticateClient(r)
	if authErr != nil {
		httpx.WriteOAuthError(w, authErr.Error, authErr.ErrorDescription)
		return
	}
	scopes := SplitScopes(r.PostFormValue("scope"))
	if len(scopes) == 0 {
		httpx.WriteOAuthError(w, "invalid_scope", "AADSTS70011: scope is required.")
		return
	}
	if i.ResolveDelegatedScopes(scopes) == nil {
		httpx.WriteOAuthError(w, "invalid_scope", "AADSTS70011: A requested scope is not registered.")
		return
	}

	deviceCode := store.NewOpaqueToken(32)
	userCode := ""
	for attempt := 0; attempt < 5; attempt++ {
		candidate := newUserCode()
		if exists, _ := i.Store.UserCodeExists(candidate); !exists {
			userCode = candidate
			break
		}
	}
	if userCode == "" {
		httpx.WriteOAuthError(w, "invalid_request", "AADSTS90002: Could not allocate a user code.")
		return
	}
	now := i.Store.Now()
	if err := i.Store.InsertDeviceCode(&store.DeviceCode{
		DeviceCodeHash: store.HashToken(deviceCode), UserCode: userCode, AppID: app.ID,
		Scopes: strings.Join(scopes, " "), Status: "pending",
		Interval: i.Cfg.DeviceInterval, ExpiresAt: now + int64(i.Cfg.Lifetimes.DeviceCode), CreatedAt: now,
	}); err != nil {
		httpx.WriteOAuthError(w, "invalid_request", "AADSTS90002: Could not persist the device code.")
		return
	}

	verificationURI := fmt.Sprintf("%s/%s/oauth2/v2.0/devicecode", i.Cfg.Origins.Login, tenantSeg)
	httpx.NoStore(w)
	// verification_uri_complete is intentionally omitted: real Entra does not
	// return it (documented in entra-docs v2-oauth2-device-code), even though
	// RFC 8628 lists it as optional. We match Entra for client fidelity.
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"device_code":      deviceCode,
		"user_code":        userCode,
		"verification_uri": verificationURI,
		"expires_in":       i.Cfg.Lifetimes.DeviceCode,
		"interval":         i.Cfg.DeviceInterval,
		"message": fmt.Sprintf(
			"To sign in, open %s in a browser and enter the code %s to authenticate.",
			verificationURI, userCode),
	})
}

// grantDeviceCode is the /token polling handler (RFC 8628 §3.4/3.5). Extra
// MSAL poll parameters (scope, client_info, telemetry) are ignored.
func (i *Identity) grantDeviceCode(w http.ResponseWriter, r *http.Request) {
	app, authErr := i.authenticateClient(r)
	if authErr != nil {
		httpx.WriteOAuthError(w, authErr.Error, authErr.ErrorDescription)
		return
	}
	plaintext := r.PostFormValue("device_code")
	if plaintext == "" {
		httpx.WriteOAuthError(w, "invalid_request", "AADSTS900144: device_code is required.")
		return
	}
	hash := store.HashToken(plaintext)
	row, err := i.Store.GetDeviceCodeByHash(hash)
	if err != nil {
		// entra-docs names an unrecognized device_code bad_verification_code.
		httpx.WriteOAuthError(w, "bad_verification_code", "AADSTS70019: The device code is unknown or already redeemed.")
		return
	}
	if row.AppID != app.ID {
		httpx.WriteOAuthError(w, "bad_verification_code", "AADSTS70019: The device code is bound to a different client.")
		return
	}
	now := i.Store.Now()
	switch {
	case row.ExpiresAt <= now:
		_ = i.Store.DeleteDeviceCode(hash) // lazy expiry
		httpx.WriteOAuthError(w, "expired_token", "AADSTS70020: The device code has expired.")
		return
	case row.Status == "denied":
		_ = i.Store.DeleteDeviceCode(hash)
		// entra-docs names user-denial authorization_declined (not access_denied).
		httpx.WriteOAuthError(w, "authorization_declined", "AADSTS70018: The user declined the request.")
		return
	case row.Status == "pending":
		httpx.WriteOAuthError(w, "authorization_pending",
			"AADSTS70016: The end user has not yet approved the request. Continue polling.")
		return
	}

	// approved → atomic single-use redemption (TOCTOU-safe).
	consumed, err := i.Store.ConsumeApprovedDeviceCode(hash, app.ID, now)
	if err != nil || consumed == nil {
		httpx.WriteOAuthError(w, "bad_verification_code", "AADSTS70019: The device code is unknown or already redeemed.")
		return
	}
	user, err := i.Store.GetUser(consumed.UserID)
	if err != nil || !user.AccountEnabled {
		httpx.WriteOAuthError(w, "invalid_grant", "AADSTS50057: The approving user is disabled or deleted.")
		return
	}
	scopes := strings.Fields(consumed.Scopes)
	resolved := i.ResolveDelegatedScopes(scopes)
	if resolved == nil {
		httpx.WriteOAuthError(w, "invalid_grant", "AADSTS70019: The granted scopes are no longer valid.")
		return
	}
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

// ---- Human approval surface ----

// handleDeviceCodePage renders the code-entry page (GET).
func (i *Identity) handleDeviceCodePage(w http.ResponseWriter, r *http.Request) {
	tenantSeg, ok := i.tenantSegment(r)
	if !ok {
		i.renderErrorPage(w, http.StatusBadRequest, "Invalid request", "Unknown tenant.")
		return
	}
	i.renderCodeEntry(w, tenantSeg, r.URL.Query().Get("user_code"), "")
}

func (i *Identity) renderCodeEntry(w http.ResponseWriter, tenantSeg, prefill, errMsg string) {
	action := "/" + tenantSeg + "/oauth2/v2.0/devicecode/verify"
	body := `<h1>Enter code</h1><p>Enter the code displayed on your device.</p>`
	if errMsg != "" {
		body += `<div class="error">` + html.EscapeString(errMsg) + `</div>`
	}
	body += fmt.Sprintf(`<form method="post" action="%s">
<input type="hidden" name="%s" value="lookup">
<label for="uc">Code</label><input id="uc" type="text" name="user_code" value="%s" autocomplete="off">
<button class="primary" type="submit">Next</button></form>`,
		html.EscapeString(action), fieldStep, html.EscapeString(prefill))
	writeHTML(w, http.StatusOK, "Enter code", body)
}

// handleDeviceVerify drives the lookup → signin → decide state machine.
func (i *Identity) handleDeviceVerify(w http.ResponseWriter, r *http.Request) {
	tenantSeg, ok := i.tenantSegment(r)
	if !ok {
		i.renderErrorPage(w, http.StatusBadRequest, "Invalid request", "Unknown tenant.")
		return
	}
	if err := r.ParseForm(); err != nil {
		i.renderErrorPage(w, http.StatusBadRequest, "Invalid request", "Malformed form submission.")
		return
	}
	switch r.PostFormValue(fieldStep) {
	case "lookup":
		i.deviceLookup(w, r, tenantSeg)
	case "signin":
		i.deviceSignIn(w, r, tenantSeg)
	case "decide":
		i.deviceDecide(w, r, tenantSeg)
	default:
		i.renderErrorPage(w, http.StatusBadRequest, "Invalid request", "Unknown step.")
	}
}

// loadPendingDeviceCode re-validates the code server-side (never trust the
// signed field alone). Renders the specific error page on failure.
func (i *Identity) loadPendingDeviceCode(w http.ResponseWriter, userCode string) *store.DeviceCode {
	row, err := i.Store.GetDeviceCodeByUserCode(userCode)
	if err != nil {
		i.renderErrorPage(w, http.StatusOK, "Code not found", "That code wasn't found. Check it and try again.")
		return nil
	}
	switch {
	case row.ExpiresAt <= i.Store.Now():
		i.renderErrorPage(w, http.StatusOK, "Code expired", "This code has expired. Request a new one on your device.")
		return nil
	case row.Status == "denied":
		i.renderErrorPage(w, http.StatusOK, "Request denied", "This request was denied.")
		return nil
	case row.Status == "approved":
		i.renderErrorPage(w, http.StatusOK, "Code already used", "This code was already used.")
		return nil
	}
	return row
}

func (i *Identity) deviceLookup(w http.ResponseWriter, r *http.Request, tenantSeg string) {
	userCode := normalizeUserCode(r.PostFormValue("user_code"))
	if userCode == "" {
		i.renderCodeEntry(w, tenantSeg, "", "Enter the 8-character code, e.g. BCDF-GHJK.")
		return
	}
	row := i.loadPendingDeviceCode(w, userCode)
	if row == nil {
		return
	}
	if sess, user := i.currentSession(r); sess != nil {
		// Direct-SSO path: consent screen bound to the live session id.
		i.renderDeviceConsent(w, tenantSeg, row, user,
			i.signState(deviceApprovalState{Kind: "device", UserCode: userCode, SID: sess.ID}))
		return
	}
	// Sign-in step carries the device state through the picker/password form.
	signed := i.signState(deviceApprovalState{Kind: "device", UserCode: userCode})
	action := "/" + tenantSeg + "/oauth2/v2.0/devicecode/verify"
	extra := map[string]string{fieldStep: "signin"}
	if i.Cfg.RequirePassword {
		i.renderPasswordForm(w, action, signed, extra, "", "")
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
	i.renderAccountPicker(w, action, signed, enabled, extra, "")
}

func (i *Identity) deviceSignIn(w http.ResponseWriter, r *http.Request, tenantSeg string) {
	var st deviceApprovalState
	if !i.verifyState(r.PostFormValue(fieldState), &st) || st.Kind != "device" {
		i.renderErrorPage(w, http.StatusBadRequest, "Invalid request", "The sign-in state is invalid or expired.")
		return
	}
	row := i.loadPendingDeviceCode(w, st.UserCode)
	if row == nil {
		return
	}
	var user *store.User
	var err error
	if i.Cfg.RequirePassword {
		user, err = i.Store.VerifyPassword(r.PostFormValue(fieldUsername), r.PostFormValue(fieldPassword))
	} else {
		user, err = i.Store.GetUser(r.PostFormValue(fieldUser))
		if err == nil && !user.AccountEnabled {
			err = store.ErrNotFound
		}
	}
	if err != nil {
		i.renderErrorPage(w, http.StatusOK, "Sign-in failed", "Incorrect account or password. Start over from your device code.")
		return
	}
	sess := i.createSession(w, user.ID)
	if sess == nil {
		i.renderErrorPage(w, http.StatusInternalServerError, "Error", "Could not create a session.")
		return
	}
	i.renderDeviceConsent(w, tenantSeg, row, user,
		i.signState(deviceApprovalState{Kind: "device", UserCode: st.UserCode, SID: sess.ID}))
}

func (i *Identity) renderDeviceConsent(w http.ResponseWriter, tenantSeg string, row *store.DeviceCode,
	user *store.User, signedState string) {
	app, err := i.Store.GetApp(row.AppID)
	if err != nil {
		i.renderErrorPage(w, http.StatusOK, "Code not found", "The requesting application no longer exists.")
		return
	}
	action := "/" + tenantSeg + "/oauth2/v2.0/devicecode/verify"
	scopesHTML := ""
	for _, sc := range strings.Fields(row.Scopes) {
		scopesHTML += "<li>" + html.EscapeString(sc) + "</li>"
	}
	decisionForm := func(decision, label, class string) string {
		return fmt.Sprintf(`<form method="post" action="%s" style="display:inline">%s
<button class="%s" type="submit">%s</button></form>`,
			html.EscapeString(action),
			hiddenFields(map[string]string{
				fieldState: signedState, fieldStep: "decide", fieldDecision: decision,
			}), class, label)
	}
	body := fmt.Sprintf(`<h1>Approve sign-in</h1>
<p><strong>%s</strong> wants to sign in as <strong>%s</strong> with these permissions:</p>
<ul class="scopes">%s</ul>%s %s`,
		html.EscapeString(app.DisplayName), html.EscapeString(user.UserPrincipalName),
		scopesHTML, decisionForm("approve", "Approve", "primary"), decisionForm("deny", "Deny", "primary"))
	writeHTML(w, http.StatusOK, "Approve sign-in", body)
}

func (i *Identity) deviceDecide(w http.ResponseWriter, r *http.Request, tenantSeg string) {
	var st deviceApprovalState
	if !i.verifyState(r.PostFormValue(fieldState), &st) || st.Kind != "device" || st.SID == "" {
		i.renderErrorPage(w, http.StatusBadRequest, "Invalid request", "The approval state is invalid.")
		return
	}
	sess, user := i.currentSession(r)
	if sess == nil || sess.ID != st.SID {
		// CSRF binding: the signed sid must equal the live session.
		i.renderErrorPage(w, http.StatusBadRequest, "Invalid request", "The approval session does not match. Start over.")
		return
	}
	if i.loadPendingDeviceCode(w, st.UserCode) == nil {
		return
	}
	switch r.PostFormValue(fieldDecision) {
	case "approve":
		if err := i.Store.SetDeviceCodeDecision(st.UserCode, "approved", user.ID); err != nil {
			i.renderErrorPage(w, http.StatusOK, "Code already used", "This code was already handled.")
			return
		}
		writeHTML(w, http.StatusOK, "Approved",
			`<h1>You're all set</h1><p>Return to your device — it will finish signing in shortly.</p>`)
	case "deny":
		if err := i.Store.SetDeviceCodeDecision(st.UserCode, "denied", ""); err != nil {
			i.renderErrorPage(w, http.StatusOK, "Code already used", "This code was already handled.")
			return
		}
		writeHTML(w, http.StatusOK, "Denied",
			`<h1>Request denied</h1><p>The device will not be signed in.</p>`)
	default:
		i.renderErrorPage(w, http.StatusBadRequest, "Invalid request", "Unknown decision.")
	}
}
