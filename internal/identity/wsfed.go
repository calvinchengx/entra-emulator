package identity

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// WS-Federation passive sign-in: a challenge arrives, a human signs in, a
// signed assertion is posted back as wresult.
//
// The sign-in half is NOT reimplemented here. It is the same account picker,
// the same password form and the same session cookie the OIDC authorize
// endpoint uses, reached by putting Kind "wsfed" in the signed state. A
// second login path would be a second place for a login bug to live, and the
// two would drift the first time either was touched.

type wsfedState struct {
	Kind    string `json:"kind"` // "wsfed"
	Tenant  string `json:"tenant"`
	Wtrealm string `json:"wtrealm"`
	Wreply  string `json:"wreply"`
	Wctx    string `json:"wctx,omitempty"`
}

// wsfedPostForm is the WS-Fed equivalent of the SAML HTTP-POST binding: a
// form the browser submits itself. WS-Fed has no way to send a body on a
// redirect, so the RSTR travels as wresult in a page that posts on load.
var wsfedPostForm = template.Must(template.New("wsfed-post").Parse(`<!DOCTYPE html>
<html><head><title>Signing in…</title></head>
<body onload="document.forms[0].submit()">
<form method="POST" action="{{.Reply}}">
<input type="hidden" name="wa" value="wsignin1.0"/>
<input type="hidden" name="wresult" value="{{.Wresult}}"/>
{{if .Wctx}}<input type="hidden" name="wctx" value="{{.Wctx}}"/>{{end}}
<noscript><p>JavaScript is off.</p><button type="submit">Continue</button></noscript>
</form></body></html>`))

// handleWSFed accepts a wa=wsignin1.0 challenge or a wa=wsignout1.0 request
// on the same GET|POST /{tid}/wsfed route. Sign-out is dispatched on wa
// before any mint: a live session never produces wresult.
func (i *Identity) handleWSFed(w http.ResponseWriter, r *http.Request) {
	tid, ok := i.tenantSegment(r)
	if !ok {
		i.renderErrorPage(w, http.StatusNotFound, "Unknown tenant", "No such tenant in this directory.")
		return
	}
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
	}
	wa := wsfedChallengeValue(r, "wa")
	if wa == "wsignout1.0" {
		i.handleWSFedSignOut(w, r)
		return
	}
	if wa != "" && wa != "wsignin1.0" {
		i.refuseUnknownWSFedAction(w, r)
		return
	}
	if r.Method == http.MethodPost {
		// A posted sign-in carries our signed state; a posted challenge
		// carries wtrealm. Distinguishing on which field is present keeps
		// one endpoint, as Entra does. wresult without that signed Kind is
		// unsolicited (SAML InResponseTo analog) and is never a new challenge.
		if r.PostFormValue(fieldState) != "" {
			i.wsfedSignIn(w, r)
			return
		}
		if r.PostFormValue("wresult") != "" {
			i.refuseUnsolicitedWSFed(w, r)
			return
		}
	}

	st := wsfedState{
		Kind: "wsfed", Tenant: tid,
		Wtrealm: wsfedChallengeValue(r, "wtrealm"),
		Wreply:  wsfedChallengeValue(r, "wreply"),
		Wctx:    wsfedChallengeValue(r, "wctx"),
	}
	noteAuditClientID(r, st.Wtrealm)
	if _, err := i.resolveWSFedRelyingParty(st.Wtrealm, st.Wreply); err != nil {
		// Deliberately NOT redirected to the RP: the whole reason this failed
		// may be that the caller named an endpoint it does not own, and
		// bouncing the error there would tell an attacker their probe landed.
		i.renderErrorPage(w, http.StatusBadRequest, "Unknown application", err.Error())
		return
	}

	if _, user := i.currentSession(r); user != nil {
		i.deliverWSFedResponse(w, r, st, user)
		return
	}
	i.renderWSFedSignIn(w, st, "")
}

// handleWSFedSignOut ends the shared emulator session and 302s to an exact
// registered wsfed-reply. It never mints an RSTR, even with a live session.
func (i *Identity) handleWSFedSignOut(w http.ResponseWriter, r *http.Request) {
	wtrealm := wsfedChallengeValue(r, "wtrealm")
	wreply := wsfedChallengeValue(r, "wreply")
	noteAuditClientID(r, wtrealm)
	returnTo, err := i.resolveWSFedSignOutReturn(wtrealm, wreply)
	if err != nil {
		i.renderErrorPage(w, http.StatusBadRequest, "Unknown application", err.Error())
		return
	}

	sessionID := ""
	if c, err := r.Cookie(sessionCookie); err == nil {
		sessionID = c.Value
	}
	if _, user := i.currentSession(r); user != nil {
		noteAuditSubject(r, user.ID, user.UserPrincipalName)
	}
	i.clearSession(w, r)
	if sessionID != "" {
		_ = i.Store.ForgetSessionApps(sessionID)
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
}

// resolveWSFedSignOutReturn prefers a library-sent wreply that is an exact
// wsfed-reply for the wtrealm app. If wreply is omitted, it uses a registered
// wsfed-reply for that app (never saml-acs or web).
func (i *Identity) resolveWSFedSignOutReturn(wtrealm, wreply string) (string, error) {
	if wreply != "" {
		if _, err := i.resolveWSFedRelyingParty(wtrealm, wreply); err != nil {
			return "", err
		}
		return wreply, nil
	}
	return i.registeredWSFedReplyForRealm(wtrealm)
}

func (i *Identity) registeredWSFedReplyForRealm(wtrealm string) (string, error) {
	if wtrealm == "" {
		return "", fmt.Errorf("wsfed: no wtrealm")
	}
	app, err := i.Store.GetAppByIDURI(wtrealm)
	if err != nil {
		return "", fmt.Errorf("wsfed: no application registered with identifier %q", wtrealm)
	}
	uris, err := i.Store.ListRedirectURIs(app.ID)
	if err != nil {
		return "", fmt.Errorf("wsfed: cannot read reply URLs for %s: %w", app.ID, err)
	}
	for _, u := range uris {
		ok, err := checkWSFedReply(i.Store, app.ID, u.URI)
		if err != nil {
			return "", fmt.Errorf("wsfed: cannot read reply URLs for %s: %w", app.ID, err)
		}
		if !ok {
			continue
		}
		return u.URI, nil
	}
	return "", fmt.Errorf("wsfed: no registered wsfed-reply for %s", app.ID)
}

// refuseUnknownWSFedAction keeps a non-empty wa other than wsignin1.0 /
// wsignout1.0 on the emulator. No token, no bounce to the caller reply.
func (i *Identity) refuseUnknownWSFedAction(w http.ResponseWriter, r *http.Request) {
	noteAuditClientID(r, wsfedChallengeValue(r, "wtrealm"))
	i.renderErrorPage(w, http.StatusBadRequest, "Unsupported action",
		"wsfed: unknown wa is refused on this emulator")
}

// refuseUnsolicitedWSFed rejects a token-shaped POST that did not start as a
// challenge this STS issued. No session, no wresult to wreply, no flag to
// allow IdP-initiated login in this cut.
func (i *Identity) refuseUnsolicitedWSFed(w http.ResponseWriter, r *http.Request) {
	noteAuditClientID(r, wsfedChallengeValue(r, "wtrealm"))
	i.renderErrorPage(w, http.StatusBadRequest, "Unsolicited sign-in",
		"wsfed: unsolicited sign-in that did not start at this STS is refused")
}

// renderWSFedSignIn reuses the OIDC sign-in UI, posting back to /wsfed.
func (i *Identity) renderWSFedSignIn(w http.ResponseWriter, st wsfedState, errMsg string) {
	action := "/" + st.Tenant + "/wsfed"
	signed := i.signState(st)
	if i.Cfg.RequirePassword {
		i.renderPasswordForm(w, action, signed, nil, "", errMsg)
		return
	}
	users, err := i.enabledDirectoryAccounts()
	if err != nil {
		i.renderErrorPage(w, http.StatusInternalServerError, "Error", "Could not list accounts.")
		return
	}
	i.renderAccountPicker(w, action, signed, users, nil, errMsg)
}

// wsfedSignIn authenticates the human and hands off to the RSTR.
func (i *Identity) wsfedSignIn(w http.ResponseWriter, r *http.Request) {
	var st wsfedState
	if !i.verifyState(r.PostFormValue(fieldState), &st) || st.Kind != "wsfed" {
		i.renderErrorPage(w, http.StatusBadRequest, "Invalid request", "The sign-in state is invalid or expired.")
		return
	}
	noteAuditClientID(r, st.Wtrealm)
	app, err := i.resolveWSFedRelyingParty(st.Wtrealm, st.Wreply)
	if err != nil {
		i.renderErrorPage(w, http.StatusBadRequest, "Unknown application", "This application is no longer registered.")
		return
	}
	var user *store.User
	if i.Cfg.RequirePassword {
		user, err = i.Store.VerifyPassword(r.PostFormValue(fieldUsername), r.PostFormValue(fieldPassword))
	} else {
		user, err = i.Store.GetUser(r.PostFormValue(fieldUser))
		if err == nil && !user.AccountEnabled {
			err = store.ErrNotFound
		}
	}
	if err != nil {
		i.renderWSFedSignIn(w, st, "Incorrect email or password.")
		return
	}
	if sess := i.createSession(w, user.ID, "pwd"); sess != nil {
		_ = i.Store.RecordSessionApp(sess.ID, app.ID)
	}
	i.deliverWSFedResponse(w, r, st, user)
}

// deliverWSFedResponse signs the assertion, wraps it in an RSTR, and posts
// it to the registered wreply. The RSTR is a live credential, so it is never
// written to the audit event (the wrapper only buffers 4xx bodies).
func (i *Identity) deliverWSFedResponse(w http.ResponseWriter, r *http.Request, st wsfedState, user *store.User) {
	noteAuditSubject(r, user.ID, user.UserPrincipalName)
	signer, err := tokens.EnsureActiveKey(i.Store, st.Tenant)
	if err != nil {
		i.renderErrorPage(w, http.StatusInternalServerError, "Cannot sign in", "No signing key for this tenant.")
		return
	}
	body, err := i.issueWSFedRSTR(signer, st, user)
	if err != nil {
		i.renderErrorPage(w, http.StatusInternalServerError, "Cannot sign in", err.Error())
		return
	}
	writeWSFedPost(w, st, string(body))
}

// issueWSFedRSTR is the minting half of deliverWSFedResponse, split out so a
// missing certificate or a malformed assertion can be refused without standing
// up an HTTP challenge that would never reach those checks.
func (i *Identity) issueWSFedRSTR(signer *tokens.Signer, st wsfedState, user *store.User) ([]byte, error) {
	certDER, err := signer.SAMLCertificate(st.Tenant, time.Now().AddDate(0, 0, -1).Truncate(24*time.Hour))
	if err != nil {
		return nil, errors.New("No signing certificate.")
	}
	now := time.Now()
	assertion, err := buildAssertion(samlAssertionInput{
		IssuerEntityID: i.samlEntityID(st.Tenant),
		SPEntityID:     st.Wtrealm,
		ACSURL:         st.Wreply,
		NameID:         user.ID,
		NameIDFormat:   nameIDFormatPersistent,
		SessionIndex:   samlID(),
		Attributes:     samlAttributesFor(user),
		Now:            now,
	}, samlID())
	if err != nil {
		return nil, err
	}
	return signAndWrapRSTR(assertion, signer.PrivateKey, certDER, rstrInput{AppliesTo: st.Wtrealm, Now: now})
}

// writeWSFedPost is the WS-Fed HTTP-POST binding: the RSTR cannot travel on a
// redirect, so it is a form the browser submits to the registered wreply.
func writeWSFedPost(w http.ResponseWriter, st wsfedState, wresult string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = wsfedPostForm.Execute(w, struct {
		Reply, Wresult, Wctx string
	}{Reply: st.Wreply, Wresult: wresult, Wctx: st.Wctx})
}
