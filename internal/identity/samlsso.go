package identity

import (
	"crypto/rand"
	"encoding/hex"
	"html/template"
	"net/http"
	"time"

	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// SP-initiated SSO: the request arrives, a human signs in, a signed assertion
// is posted back.
//
// The sign-in half is NOT reimplemented here. It is the same account picker,
// the same password form and the same session cookie the OIDC authorize
// endpoint uses, reached by putting a different Kind in the signed state. A
// second login path would be a second place for a login bug to live, and the
// two would drift the first time either was touched.

type samlState struct {
	Kind         string `json:"kind"` // "saml"
	Tenant       string `json:"tenant"`
	RequestID    string `json:"rid"`
	SPEntityID   string `json:"sp"`
	ACSURL       string `json:"acs"`
	RelayState   string `json:"relay"`
	NameIDFormat string `json:"nif"`
}

// samlPostForm is the HTTP-POST binding: a form the browser submits itself.
// SAML has no way to send a body on a redirect, so the assertion travels as a
// form field in a page that posts on load.
var samlPostForm = template.Must(template.New("saml-post").Parse(`<!DOCTYPE html>
<html><head><title>Signing in…</title></head>
<body onload="document.forms[0].submit()">
<form method="POST" action="{{.ACS}}">
<input type="hidden" name="SAMLResponse" value="{{.SAMLResponse}}"/>
{{if .RelayState}}<input type="hidden" name="RelayState" value="{{.RelayState}}"/>{{end}}
<noscript><p>JavaScript is off.</p><button type="submit">Continue</button></noscript>
</form></body></html>`))

// samlID returns an XML ID. SAML IDs must not start with a digit, because the
// schema types them as xs:ID; a hex string that happens to begin with a number
// produces a document that fails schema validation at some SPs and not others,
// which is the worst kind of intermittent.
func samlID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "_" + hex.EncodeToString(b)
}

// handleSAMLSSO accepts an AuthnRequest by either binding.
func (i *Identity) handleSAMLSSO(w http.ResponseWriter, r *http.Request) {
	tid, ok := i.tenantSegment(r)
	if !ok {
		i.renderErrorPage(w, http.StatusNotFound, "Unknown tenant", "No such tenant in this directory.")
		return
	}
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		// A posted sign-in carries our signed state; a posted AuthnRequest
		// carries SAMLRequest. Distinguishing on which field is present keeps
		// one endpoint, as Entra does.
		if r.PostFormValue(fieldState) != "" {
			i.samlSignIn(w, r)
			return
		}
	}

	encoded, relay := r.URL.Query().Get("SAMLRequest"), r.URL.Query().Get("RelayState")
	deflated := true
	if r.Method == http.MethodPost {
		encoded, relay = r.PostFormValue("SAMLRequest"), r.PostFormValue("RelayState")
		deflated = false // the POST binding does not compress
	}
	req, err := decodeAuthnRequest(encoded, deflated)
	if err != nil {
		i.renderErrorPage(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	app, acs, err := i.resolveServiceProvider(req)
	if err != nil {
		// Deliberately NOT redirected to the SP: the whole reason this failed
		// may be that the caller named an endpoint it does not own, and
		// bouncing the error there would tell an attacker their probe landed.
		i.renderErrorPage(w, http.StatusBadRequest, "Unknown application", err.Error())
		return
	}

	st := samlState{
		Kind: "saml", Tenant: tid, RequestID: req.ID, SPEntityID: req.Issuer,
		ACSURL: acs, RelayState: relay, NameIDFormat: req.NameIDPolicy.Format,
	}
	// An existing session means no second sign-in, which is what SSO means.
	if _, user := i.currentSession(r); user != nil {
		i.deliverSAMLResponse(w, st, user, app)
		return
	}
	i.renderSAMLSignIn(w, st, "")
}

// renderSAMLSignIn reuses the OIDC sign-in UI, posting back to /saml2.
func (i *Identity) renderSAMLSignIn(w http.ResponseWriter, st samlState, errMsg string) {
	action := "/" + st.Tenant + "/saml2"
	signed := i.signState(st)
	if i.Cfg.RequirePassword {
		i.renderPasswordForm(w, action, signed, nil, "", errMsg)
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
	i.renderAccountPicker(w, action, signed, enabled, nil, errMsg)
}

// samlSignIn authenticates the human and hands off to the assertion.
func (i *Identity) samlSignIn(w http.ResponseWriter, r *http.Request) {
	var st samlState
	if !i.verifyState(r.PostFormValue(fieldState), &st) || st.Kind != "saml" {
		i.renderErrorPage(w, http.StatusBadRequest, "Invalid request", "The sign-in state is invalid or expired.")
		return
	}
	app, err := i.Store.GetAppByIDURI(st.SPEntityID)
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
		i.renderSAMLSignIn(w, st, "Incorrect email or password.")
		return
	}
	if sess := i.createSession(w, user.ID, "pwd"); sess != nil {
		_ = i.Store.RecordSessionApp(sess.ID, app.ID)
	}
	i.deliverSAMLResponse(w, st, user, app)
}

// deliverSAMLResponse signs the assertion and posts it to the SP.
func (i *Identity) deliverSAMLResponse(w http.ResponseWriter, st samlState, user *store.User, app *store.App) {
	signer, err := tokens.EnsureActiveKey(i.Store, st.Tenant)
	if err != nil {
		i.renderErrorPage(w, http.StatusInternalServerError, "Cannot sign in", "No signing key for this tenant.")
		return
	}
	certDER, err := signer.SAMLCertificate(st.Tenant, time.Now().AddDate(0, 0, -1).Truncate(24*time.Hour))
	if err != nil {
		i.renderErrorPage(w, http.StatusInternalServerError, "Cannot sign in", "No signing certificate.")
		return
	}
	now := time.Now()
	assertion, err := buildAssertion(samlAssertionInput{
		IssuerEntityID: i.samlEntityID(st.Tenant),
		SPEntityID:     st.SPEntityID,
		ACSURL:         st.ACSURL,
		InResponseTo:   st.RequestID,
		NameID:         user.UserPrincipalName,
		NameIDFormat:   st.NameIDFormat,
		SessionIndex:   samlID(),
		Attributes:     samlAttributesFor(user),
		Now:            now,
	}, samlID())
	if err != nil {
		i.renderErrorPage(w, http.StatusInternalServerError, "Cannot sign in", err.Error())
		return
	}
	signed, err := signAssertion(assertion, signer.PrivateKey, certDER)
	if err != nil {
		i.renderErrorPage(w, http.StatusInternalServerError, "Cannot sign in", err.Error())
		return
	}
	body, err := buildResponse(signed, i.samlEntityID(st.Tenant), st.ACSURL, st.RequestID, samlID(), now)
	if err != nil {
		i.renderErrorPage(w, http.StatusInternalServerError, "Cannot sign in", err.Error())
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The assertion is a bearer credential, so it must not be cached by an
	// intermediary or replayed from the back button.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = samlPostForm.Execute(w, struct {
		ACS, SAMLResponse, RelayState string
	}{ACS: st.ACSURL, SAMLResponse: encodeSAMLResponse(body), RelayState: st.RelayState})
}

// samlAttributesFor is the claim set Entra sends by default, under the same
// long-form claim URIs, so an SP's attribute mapping does not change.
func samlAttributesFor(u *store.User) map[string][]string {
	attrs := map[string][]string{
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name": {u.UserPrincipalName},
	}
	if u.DisplayName != "" {
		attrs["http://schemas.microsoft.com/identity/claims/displayname"] = []string{u.DisplayName}
	}
	if u.ID != "" {
		attrs["http://schemas.microsoft.com/identity/claims/objectidentifier"] = []string{u.ID}
	}
	return attrs
}
