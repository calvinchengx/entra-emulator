package identity

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/store"
)

// decodeJSON reads a JSON request body into v.
func decodeJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// Passkey (FIDO2/WebAuthn) sign-in (roadmap #11). The relying party is built
// per request from the Host header, so a passkey works on whichever origin
// the emulator is reached on (subdomains, compat localhost, or a test
// listener) without static RP configuration.

const waCookie = "ee_webauthn"

// waCeremony is the persisted state between a begin and finish call.
type waCeremony struct {
	UserID  string
	Session webauthn.SessionData
}

// rpForRequest builds a WebAuthn relying party matching the request origin.
func (i *Identity) rpForRequest(r *http.Request) (*webauthn.WebAuthn, error) {
	host := r.Host
	rpID := host
	if idx := strings.LastIndex(host, ":"); idx > 0 && !strings.Contains(host[idx:], "]") {
		rpID = host[:idx] // strip port for the RP ID
	}
	scheme := "https"
	if !i.Cfg.TLSEnabled {
		scheme = "http"
	}
	return webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: "Entra Emulator",
		RPOrigins:     []string{scheme + "://" + host},
	})
}

// waUser adapts a directory user + stored credentials to webauthn.User.
type waUser struct {
	u     *store.User
	creds []webauthn.Credential
}

func (w *waUser) WebAuthnID() []byte          { return []byte(w.u.ID) }
func (w *waUser) WebAuthnName() string         { return w.u.UserPrincipalName }
func (w *waUser) WebAuthnDisplayName() string  { return w.u.DisplayName }
func (w *waUser) WebAuthnCredentials() []webauthn.Credential { return w.creds }

// loadWAUser resolves a user by UPN and loads their stored passkeys.
func (i *Identity) loadWAUser(upn string) (*waUser, error) {
	u, err := i.Store.GetUserByUPN(upn)
	if err != nil {
		return nil, err
	}
	stored, err := i.Store.ListWebAuthnCredentials(u.ID)
	if err != nil {
		return nil, err
	}
	creds := make([]webauthn.Credential, 0, len(stored))
	for _, c := range stored {
		id, _ := base64.RawURLEncoding.DecodeString(c.ID)
		creds = append(creds, webauthn.Credential{
			ID:        id,
			PublicKey: c.PublicKey,
			Authenticator: webauthn.Authenticator{
				AAGUID:    c.AAGUID,
				SignCount: c.SignCount,
			},
		})
	}
	return &waUser{u: u, creds: creds}, nil
}

func (i *Identity) storeCeremony(w http.ResponseWriter, c waCeremony) {
	id := store.NewOpaqueToken(24)
	i.waSess.Store(id, c)
	http.SetCookie(w, &http.Cookie{
		Name: waCookie, Value: id, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: i.Cfg.TLSEnabled, MaxAge: 300,
	})
}

func (i *Identity) takeCeremony(r *http.Request) (waCeremony, bool) {
	c, err := r.Cookie(waCookie)
	if err != nil || c.Value == "" {
		return waCeremony{}, false
	}
	v, ok := i.waSess.LoadAndDelete(c.Value)
	if !ok {
		return waCeremony{}, false
	}
	return v.(waCeremony), true
}

type upnBody struct {
	UPN  string `json:"upn"`
	Name string `json:"name"`
}

func (i *Identity) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if _, ok := i.tenantSegment(r); !ok {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "unknown tenant"})
		return
	}
	var body upnBody
	if err := decodeJSON(r, &body); err != nil || body.UPN == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "upn is required"})
		return
	}
	wu, err := i.loadWAUser(body.UPN)
	if err != nil {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}
	rp, err := i.rpForRequest(r)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	options, sessionData, err := rp.BeginRegistration(wu)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	i.storeCeremony(w, waCeremony{UserID: wu.u.ID, Session: *sessionData})
	httpx.WriteJSON(w, http.StatusOK, options)
}

func (i *Identity) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	cer, ok := i.takeCeremony(r)
	if !ok {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "no registration in progress"})
		return
	}
	u, err := i.Store.GetUser(cer.UserID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "user gone"})
		return
	}
	wu := &waUser{u: u}
	rp, err := i.rpForRequest(r)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	cred, err := rp.FinishRegistration(wu, cer.Session, r)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := i.Store.AddWebAuthnCredential(&store.WebAuthnCredential{
		ID:        base64.RawURLEncoding.EncodeToString(cred.ID),
		UserID:    u.ID,
		PublicKey: cred.PublicKey,
		SignCount: cred.Authenticator.SignCount,
		AAGUID:    cred.Authenticator.AAGUID,
		CreatedAt: i.Store.Now(),
	}); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"registered":   true,
		"credentialId": base64.RawURLEncoding.EncodeToString(cred.ID),
	})
}

func (i *Identity) handleWebAuthnAssertBegin(w http.ResponseWriter, r *http.Request) {
	if _, ok := i.tenantSegment(r); !ok {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "unknown tenant"})
		return
	}
	var body upnBody
	if err := decodeJSON(r, &body); err != nil || body.UPN == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "upn is required"})
		return
	}
	wu, err := i.loadWAUser(body.UPN)
	if err != nil {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}
	if len(wu.creds) == 0 {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "user has no passkeys"})
		return
	}
	rp, err := i.rpForRequest(r)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	options, sessionData, err := rp.BeginLogin(wu)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	i.storeCeremony(w, waCeremony{UserID: wu.u.ID, Session: *sessionData})
	httpx.WriteJSON(w, http.StatusOK, options)
}

// handleWebAuthnAssertFinish verifies the assertion and, on success, creates
// an SSO session tagged with method "fido" — so a subsequent /authorize issues
// a code whose token carries amr:["fido"].
func (i *Identity) handleWebAuthnAssertFinish(w http.ResponseWriter, r *http.Request) {
	cer, ok := i.takeCeremony(r)
	if !ok {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "no assertion in progress"})
		return
	}
	wu, err := i.loadWAUserByID(cer.UserID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "user gone"})
		return
	}
	rp, err := i.rpForRequest(r)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	cred, err := rp.FinishLogin(wu, cer.Session, r)
	if err != nil {
		httpx.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	// Update the stored sign count (clone/replay detection input).
	_ = i.Store.UpdateWebAuthnSignCount(
		base64.RawURLEncoding.EncodeToString(cred.ID), cred.Authenticator.SignCount)

	i.createSession(w, wu.u.ID, "fido")
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"userId":        wu.u.ID,
		"amr":           "fido",
	})
}

func (i *Identity) loadWAUserByID(userID string) (*waUser, error) {
	u, err := i.Store.GetUser(userID)
	if err != nil {
		return nil, err
	}
	return i.loadWAUser(u.UserPrincipalName)
}
