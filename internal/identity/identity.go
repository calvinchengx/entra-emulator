package identity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/calvinchengx/entra-emulator/internal/audit"
	"github.com/calvinchengx/entra-emulator/internal/config"
	"github.com/calvinchengx/entra-emulator/internal/faults"
	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// Cookie and form-field names — a stable contract; tests and the e2e
// suites rely on these exact names.
const (
	sessionCookie          = "ee_session"
	recentCookie           = "ee_recent"
	sessionLifetimeSeconds = 8 * 60 * 60
	fieldState             = "__ee_state"
	fieldStep              = "__ee_step"
	fieldConsent           = "__ee_consent"
	fieldUser              = "__ee_user"
	fieldUsername          = "__ee_username"
	fieldPassword          = "__ee_password"
	fieldDecision          = "__ee_decision"
)

// Identity is the STS surface.
type Identity struct {
	Cfg      *config.Config
	Store    *store.Store
	Tokens   *tokens.Service
	Faults   *faults.Store
	Audit    *audit.Recorder
	stateKey []byte   // per-process HMAC key for signed form state
	waSess   sync.Map // WebAuthn ceremony state keyed by a per-flow cookie
}

func New(cfg *config.Config, st *store.Store, ts *tokens.Service, fs *faults.Store, au *audit.Recorder) *Identity {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	if fs == nil {
		fs = faults.New()
	}
	if au == nil {
		au = audit.New(0)
	}
	return &Identity{Cfg: cfg, Store: st, Tokens: ts, Faults: fs, Audit: au, stateKey: key}
}

// Register mounts the tenant-scoped OIDC routes on mux. Paths carry a
// {tenant} wildcard validated per request.
func (i *Identity) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /{tenant}/v2.0/.well-known/openid-configuration", withCORS(i.handleDiscovery))
	mux.HandleFunc("GET /{tenant}/discovery/v2.0/keys", withCORS(i.handleJWKS))
	// MSAL/ADAL validate the authority via instance discovery before acquiring a
	// token; `common` here is a literal segment (not a tenant), so it is its own
	// route. Real Fabric clients (fab CLI, azcopy) require this to authenticate.
	mux.HandleFunc("GET /common/discovery/instance", withCORS(i.handleInstanceDiscovery))
	// MSAL Go probes the user realm before it will attempt a username/password
	// request, and gives up on a non-200 — so ROPC is unreachable without this.
	mux.HandleFunc("GET /common/UserRealm/{user}", i.handleUserRealm)
	registerCORSPreflight(mux)
	mux.HandleFunc("GET /{tenant}/oauth2/v2.0/authorize", i.audited("authorize", i.handleAuthorize))
	mux.HandleFunc("POST /{tenant}/oauth2/v2.0/authorize", i.audited("authorize", i.handleAuthorize))
	mux.HandleFunc("POST /{tenant}/oauth2/v2.0/token", i.withTokenCORS(i.audited("token", i.handleToken)))
	mux.HandleFunc("POST /{tenant}/oauth2/v2.0/devicecode", i.handleDeviceAuthorization)
	mux.HandleFunc("GET /{tenant}/oauth2/v2.0/devicecode", i.handleDeviceCodePage)
	mux.HandleFunc("POST /{tenant}/oauth2/v2.0/devicecode/verify", i.handleDeviceVerify)
	mux.HandleFunc("GET /{tenant}/oauth2/v2.0/logout", i.handleLogout)
	// SAML 2.0. Entra's own paths, so an SP configured against a real
	// tenant is repointed by changing the host and nothing else.
	mux.HandleFunc("GET /{tenant}/federationmetadata/2007-06/federationmetadata.xml",
		i.audited("saml-metadata", i.handleSAMLMetadata))
	mux.HandleFunc("GET /{tenant}/saml2", i.audited("saml-sso", i.handleSAMLSSO))
	mux.HandleFunc("POST /{tenant}/saml2", i.audited("saml-sso", i.handleSAMLSSO))
	// WS-Federation passive profile. Entra's path; GET and POST both accept
	// wa=wsignin1.0 (some RPs POST the challenge, as with SAML POST vs Redirect).
	// Account choice POSTs back to the same path. A token-shaped POST (wresult)
	// without this STS's signed Kind is unsolicited and is refused; there is
	// no flag to allow IdP-initiated login.
	mux.HandleFunc("GET /{tenant}/wsfed", i.audited("wsfed", i.handleWSFed))
	mux.HandleFunc("POST /{tenant}/wsfed", i.audited("wsfed", i.handleWSFed))

	// Passkey (WebAuthn) ceremonies (roadmap #11).
	mux.HandleFunc("POST /{tenant}/webauthn/register/begin", i.handleWebAuthnRegisterBegin)
	mux.HandleFunc("POST /{tenant}/webauthn/register/finish", i.handleWebAuthnRegisterFinish)
	mux.HandleFunc("POST /{tenant}/webauthn/assert/begin", i.handleWebAuthnAssertBegin)
	mux.HandleFunc("POST /{tenant}/webauthn/assert/finish", i.handleWebAuthnAssertFinish)
}

// ---- Signed hidden-form state (HMAC, per-process key) ----

func (i *Identity) signState(v any) string {
	payload, _ := json.Marshal(v)
	mac := hmac.New(sha256.New, i.stateKey)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (i *Identity) verifyState(signed string, into any) bool {
	dot := -1
	for idx := len(signed) - 1; idx >= 0; idx-- {
		if signed[idx] == '.' {
			dot = idx
			break
		}
	}
	if dot < 0 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(signed[:dot])
	if err != nil {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(signed[dot+1:])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, i.stateKey)
	mac.Write(payload)
	if !hmac.Equal(mac.Sum(nil), sig) {
		return false
	}
	return json.Unmarshal(payload, into) == nil
}

// ---- Sessions ----

// currentSession resolves a valid, unexpired session with an enabled user.
func (i *Identity) currentSession(r *http.Request) (*store.Session, *store.User) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil, nil
	}
	sess, err := i.Store.GetSession(c.Value)
	if err != nil || sess.ExpiresAt <= i.Store.Now() {
		return nil, nil
	}
	user, err := i.Store.GetUser(sess.UserID)
	if err != nil || !user.AccountEnabled {
		return nil, nil
	}
	return sess, user
}

// enabledDirectoryAccounts is the Pick an account roster: disabled users are
// not selectable.
func (i *Identity) enabledDirectoryAccounts() ([]*store.User, error) {
	users, _, err := i.Store.ListUsers(100, 0, "")
	if err != nil {
		return nil, err
	}
	enabled := users[:0]
	for _, u := range users {
		if u.AccountEnabled {
			enabled = append(enabled, u)
		}
	}
	return enabled, nil
}

// createSession persists a session row and sets ee_session as the FIRST
// Set-Cookie header (ordering invariant the e2e helpers rely on).
func (i *Identity) createSession(w http.ResponseWriter, userID, method string) *store.Session {
	now := i.Store.Now()
	if method == "" {
		method = "pwd"
	}
	sess := &store.Session{
		ID: store.NewOpaqueToken(24), UserID: userID, AuthMethod: method,
		CreatedAt: now, ExpiresAt: now + sessionLifetimeSeconds,
	}
	if err := i.Store.CreateSession(sess); err != nil {
		return nil
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: sess.ID, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: i.Cfg.TLSEnabled,
		MaxAge: sessionLifetimeSeconds,
	})
	return sess
}

func (i *Identity) clearSession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		_ = i.Store.DeleteSession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: i.Cfg.TLSEnabled, MaxAge: -1,
	})
}

// tenantSegment validates the {tenant} path value and resolves it to a
// concrete tenant ID. The home GUID and the multi-tenant aliases (common,
// organizations, consumers) resolve to the home tenant; any other value is
// treated as a tenant GUID and accepted only if that tenant exists. ok=false
// means the caller must reject the request.
func (i *Identity) tenantSegment(r *http.Request) (string, bool) {
	seg := r.PathValue("tenant")
	switch seg {
	case i.Cfg.TenantID, "common", "organizations", "consumers":
		return i.Cfg.TenantID, true
	}
	if _, err := i.Store.GetTenantByID(seg); err == nil {
		return seg, true
	}
	return seg, false
}
