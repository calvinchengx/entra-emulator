package identity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/calvinchengx/entra-emulator/internal/config"
	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// Cookie and form-field names (upstream parity — tests and helpers rely on
// these exact names).
const (
	sessionCookie          = "el_session"
	recentCookie           = "el_recent"
	sessionLifetimeSeconds = 8 * 60 * 60
	fieldState             = "__el_state"
	fieldStep              = "__el_step"
	fieldUser              = "__el_user"
	fieldUsername          = "__el_username"
	fieldPassword          = "__el_password"
	fieldDecision          = "__el_decision"
)

// Identity is the STS surface.
type Identity struct {
	Cfg      *config.Config
	Store    *store.Store
	Tokens   *tokens.Service
	stateKey []byte // per-process HMAC key for signed form state
}

func New(cfg *config.Config, st *store.Store, ts *tokens.Service) *Identity {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return &Identity{Cfg: cfg, Store: st, Tokens: ts, stateKey: key}
}

// Register mounts the tenant-scoped OIDC routes on mux. Paths carry a
// {tenant} wildcard validated per request.
func (i *Identity) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /{tenant}/v2.0/.well-known/openid-configuration", i.handleDiscovery)
	mux.HandleFunc("GET /{tenant}/discovery/v2.0/keys", i.handleJWKS)
	mux.HandleFunc("GET /{tenant}/oauth2/v2.0/authorize", i.handleAuthorize)
	mux.HandleFunc("POST /{tenant}/oauth2/v2.0/authorize", i.handleAuthorize)
	mux.HandleFunc("POST /{tenant}/oauth2/v2.0/token", i.handleToken)
	mux.HandleFunc("POST /{tenant}/oauth2/v2.0/devicecode", i.handleDeviceAuthorization)
	mux.HandleFunc("GET /{tenant}/oauth2/v2.0/devicecode", i.handleDeviceCodePage)
	mux.HandleFunc("POST /{tenant}/oauth2/v2.0/devicecode/verify", i.handleDeviceVerify)
	mux.HandleFunc("GET /{tenant}/oauth2/v2.0/logout", i.handleLogout)
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

// createSession persists a session row and sets el_session as the FIRST
// Set-Cookie header (upstream cookie-ordering invariant).
func (i *Identity) createSession(w http.ResponseWriter, userID string) *store.Session {
	now := i.Store.Now()
	sess := &store.Session{
		ID: store.NewOpaqueToken(24), UserID: userID,
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

// tenantSegment validates the {tenant} path value; ok=false means the
// caller must reject the request.
func (i *Identity) tenantSegment(r *http.Request) (string, bool) {
	seg := r.PathValue("tenant")
	switch seg {
	case i.Cfg.TenantID, "common", "organizations", "consumers":
		return seg, true
	}
	return seg, false
}
