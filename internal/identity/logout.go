package identity

import (
	"net/http"
	"net/url"

	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// handleLogout clears the SSO session (idempotent) and honors a validated
// post_logout_redirect_uri; otherwise renders the signed-out page.
func (i *Identity) handleLogout(w http.ResponseWriter, r *http.Request) {
	if _, ok := i.tenantSegment(r); !ok {
		i.renderErrorPage(w, http.StatusBadRequest, "Invalid request", "Unknown tenant.")
		return
	}
	i.clearSession(w, r)

	q := r.URL.Query()
	target := q.Get("post_logout_redirect_uri")
	if target == "" {
		i.renderSignedOut(w)
		return
	}

	clientID := q.Get("client_id")
	if clientID == "" {
		// Best-effort inference from the unverified id_token_hint's aud.
		if hint := q.Get("id_token_hint"); hint != "" {
			if claims, err := tokens.DecodeUnverified(hint); err == nil {
				clientID, _ = claims["aud"].(string)
			}
		}
	}
	if clientID == "" {
		i.renderSignedOut(w) // never redirect to an unvalidated URI
		return
	}
	if ok, _ := i.Store.HasRedirectURI(clientID, target); !ok {
		i.renderSignedOut(w)
		return
	}

	if state := q.Get("state"); state != "" {
		sep := "?"
		if u, err := url.Parse(target); err == nil && u.RawQuery != "" {
			sep = "&"
		}
		target += sep + "state=" + url.QueryEscape(state)
	}
	http.Redirect(w, r, target, http.StatusFound)
}
