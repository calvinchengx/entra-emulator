package identity

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// handleLogout clears the SSO session (idempotent) and honors a validated
// post_logout_redirect_uri; otherwise renders the signed-out page.
func (i *Identity) handleLogout(w http.ResponseWriter, r *http.Request) {
	if _, ok := i.tenantSegment(r); !ok {
		i.renderErrorPage(w, http.StatusBadRequest, "Invalid request", "Unknown tenant.")
		return
	}
	// Front-channel logout: before the session goes away, collect the logout
	// URIs of the relying parties THIS session actually signed into, so we
	// notify exactly those — not every app in the directory.
	var rpLogoutURIs []string
	sessionID := ""
	if c, err := r.Cookie(sessionCookie); err == nil {
		sessionID = c.Value
		rpLogoutURIs, _ = i.Store.SessionLogoutURIs(sessionID)
	}

	i.clearSession(w, r)
	if sessionID != "" {
		_ = i.Store.ForgetSessionApps(sessionID)
	}

	q := r.URL.Query()
	if len(rpLogoutURIs) > 0 {
		i.renderFrontchannelLogout(w, rpLogoutURIs, i.validatedPostLogoutRedirect(q), tokens.FrontchannelSID(sessionID))
		return
	}
	target := i.validatedPostLogoutRedirect(q)
	if target == "" {
		i.renderSignedOut(w)
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// renderFrontchannelLogout renders the OP-side logout page: one hidden iframe
// per relying party, each carrying iss and sid as the front-channel logout
// spec requires, then continues to the app's post-logout page.
func (i *Identity) renderFrontchannelLogout(w http.ResponseWriter, uris []string, target, sid string) {
	frames := ""
	for _, u := range uris {
		// Old databases/imported fixtures may contain unvalidated registrations.
		if !httpx.ValidFrontchannelLogoutURI(u) {
			continue
		}
		parsed, _ := url.Parse(u) // validated above
		// Keep application parameters byte for byte, including valueless keys
		// and pairs net/url.ParseQuery would discard (for example, semicolons).
		// Replace only the OP-owned fields, including percent-encoded names.
		parts := make([]string, 0, 4)
		for _, part := range strings.Split(parsed.RawQuery, "&") {
			key, _, _ := strings.Cut(part, "=")
			decoded, err := url.QueryUnescape(key)
			if part == "" || (err == nil && (decoded == "iss" || decoded == "sid")) {
				continue
			}
			parts = append(parts, part)
		}
		parts = append(parts, url.Values{"iss": {i.Cfg.Issuer}, "sid": {sid}}.Encode())
		parsed.RawQuery = strings.Join(parts, "&")
		src := parsed.String()
		frames += fmt.Sprintf(`<iframe src="%s" style="display:none" title="logout"></iframe>`,
			html.EscapeString(src))
	}
	if frames == "" && target == "" {
		i.renderSignedOut(w)
		return
	}
	cont := ""
	if target != "" {
		cont = fmt.Sprintf(`<meta http-equiv="refresh" content="1;url=%s">`, html.EscapeString(target))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `<!doctype html><html><head>%s</head><body>
<p>Signing out\u2026</p>%s</body></html>`, cont, frames)
}

// validatedPostLogoutRedirect resolves post_logout_redirect_uri only when it is
// registered for the named client — never redirect to an unvalidated URI.
func (i *Identity) validatedPostLogoutRedirect(q url.Values) string {
	target := q.Get("post_logout_redirect_uri")
	if target == "" {
		return ""
	}
	clientID := q.Get("client_id")
	if clientID == "" {
		if hint := q.Get("id_token_hint"); hint != "" {
			if claims, err := tokens.DecodeUnverified(hint); err == nil {
				clientID, _ = claims["aud"].(string)
			}
		}
	}
	if clientID == "" {
		return ""
	}
	if ok, _ := i.Store.HasRedirectURI(clientID, target); !ok {
		return ""
	}
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	if state := q.Get("state"); state != "" {
		if u.RawQuery != "" {
			u.RawQuery += "&"
		}
		u.RawQuery += "state=" + url.QueryEscape(state)
	}
	return u.String()
}
