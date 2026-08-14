package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"html"
	"net/http"
	"strings"

	"github.com/calvinchengx/entra-emulator/internal/audit"
)

// captureWriter records the status and (for error diagnosis) the body of a
// response so the audit middleware can extract the concrete reason.
type captureWriter struct {
	http.ResponseWriter
	status  int
	body    bytes.Buffer
	capture bool // only buffer the body when we'll need it
}

func (c *captureWriter) WriteHeader(status int) {
	c.status = status
	c.capture = status >= 400 // errors carry the reason we want to log
	c.ResponseWriter.WriteHeader(status)
}

func (c *captureWriter) Write(p []byte) (int, error) {
	if c.capture && c.body.Len() < 4096 {
		c.body.Write(p)
	}
	return c.ResponseWriter.Write(p)
}

// audited wraps an STS handler, recording the exchange and its outcome. flow
// is "token" or "authorize".
func (i *Identity) audited(flow string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm() // idempotent; the handler's own ParseForm returns the cache
		cw := &captureWriter{ResponseWriter: w, status: http.StatusOK}
		subj := &auditSubject{}
		next(cw, r.WithContext(context.WithValue(r.Context(), auditSubjectKey{}, subj)))

		ev := audit.Event{
			Time:      i.Store.Now(),
			Flow:      flow,
			GrantType: r.FormValue("grant_type"),
			ClientID:  r.FormValue("client_id"),
			Status:    cw.status,
			OK:        cw.status < 400,
		}
		ev.UserID, ev.UserPrincipalName = subj.UserID, subj.UPN
		// WS-Fed names the app with wtrealm, not client_id. The field is
		// OIDC-era; handlers may also stash the URI via noteAuditClientID
		// because the picker POST does not repeat wtrealm.
		if subj.ClientID != "" {
			ev.ClientID = subj.ClientID
		} else if ev.ClientID == "" {
			ev.ClientID = r.FormValue("wtrealm")
		}
		// Token errors are JSON with error/error_description. WS-Fed (and
		// other HTML STS pages) put the concrete reason in a .error div.
		if cw.status >= 400 && cw.body.Len() > 0 {
			var oerr struct {
				Error string `json:"error"`
				Desc  string `json:"error_description"`
			}
			if json.Unmarshal(cw.body.Bytes(), &oerr) == nil && (oerr.Error != "" || oerr.Desc != "") {
				ev.Error = oerr.Error
				ev.Reason = oerr.Desc
			}
			if ev.Reason == "" {
				ev.Reason = htmlErrorMessage(cw.body.String())
			}
		}
		// Authorize can deliver an error via a redirect (302 with error=...).
		if flow == "authorize" && ev.OK {
			if loc := cw.Header().Get("Location"); strings.Contains(loc, "error=") {
				ev.OK = false
				ev.Error = extractQueryParam(loc, "error")
				ev.Reason = extractQueryParam(loc, "error_description")
			}
		}
		i.Audit.Record(ev)
	}
}

// extractQueryParam pulls a param value from a URL's query or fragment
// (authorize redirects use either).
func extractQueryParam(rawurl, key string) string {
	needle := key + "="
	for _, sep := range []string{"?", "#", "&"} {
		for _, part := range strings.Split(rawurl, sep) {
			if strings.HasPrefix(part, needle) {
				v := strings.TrimPrefix(part, needle)
				if amp := strings.IndexByte(v, '&'); amp >= 0 {
					v = v[:amp]
				}
				return v
			}
		}
	}
	return ""
}

func htmlErrorMessage(body string) string {
	const open = `<div class="error">`
	i := strings.Index(body, open)
	if i < 0 {
		return ""
	}
	rest := body[i+len(open):]
	j := strings.Index(rest, "</div>")
	if j < 0 {
		return ""
	}
	return html.UnescapeString(strings.TrimSpace(rest[:j]))
}

// The audit middleware records AFTER the handler returns, but only the handler
// knows which user an exchange resolved. It therefore places a mutable holder
// in the request context and handlers fill it in via noteAuditSubject.
type auditSubject struct{ UserID, UPN, ClientID string }

type auditSubjectKey struct{}

// noteAuditSubject records the user this exchange authenticated. Safe to call
// from any handler: it is a no-op when the request is not being audited.
func noteAuditSubject(r *http.Request, userID, upn string) {
	if s, ok := r.Context().Value(auditSubjectKey{}).(*auditSubject); ok {
		s.UserID, s.UPN = userID, upn
	}
}

// noteAuditClientID records the application this exchange was for when the
// wire parameter is not client_id (WS-Fed wtrealm).
func noteAuditClientID(r *http.Request, clientID string) {
	if s, ok := r.Context().Value(auditSubjectKey{}).(*auditSubject); ok {
		s.ClientID = clientID
	}
}
