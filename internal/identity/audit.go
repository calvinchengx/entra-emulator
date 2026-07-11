package identity

import (
	"bytes"
	"encoding/json"
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
		next(cw, r)

		ev := audit.Event{
			Time:      i.Store.Now(),
			Flow:      flow,
			GrantType: r.FormValue("grant_type"),
			ClientID:  r.FormValue("client_id"),
			Status:    cw.status,
			OK:        cw.status < 400,
		}
		// Token errors are JSON with error/error_description.
		if cw.status >= 400 && cw.body.Len() > 0 {
			var oerr struct {
				Error string `json:"error"`
				Desc  string `json:"error_description"`
			}
			if json.Unmarshal(cw.body.Bytes(), &oerr) == nil {
				ev.Error = oerr.Error
				ev.Reason = oerr.Desc
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
