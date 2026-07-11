package admin

import (
	"net/http"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
)

// rotateSigningKey generates a new active signing key and retires the old one,
// keeping it in JWKS for a grace window (roadmap #14).
func (a *Admin) rotateSigningKey(w http.ResponseWriter, r *http.Request) {
	body := struct {
		GraceSeconds *int `json:"graceSeconds"`
	}{}
	if r.ContentLength > 0 && !decodeBody(w, r, &body) {
		return
	}
	grace := 3600 // default: retired key stays verifiable for an hour
	if body.GraceSeconds != nil {
		grace = *body.GraceSeconds
	}
	if grace < 0 {
		httpx.WriteAdminError(w, http.StatusBadRequest, "validation_error",
			"graceSeconds must be non-negative.")
		return
	}
	newKid, err := a.Tokens.Rotate(grace)
	if err != nil {
		httpx.WriteAdminError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	published, _ := a.Store.ListPublishableKeys(a.Cfg.TenantID, a.Store.Now())
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"activeKid":      newKid,
		"publishedCount": len(published),
		"graceSeconds":   grace,
	})
}
