package admin

import (
	"net/http"
	"strconv"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
)

// getAudit returns recent authorize/token exchanges, newest first. `?limit=`
// caps the count (default 100).
func (a *Admin) getAudit(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
		limit = v
	}
	events := a.Audit.List(limit)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"value": events,
		"count": len(events),
	})
}

// clearAudit empties the audit trail.
func (a *Admin) clearAudit(w http.ResponseWriter, _ *http.Request) {
	a.Audit.Clear()
	w.WriteHeader(http.StatusNoContent)
}
