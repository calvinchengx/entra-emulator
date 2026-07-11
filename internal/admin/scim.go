package admin

import (
	"net/http"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/scim"
)

// getScimTarget reports the configured provisioning target (token withheld).
func (a *Admin) getScimTarget(w http.ResponseWriter, _ *http.Request) {
	t, ok := a.Provisioner.Target()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"configured": ok,
		"endpoint":   t.Endpoint,
	})
}

// setScimTarget points outbound provisioning at a downstream SCIM endpoint
// (roadmap #21b).
func (a *Admin) setScimTarget(w http.ResponseWriter, r *http.Request) {
	var t scim.Target
	if !decodeBody(w, r, &t) {
		return
	}
	if t.Endpoint == "" {
		httpx.WriteAdminError(w, http.StatusBadRequest, "validation_error", "endpoint is required.")
		return
	}
	a.Provisioner.SetTarget(t)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"configured": true, "endpoint": t.Endpoint})
}

func (a *Admin) clearScimTarget(w http.ResponseWriter, _ *http.Request) {
	a.Provisioner.ClearTarget()
	w.WriteHeader(http.StatusNoContent)
}

// scimSync runs a provisioning cycle against the configured target.
func (a *Admin) scimSync(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Mode string `json:"mode"`
	}
	if r.ContentLength > 0 && !decodeBody(w, r, &body) {
		return
	}
	if body.Mode == "" {
		body.Mode = "initial"
	}
	result, err := a.Provisioner.Sync(body.Mode)
	if err != nil {
		httpx.WriteAdminError(w, http.StatusBadRequest, "not_configured", err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, result)
}

// getScimLog returns the outbound-provisioning request trail.
func (a *Admin) getScimLog(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"value": a.Provisioner.Log()})
}

func (a *Admin) clearScimLog(w http.ResponseWriter, _ *http.Request) {
	a.Provisioner.ClearLog()
	w.WriteHeader(http.StatusNoContent)
}
