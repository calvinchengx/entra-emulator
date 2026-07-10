package admin

import (
	"net/http"

	"github.com/calvinchengx/entra-emulator/internal/faults"
	"github.com/calvinchengx/entra-emulator/internal/httpx"
)

// getFaults returns the active fault-injection config.
func (a *Admin) getFaults(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, a.Faults.Get())
}

// setFaults arms fault injection (roadmap #5).
func (a *Admin) setFaults(w http.ResponseWriter, r *http.Request) {
	var cfg faults.Config
	if !decodeBody(w, r, &cfg) {
		return
	}
	if cfg.TokenLatencyMs < 0 {
		httpx.WriteAdminError(w, http.StatusBadRequest, "validation_error",
			"tokenLatencyMs must be non-negative.")
		return
	}
	if cfg.Probability < 0 || cfg.Probability > 1 {
		httpx.WriteAdminError(w, http.StatusBadRequest, "validation_error",
			"probability must be within [0,1].")
		return
	}
	a.Faults.Set(cfg)
	httpx.WriteJSON(w, http.StatusOK, a.Faults.Get())
}

// clearFaults disarms all fault injection.
func (a *Admin) clearFaults(w http.ResponseWriter, _ *http.Request) {
	a.Faults.Clear()
	w.WriteHeader(http.StatusNoContent)
}
