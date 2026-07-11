package admin

import (
	"net/http"

	"github.com/calvinchengx/entra-emulator/internal/customext"
	"github.com/calvinchengx/entra-emulator/internal/httpx"
)

// listCustomExtensions returns all configured token-issuance webhooks
// (roadmap #10), keyed by app id.
func (a *Admin) listCustomExtensions(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"value": a.CustomExt.All()})
}

// setCustomExtension registers/updates the onTokenIssuanceStart webhook for
// an app.
func (a *Admin) setCustomExtension(w http.ResponseWriter, r *http.Request) {
	appID := r.PathValue("id")
	if _, err := a.Store.GetApp(appID); err != nil {
		writeStoreErr(w, err)
		return
	}
	var cfg customext.Config
	if !decodeBody(w, r, &cfg) {
		return
	}
	if cfg.Endpoint == "" {
		httpx.WriteAdminError(w, http.StatusBadRequest, "validation_error",
			"endpoint is required.")
		return
	}
	a.CustomExt.Set(appID, cfg)
	httpx.WriteJSON(w, http.StatusOK, cfg)
}

// deleteCustomExtension removes an app's webhook.
func (a *Admin) deleteCustomExtension(w http.ResponseWriter, r *http.Request) {
	a.CustomExt.Delete(r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}
