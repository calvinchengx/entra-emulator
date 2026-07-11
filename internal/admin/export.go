package admin

import (
	"net/http"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/store"
)

// exportDirectory dumps the directory as a portable JSON fixture (roadmap #7).
func (a *Admin) exportDirectory(w http.ResponseWriter, _ *http.Request) {
	snap, err := a.Store.ExportDirectory()
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="entra-emulator-directory.json"`)
	httpx.WriteJSON(w, http.StatusOK, snap)
}

// importDirectory replaces the directory from a fixture (roadmap #7).
func (a *Admin) importDirectory(w http.ResponseWriter, r *http.Request) {
	var snap store.DirectorySnapshot
	if !decodeBody(w, r, &snap) {
		return
	}
	if err := a.Store.ImportDirectory(&snap, a.Cfg.TenantID); err != nil {
		writeStoreErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"imported": map[string]int{
			"users":  len(snap.Users),
			"groups": len(snap.Groups),
			"apps":   len(snap.Apps),
		},
	})
}
