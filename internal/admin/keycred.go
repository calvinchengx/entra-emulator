package admin

import (
	"net/http"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/store"
)

// listKeyCredentials returns an app's registered public keys (roadmap #13).
func (a *Admin) listKeyCredentials(w http.ResponseWriter, r *http.Request) {
	if _, err := a.Store.GetApp(r.PathValue("id")); err != nil {
		writeStoreErr(w, err)
		return
	}
	creds, err := a.Store.ListAppKeyCredentials(r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	dtos := make([]map[string]any, 0, len(creds))
	for _, c := range creds {
		dtos = append(dtos, map[string]any{
			"id": c.ID, "displayName": nullable(c.DisplayName), "createdAt": iso(c.CreatedAt),
		})
	}
	paged(w, dtos, len(dtos), len(dtos), 0)
}

// addKeyCredential registers a PEM public key or certificate for an app.
func (a *Admin) addKeyCredential(w http.ResponseWriter, r *http.Request) {
	if _, err := a.Store.GetApp(r.PathValue("id")); err != nil {
		writeStoreErr(w, err)
		return
	}
	var body struct {
		PublicKey   string `json:"publicKey"`
		DisplayName string `json:"displayName"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if body.PublicKey == "" {
		httpx.WriteAdminError(w, http.StatusBadRequest, "validation_error",
			"publicKey (PEM) is required.")
		return
	}
	cred := &store.AppKeyCredential{
		ID: store.NewGUID(), AppID: r.PathValue("id"),
		PublicKey: body.PublicKey, DisplayName: body.DisplayName, CreatedAt: a.Store.Now(),
	}
	if err := a.Store.AddAppKeyCredential(cred); err != nil {
		writeStoreErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"id": cred.ID, "displayName": nullable(cred.DisplayName), "createdAt": iso(cred.CreatedAt),
	})
}

func (a *Admin) deleteKeyCredential(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.DeleteAppKeyCredential(r.PathValue("id"), r.PathValue("credId")); err != nil {
		writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
