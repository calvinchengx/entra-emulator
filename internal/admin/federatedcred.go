package admin

import (
	"net/http"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/store"
)

// Federated identity credentials: the trusts that let an external workload's
// own OIDC token stand in for this app's secret (workload identity federation).
// Real Entra manages these at
// applications/{id}/federatedIdentityCredentials; the emulator's control
// surface is the admin API, which is where every other app credential is
// managed here too.

func (a *Admin) registerFederatedCredentials(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/api/apps/{id}/federated-credentials", a.listFederatedCredentials)
	mux.HandleFunc("POST /admin/api/apps/{id}/federated-credentials", a.addFederatedCredential)
	mux.HandleFunc("DELETE /admin/api/apps/{id}/federated-credentials/{credId}", a.deleteFederatedCredential)
}

func (a *Admin) listFederatedCredentials(w http.ResponseWriter, r *http.Request) {
	appID := r.PathValue("id")
	if _, err := a.Store.GetApp(appID); err != nil {
		writeStoreErr(w, err)
		return
	}
	creds, err := a.Store.ListFederatedCredentials(appID)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"value": creds, "count": len(creds)})
}

func (a *Admin) addFederatedCredential(w http.ResponseWriter, r *http.Request) {
	appID := r.PathValue("id")
	if _, err := a.Store.GetApp(appID); err != nil {
		writeStoreErr(w, err)
		return
	}
	body := struct {
		Name        string   `json:"name"`
		Issuer      string   `json:"issuer"`
		Subject     string   `json:"subject"`
		Audiences   []string `json:"audiences"`
		Description string   `json:"description"`
	}{}
	if !decodeBody(w, r, &body) {
		return
	}
	if body.Name == "" || body.Issuer == "" || body.Subject == "" {
		httpx.WriteAdminError(w, http.StatusBadRequest, "invalid_request",
			"name, issuer and subject are required.")
		return
	}
	cred := &store.FederatedCredential{
		ID: store.NewGUID(), AppID: appID, Name: body.Name,
		Issuer: body.Issuer, Subject: body.Subject, Audiences: body.Audiences,
		Description: body.Description, CreatedAt: a.Store.Now(),
	}
	if err := a.Store.CreateFederatedCredential(cred); err != nil {
		writeStoreErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, cred)
}

func (a *Admin) deleteFederatedCredential(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.DeleteFederatedCredential(r.PathValue("id"), r.PathValue("credId")); err != nil {
		writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
