package admin

import (
	"net/http"
	"strings"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/store"
)

// Fabric workspace identities (roadmap #16b). A workspace identity is an app
// registration + service principal with an emulator-managed credential, linked
// to a Fabric workspace: its name follows the workspace and deleting it
// cascades the SP. Tokens are minted internally via the STS endpoint
// (GET /fabric/workspaceidentities/{id}/token) — no caller-held secret.

func (a *Admin) workspaceIdentityDTO(wi *store.WorkspaceIdentity) map[string]any {
	return map[string]any{
		"id":            wi.ID,    // service principal object id
		"appId":         wi.AppID, // the SP's client/app id
		"tenantId":      wi.TenantID,
		"workspaceId":   wi.WorkspaceID,
		"workspaceName": wi.WorkspaceName,
		"state":         wi.State,
		"createdAt":     iso(wi.CreatedAt),
	}
}

func (a *Admin) listWorkspaceIdentities(w http.ResponseWriter, r *http.Request) {
	wis, err := a.Store.ListWorkspaceIdentities()
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	dtos := make([]map[string]any, 0, len(wis))
	for _, wi := range wis {
		dtos = append(dtos, a.workspaceIdentityDTO(wi))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"value": dtos})
}

func (a *Admin) getWorkspaceIdentity(w http.ResponseWriter, r *http.Request) {
	wi, err := a.Store.GetWorkspaceIdentity(r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, a.workspaceIdentityDTO(wi))
}

type workspaceIdentityBody struct {
	WorkspaceName *string `json:"workspaceName"`
	WorkspaceID   *string `json:"workspaceId"`
	TenantID      *string `json:"tenantId"`
	State         *string `json:"state"`
}

func (a *Admin) createWorkspaceIdentity(w http.ResponseWriter, r *http.Request) {
	var b workspaceIdentityBody
	if r.ContentLength > 0 && !decodeBody(w, r, &b) {
		return
	}

	name := ""
	if b.WorkspaceName != nil {
		name = strings.TrimSpace(*b.WorkspaceName)
	}
	if name == "" {
		name = gofakeit.Company() + " Analytics"
	}

	tenantID := a.Cfg.TenantID
	if b.TenantID != nil && *b.TenantID != "" {
		if _, err := a.Store.GetTenantByID(*b.TenantID); err != nil {
			httpx.WriteAdminError(w, http.StatusBadRequest, "invalid_reference",
				"tenantId does not resolve to a tenant.")
			return
		}
		tenantID = *b.TenantID
	}

	workspaceID := ""
	if b.WorkspaceID != nil {
		workspaceID = strings.TrimSpace(*b.WorkspaceID)
	}
	if workspaceID == "" {
		workspaceID = store.NewGUID()
	}

	now := a.Store.Now()
	appID := store.NewGUID()
	app := &store.App{ID: appID, TenantID: tenantID, DisplayName: name, IsConfidential: true, CreatedAt: now}
	wi := &store.WorkspaceIdentity{
		ID: store.NewGUID(), TenantID: tenantID, AppID: appID,
		WorkspaceID: workspaceID, WorkspaceName: name, State: "Active", CreatedAt: now,
	}
	if err := a.Store.CreateWorkspaceIdentity(wi, app); err != nil {
		writeStoreErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, a.workspaceIdentityDTO(wi))
}

func (a *Admin) patchWorkspaceIdentity(w http.ResponseWriter, r *http.Request) {
	wi, err := a.Store.GetWorkspaceIdentity(r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	var b workspaceIdentityBody
	if !decodeBody(w, r, &b) {
		return
	}
	if b.WorkspaceName != nil {
		if name := strings.TrimSpace(*b.WorkspaceName); name != "" {
			wi.WorkspaceName = name // name follows the workspace; SP renamed in store
		}
	}
	if b.State != nil {
		if !store.ValidWorkspaceIdentityState(*b.State) {
			httpx.WriteAdminError(w, http.StatusBadRequest, "validation_error", "Invalid workspace identity.",
				httpx.AdminDetail{Field: "state", Message: "Must be Active, Provisioning, Failed, or Deprovisioning."})
			return
		}
		wi.State = *b.State
	}
	if err := a.Store.UpdateWorkspaceIdentity(wi); err != nil {
		writeStoreErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, a.workspaceIdentityDTO(wi))
}

func (a *Admin) deleteWorkspaceIdentity(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.DeleteWorkspaceIdentity(r.PathValue("id")); err != nil {
		writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
