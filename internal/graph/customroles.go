package graph

import (
	"net/http"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// Custom (tenant-authored) directory role definitions. Built-in roles are the
// fixed list in roles.go; these are created at runtime and stored.
//
// They are NOT built-in, which matters beyond a boolean: `isBuiltIn:false`,
// no `templateId` (real Entra only assigns template GUIDs to built-ins), and —
// enforced in the store — they never appear in a token's `wids` claim.

func (g *Graph) registerCustomRoles(mux *http.ServeMux, prefix string) {
	base := prefix + "/v1.0/roleManagement/directory/roleDefinitions"
	mux.HandleFunc("POST "+base, g.requireBearer(g.createRoleDefinition))
	mux.HandleFunc("PATCH "+base+"/{id}", g.requireBearer(g.updateRoleDefinition))
	mux.HandleFunc("DELETE "+base+"/{id}", g.requireBearer(g.deleteRoleDefinition))
}

func customRoleShape(d *store.CustomRoleDefinition) map[string]any {
	perms := []any{}
	if len(d.RolePermissions) > 0 {
		perms = append(perms, map[string]any{"allowedResourceActions": d.RolePermissions})
	}
	return map[string]any{
		"@odata.type":     "#microsoft.graph.unifiedRoleDefinition",
		"id":              d.ID,
		"displayName":     d.DisplayName,
		"description":     d.Description,
		"isBuiltIn":       false,
		"isEnabled":       d.IsEnabled,
		"rolePermissions": perms,
	}
}

type roleDefBody struct {
	DisplayName     string   `json:"displayName"`
	Description     string   `json:"description"`
	IsEnabled       *bool    `json:"isEnabled"`
	RolePermissions []string `json:"rolePermissions"`
}

func (g *Graph) createRoleDefinition(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	var body roleDefBody
	if !decodeGraph(w, r, &body) {
		return
	}
	if body.DisplayName == "" {
		httpx.WriteGraphError(w, http.StatusBadRequest, "Request_BadRequest", "displayName is required.")
		return
	}
	d := &store.CustomRoleDefinition{
		ID: store.NewGUID(), DisplayName: body.DisplayName, Description: body.Description,
		IsEnabled: true, RolePermissions: body.RolePermissions, CreatedAt: g.Store.Now(),
	}
	if body.IsEnabled != nil {
		d.IsEnabled = *body.IsEnabled
	}
	if err := g.Store.CreateCustomRoleDefinition(d); err != nil {
		httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	shape := customRoleShape(d)
	shape["@odata.context"] = g.contextURL("roleManagement/directory/roleDefinitions/$entity")
	httpx.WriteJSON(w, http.StatusCreated, shape)
}

func (g *Graph) updateRoleDefinition(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	id := r.PathValue("id")
	if _, isBuiltIn := roleDefByID[id]; isBuiltIn {
		httpx.WriteGraphError(w, http.StatusForbidden, "Authorization_RequestDenied",
			"Built-in role definitions cannot be modified.")
		return
	}
	d, err := g.Store.GetCustomRoleDefinition(id)
	if err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound", "Role definition does not exist.")
		return
	}
	var body roleDefBody
	if !decodeGraph(w, r, &body) {
		return
	}
	if body.DisplayName != "" {
		d.DisplayName = body.DisplayName
	}
	if body.Description != "" {
		d.Description = body.Description
	}
	if body.IsEnabled != nil {
		d.IsEnabled = *body.IsEnabled
	}
	if body.RolePermissions != nil {
		d.RolePermissions = body.RolePermissions
	}
	if err := g.Store.UpdateCustomRoleDefinition(d); err != nil {
		httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, customRoleShape(d))
}

func (g *Graph) deleteRoleDefinition(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	id := r.PathValue("id")
	if _, isBuiltIn := roleDefByID[id]; isBuiltIn {
		httpx.WriteGraphError(w, http.StatusForbidden, "Authorization_RequestDenied",
			"Built-in role definitions cannot be deleted.")
		return
	}
	if err := g.Store.DeleteCustomRoleDefinition(id); err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound", "Role definition does not exist.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
