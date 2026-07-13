package graph

import (
	"net/http"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// Directory roles (docs/19-stateful-directory.md): the modern unified-RBAC
// surface, roleManagement/directory. Built-in role definitions are static
// (their id equals the role template GUID); assignments are persisted. A
// tenant-wide assignment (directoryScopeId "/") drives the user's wids claim.

type roleDef struct {
	ID          string
	DisplayName string
	Description string
}

// builtInRoleDefinitions are the common Entra directory roles. IDs are the
// published role template GUIDs (identity/role-based-access-control docs).
var builtInRoleDefinitions = []roleDef{
	{"62e90394-69f5-4237-9190-012177145e10", "Global Administrator", "Can manage all aspects of Microsoft Entra ID and Microsoft services that use Microsoft Entra identities."},
	{"f2ef992c-3afb-46b9-b7cf-a126ee74c451", "Global Reader", "Can read everything that a Global Administrator can, but not update anything."},
	{"e8611ab8-c189-46e8-94e1-60213ab1f814", "Privileged Role Administrator", "Can manage role assignments in Microsoft Entra ID, and all aspects of Privileged Identity Management."},
	{"fe930be7-5e62-47db-91af-98c3a49a38b1", "User Administrator", "Can manage all aspects of users and groups, including resetting passwords for limited admins."},
	{"9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", "Application Administrator", "Can create and manage all aspects of app registrations and enterprise apps."},
	{"158c047a-c907-4556-b7ef-446551a6b5f7", "Cloud Application Administrator", "Can create and manage all aspects of app registrations and enterprise apps except App Proxy."},
}

var roleDefByID = func() map[string]roleDef {
	m := map[string]roleDef{}
	for _, d := range builtInRoleDefinitions {
		m[d.ID] = d
	}
	return m
}()

func (g *Graph) registerRoles(mux *http.ServeMux, prefix string) {
	base := prefix + "/v1.0/roleManagement/directory"
	mux.HandleFunc("GET "+base+"/roleDefinitions", g.requireBearer(g.listRoleDefinitions))
	mux.HandleFunc("GET "+base+"/roleDefinitions/{id}", g.requireBearer(g.getRoleDefinition))
	mux.HandleFunc("GET "+base+"/roleAssignments", g.requireBearer(g.listRoleAssignments))
	mux.HandleFunc("POST "+base+"/roleAssignments", g.requireBearer(g.createRoleAssignment))
	mux.HandleFunc("GET "+base+"/roleAssignments/{id}", g.requireBearer(g.getRoleAssignment))
	mux.HandleFunc("DELETE "+base+"/roleAssignments/{id}", g.requireBearer(g.deleteRoleAssignment))
}

func roleDefShape(d roleDef) map[string]any {
	return map[string]any{
		"id":              d.ID,
		"templateId":      d.ID,
		"displayName":     d.DisplayName,
		"description":     d.Description,
		"isBuiltIn":       true,
		"isEnabled":       true,
		"rolePermissions": []any{},
	}
}

func (g *Graph) listRoleDefinitions(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	shapes := make([]map[string]any, 0, len(builtInRoleDefinitions))
	for _, d := range builtInRoleDefinitions {
		shapes = append(shapes, roleDefShape(d))
	}
	g.writeSimpleCollection(w, "roleManagement/directory/roleDefinitions", shapes)
}

func (g *Graph) getRoleDefinition(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	d, ok := roleDefByID[r.PathValue("id")]
	if !ok {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound", "Role definition does not exist.")
		return
	}
	shape := roleDefShape(d)
	shape["@odata.context"] = g.contextURL("roleManagement/directory/roleDefinitions/$entity")
	httpx.WriteJSON(w, http.StatusOK, shape)
}

func roleAssignmentShape(a *store.DirectoryRoleAssignment) map[string]any {
	return map[string]any{
		"@odata.type":      "#microsoft.graph.unifiedRoleAssignment",
		"id":               a.ID,
		"roleDefinitionId": a.RoleDefinitionID,
		"principalId":      a.PrincipalID,
		"directoryScopeId": a.DirectoryScopeID,
	}
}

func (g *Graph) listRoleAssignments(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	list, err := g.Store.ListDirectoryRoleAssignments()
	if err != nil {
		httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	raw := r.URL.Query().Get("$filter")
	wantPrincipal, hasPrincipal := grantFilterField(raw, "principalId")
	wantRole, hasRole := grantFilterField(raw, "roleDefinitionId")
	shapes := make([]map[string]any, 0, len(list))
	for _, a := range list {
		if hasPrincipal && a.PrincipalID != wantPrincipal {
			continue
		}
		if hasRole && a.RoleDefinitionID != wantRole {
			continue
		}
		shapes = append(shapes, roleAssignmentShape(a))
	}
	g.writeSimpleCollection(w, "roleManagement/directory/roleAssignments", shapes)
}

func (g *Graph) getRoleAssignment(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	a, err := g.Store.GetDirectoryRoleAssignment(r.PathValue("id"))
	if err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound", "Role assignment does not exist.")
		return
	}
	shape := roleAssignmentShape(a)
	shape["@odata.context"] = g.contextURL("roleManagement/directory/roleAssignments/$entity")
	httpx.WriteJSON(w, http.StatusOK, shape)
}

func (g *Graph) createRoleAssignment(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	var b struct {
		RoleDefinitionID string `json:"roleDefinitionId"`
		PrincipalID      string `json:"principalId"`
		DirectoryScopeID string `json:"directoryScopeId"`
	}
	if !decodeGraph(w, r, &b) {
		return
	}
	if b.RoleDefinitionID == "" || b.PrincipalID == "" {
		httpx.WriteGraphError(w, http.StatusBadRequest, "Request_BadRequest",
			"roleDefinitionId and principalId are required.")
		return
	}
	if _, ok := roleDefByID[b.RoleDefinitionID]; !ok {
		httpx.WriteGraphError(w, http.StatusBadRequest, "Request_BadRequest",
			"Unknown roleDefinitionId (only built-in roles are supported).")
		return
	}
	if b.DirectoryScopeID == "" {
		b.DirectoryScopeID = "/"
	}
	a := &store.DirectoryRoleAssignment{
		ID: store.NewGUID(), RoleDefinitionID: b.RoleDefinitionID,
		PrincipalID: b.PrincipalID, DirectoryScopeID: b.DirectoryScopeID, CreatedAt: g.Store.Now(),
	}
	if err := g.Store.CreateDirectoryRoleAssignment(a); err != nil {
		writeStoreErrGraph(w, err)
		return
	}
	shape := roleAssignmentShape(a)
	shape["@odata.context"] = g.contextURL("roleManagement/directory/roleAssignments/$entity")
	httpx.WriteJSON(w, http.StatusCreated, shape)
}

func (g *Graph) deleteRoleAssignment(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	if err := g.Store.DeleteDirectoryRoleAssignment(r.PathValue("id")); err != nil {
		writeStoreErrGraph(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
