package graph

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// Graph write surface (roadmap #18): user/group/application create-update-delete
// and group membership $ref links, backed by the same store the portal admin
// API writes to. No fine-grained permission enforcement (documented divergence);
// a valid Graph-audience token suffices.

// registerWrites mounts the write routes; called from Register.
func (g *Graph) registerWrites(mux *http.ServeMux, prefix string) {
	mux.HandleFunc("POST "+prefix+"/v1.0/users", g.requireBearer(g.createUser))
	mux.HandleFunc("PATCH "+prefix+"/v1.0/users/{id}", g.requireBearer(g.updateUser))
	mux.HandleFunc("DELETE "+prefix+"/v1.0/users/{id}", g.requireBearer(g.deleteUser))

	mux.HandleFunc("POST "+prefix+"/v1.0/groups", g.requireBearer(g.createGroup))
	mux.HandleFunc("PATCH "+prefix+"/v1.0/groups/{id}", g.requireBearer(g.updateGroup))
	mux.HandleFunc("DELETE "+prefix+"/v1.0/groups/{id}", g.requireBearer(g.deleteGroup))
	mux.HandleFunc("POST "+prefix+"/v1.0/groups/{id}/members/$ref", g.requireBearer(g.addGroupMember))
	mux.HandleFunc("DELETE "+prefix+"/v1.0/groups/{id}/members/{userId}/$ref", g.requireBearer(g.removeGroupMember))

	mux.HandleFunc("POST "+prefix+"/v1.0/applications", g.requireBearer(g.createApplication))
	mux.HandleFunc("PATCH "+prefix+"/v1.0/applications/{id}", g.requireBearer(g.updateApplication))
	mux.HandleFunc("DELETE "+prefix+"/v1.0/applications/{id}", g.requireBearer(g.deleteApplication))
}

// tenantOf resolves the tenant a write targets: the token's tid, or home.
func (g *Graph) tenantOf(tok *tokens.ValidatedToken) string {
	if tid, _ := tok.Claims["tid"].(string); tid != "" {
		return tid
	}
	return g.Cfg.TenantID
}

func decodeGraph(w http.ResponseWriter, r *http.Request, into any) bool {
	if err := json.NewDecoder(r.Body).Decode(into); err != nil {
		httpx.WriteGraphError(w, http.StatusBadRequest, "BadRequest", "Invalid JSON: "+err.Error())
		return false
	}
	return true
}

// writeStoreErrGraph maps store sentinels onto Graph error shapes.
func writeStoreErrGraph(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound", "The resource does not exist.")
	case errors.Is(err, store.ErrConflict):
		httpx.WriteGraphError(w, http.StatusBadRequest, "Request_BadRequest",
			"Another object with the same value for property already exists.")
	default:
		httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
	}
}

// ---- Users ----

type userWriteBody struct {
	AccountEnabled    *bool   `json:"accountEnabled"`
	DisplayName       *string `json:"displayName"`
	GivenName         *string `json:"givenName"`
	Surname           *string `json:"surname"`
	Mail              *string `json:"mail"`
	UserPrincipalName *string `json:"userPrincipalName"`
	PasswordProfile   *struct {
		Password string `json:"password"`
	} `json:"passwordProfile"`
}

func (g *Graph) createUser(w http.ResponseWriter, r *http.Request, tok *tokens.ValidatedToken) {
	var b userWriteBody
	if !decodeGraph(w, r, &b) {
		return
	}
	if b.DisplayName == nil || *b.DisplayName == "" || b.UserPrincipalName == nil || *b.UserPrincipalName == "" {
		httpx.WriteGraphError(w, http.StatusBadRequest, "Request_BadRequest",
			"displayName and userPrincipalName are required.")
		return
	}
	u := &store.User{
		ID: store.NewGUID(), TenantID: g.tenantOf(tok),
		UserPrincipalName: *b.UserPrincipalName, DisplayName: *b.DisplayName,
		AccountEnabled: true, CreatedAt: g.Store.Now(),
	}
	if b.AccountEnabled != nil {
		u.AccountEnabled = *b.AccountEnabled
	}
	if b.GivenName != nil {
		u.GivenName = *b.GivenName
	}
	if b.Surname != nil {
		u.Surname = *b.Surname
	}
	if b.Mail != nil {
		u.Mail = *b.Mail
	}
	if b.PasswordProfile != nil && b.PasswordProfile.Password != "" {
		hash, err := store.HashSecret(b.PasswordProfile.Password)
		if err != nil {
			httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		u.PasswordHash = hash
	}
	if err := g.Store.CreateUser(u); err != nil {
		writeStoreErrGraph(w, err)
		return
	}
	shape := userShape(u)
	shape["@odata.context"] = g.contextURL("users/$entity")
	httpx.WriteJSON(w, http.StatusCreated, shape)
}

func (g *Graph) updateUser(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	u, err := g.Store.GetUser(r.PathValue("id"))
	if err != nil {
		writeStoreErrGraph(w, err)
		return
	}
	var b userWriteBody
	if !decodeGraph(w, r, &b) {
		return
	}
	if b.DisplayName != nil {
		u.DisplayName = *b.DisplayName
	}
	if b.GivenName != nil {
		u.GivenName = *b.GivenName
	}
	if b.Surname != nil {
		u.Surname = *b.Surname
	}
	if b.Mail != nil {
		u.Mail = *b.Mail
	}
	if b.UserPrincipalName != nil {
		u.UserPrincipalName = *b.UserPrincipalName
	}
	if b.AccountEnabled != nil {
		u.AccountEnabled = *b.AccountEnabled
	}
	if b.PasswordProfile != nil && b.PasswordProfile.Password != "" {
		hash, err := store.HashSecret(b.PasswordProfile.Password)
		if err != nil {
			httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		u.PasswordHash = hash
	}
	if err := g.Store.UpdateUser(u); err != nil {
		writeStoreErrGraph(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (g *Graph) deleteUser(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	if err := g.Store.DeleteUser(r.PathValue("id")); err != nil {
		writeStoreErrGraph(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- Groups ----

type groupWriteBody struct {
	DisplayName *string `json:"displayName"`
	Description *string `json:"description"`
}

func (g *Graph) createGroup(w http.ResponseWriter, r *http.Request, tok *tokens.ValidatedToken) {
	var b groupWriteBody
	if !decodeGraph(w, r, &b) {
		return
	}
	if b.DisplayName == nil || *b.DisplayName == "" {
		httpx.WriteGraphError(w, http.StatusBadRequest, "Request_BadRequest", "displayName is required.")
		return
	}
	gr := &store.Group{ID: store.NewGUID(), TenantID: g.tenantOf(tok),
		DisplayName: *b.DisplayName, CreatedAt: g.Store.Now()}
	if b.Description != nil {
		gr.Description = *b.Description
	}
	if err := g.Store.CreateGroup(gr); err != nil {
		writeStoreErrGraph(w, err)
		return
	}
	shape := groupShape(gr)
	shape["@odata.context"] = g.contextURL("groups/$entity")
	httpx.WriteJSON(w, http.StatusCreated, shape)
}

func (g *Graph) updateGroup(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	gr, err := g.Store.GetGroup(r.PathValue("id"))
	if err != nil {
		writeStoreErrGraph(w, err)
		return
	}
	var b groupWriteBody
	if !decodeGraph(w, r, &b) {
		return
	}
	if b.DisplayName != nil {
		gr.DisplayName = *b.DisplayName
	}
	if b.Description != nil {
		gr.Description = *b.Description
	}
	if err := g.Store.UpdateGroup(gr); err != nil {
		writeStoreErrGraph(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (g *Graph) deleteGroup(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	if err := g.Store.DeleteGroup(r.PathValue("id")); err != nil {
		writeStoreErrGraph(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// addGroupMember consumes the {"@odata.id": ".../directoryObjects/{userId}"}
// reference body Graph uses for member links.
func (g *Graph) addGroupMember(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	var b struct {
		ODataID string `json:"@odata.id"`
	}
	if !decodeGraph(w, r, &b) {
		return
	}
	userID := refTailID(b.ODataID)
	if userID == "" {
		httpx.WriteGraphError(w, http.StatusBadRequest, "Request_BadRequest", "@odata.id is required.")
		return
	}
	if err := g.Store.AddGroupMember(r.PathValue("id"), userID); err != nil {
		writeStoreErrGraph(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (g *Graph) removeGroupMember(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	if _, err := g.Store.GetGroup(r.PathValue("id")); err != nil {
		writeStoreErrGraph(w, err)
		return
	}
	if err := g.Store.RemoveGroupMember(r.PathValue("id"), r.PathValue("userId")); err != nil {
		writeStoreErrGraph(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// refTailID extracts the trailing directory-object GUID from an @odata.id URL
// like https://graph/.../directoryObjects/{id} or .../users/{id}.
func refTailID(odataID string) string {
	odataID = strings.TrimSpace(odataID)
	if odataID == "" {
		return ""
	}
	if i := strings.LastIndex(odataID, "/"); i >= 0 {
		return odataID[i+1:]
	}
	return odataID
}

// ---- Applications ----

type applicationWriteBody struct {
	DisplayName    *string  `json:"displayName"`
	IdentifierUris []string `json:"identifierUris"`
	SignInAudience *string  `json:"signInAudience"`
}

func (g *Graph) createApplication(w http.ResponseWriter, r *http.Request, tok *tokens.ValidatedToken) {
	var b applicationWriteBody
	if !decodeGraph(w, r, &b) {
		return
	}
	if b.DisplayName == nil || *b.DisplayName == "" {
		httpx.WriteGraphError(w, http.StatusBadRequest, "Request_BadRequest", "displayName is required.")
		return
	}
	app := &store.App{ID: store.NewGUID(), TenantID: g.tenantOf(tok),
		DisplayName: *b.DisplayName, GroupMembershipClaims: "None", CreatedAt: g.Store.Now()}
	if len(b.IdentifierUris) > 0 {
		app.AppIDURI = b.IdentifierUris[0]
	}
	if err := g.Store.CreateApp(app); err != nil {
		writeStoreErrGraph(w, err)
		return
	}
	shape := g.applicationDTO(app)
	shape["@odata.context"] = g.contextURL("applications/$entity")
	httpx.WriteJSON(w, http.StatusCreated, shape)
}

func (g *Graph) updateApplication(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	app, err := g.Store.GetApp(r.PathValue("id"))
	if err != nil {
		writeStoreErrGraph(w, err)
		return
	}
	var b applicationWriteBody
	if !decodeGraph(w, r, &b) {
		return
	}
	if b.DisplayName != nil {
		app.DisplayName = *b.DisplayName
	}
	if b.IdentifierUris != nil {
		if len(b.IdentifierUris) > 0 {
			app.AppIDURI = b.IdentifierUris[0]
		} else {
			app.AppIDURI = ""
		}
	}
	if err := g.Store.UpdateApp(app); err != nil {
		writeStoreErrGraph(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (g *Graph) deleteApplication(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	if err := g.Store.DeleteApp(r.PathValue("id")); err != nil {
		writeStoreErrGraph(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

