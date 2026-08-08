package graph

import (
	"net/http"
	"strings"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// Administrative units: directory containers that scope administration to a
// subset of users and groups. Mounted under /directory, so the existing
// permission gate already requires Directory.Read.All / Directory.ReadWrite.All.

func (g *Graph) registerAdminUnits(mux *http.ServeMux, prefix string) {
	base := prefix + "/v1.0/directory/administrativeUnits"
	mux.HandleFunc("GET "+base, g.requireBearer(g.listAdminUnits))
	mux.HandleFunc("POST "+base, g.requireBearer(g.createAdminUnit))
	mux.HandleFunc("GET "+base+"/{id}", g.requireBearer(g.getAdminUnit))
	mux.HandleFunc("PATCH "+base+"/{id}", g.requireBearer(g.updateAdminUnit))
	mux.HandleFunc("DELETE "+base+"/{id}", g.requireBearer(g.deleteAdminUnit))
	mux.HandleFunc("GET "+base+"/{id}/members", g.requireBearer(g.listAdminUnitMembers))
	mux.HandleFunc("POST "+base+"/{id}/members/$ref", g.requireBearer(g.addAdminUnitMember))
	mux.HandleFunc("DELETE "+base+"/{id}/members/{memberId}/$ref", g.requireBearer(g.removeAdminUnitMember))
}

func adminUnitShape(a *store.AdministrativeUnit) map[string]any {
	return map[string]any{
		"@odata.type": "#microsoft.graph.administrativeUnit",
		"id":          a.ID,
		"displayName": a.DisplayName,
		"description": nullable(a.Description),
		"visibility":  a.Visibility,
	}
}

type adminUnitBody struct {
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
	Visibility  string `json:"visibility"`
}

func (g *Graph) listAdminUnits(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	units, err := g.Store.ListAdministrativeUnits()
	if err != nil {
		httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	shapes := make([]map[string]any, 0, len(units))
	for _, a := range units {
		shapes = append(shapes, adminUnitShape(a))
	}
	g.writeSimpleCollection(w, "directory/administrativeUnits", shapes)
}

func (g *Graph) createAdminUnit(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	var body adminUnitBody
	if !decodeGraph(w, r, &body) {
		return
	}
	if body.DisplayName == "" {
		httpx.WriteGraphError(w, http.StatusBadRequest, "Request_BadRequest", "displayName is required.")
		return
	}
	if body.Visibility != "" && body.Visibility != "Public" && body.Visibility != "HiddenMembership" {
		httpx.WriteGraphError(w, http.StatusBadRequest, "Request_BadRequest",
			"visibility must be Public or HiddenMembership.")
		return
	}
	a := &store.AdministrativeUnit{
		ID: store.NewGUID(), DisplayName: body.DisplayName,
		Description: body.Description, Visibility: body.Visibility, CreatedAt: g.Store.Now(),
	}
	if err := g.Store.CreateAdministrativeUnit(a); err != nil {
		httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	shape := adminUnitShape(a)
	shape["@odata.context"] = g.contextURL("directory/administrativeUnits/$entity")
	httpx.WriteJSON(w, http.StatusCreated, shape)
}

func (g *Graph) getAdminUnit(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	a, err := g.Store.GetAdministrativeUnit(r.PathValue("id"))
	if err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound", "Administrative unit does not exist.")
		return
	}
	shape := g.selectEntity(r, adminUnitShape(a))
	shape["@odata.context"] = g.contextURL("directory/administrativeUnits/$entity")
	httpx.WriteJSON(w, http.StatusOK, shape)
}

func (g *Graph) updateAdminUnit(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	a, err := g.Store.GetAdministrativeUnit(r.PathValue("id"))
	if err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound", "Administrative unit does not exist.")
		return
	}
	var body adminUnitBody
	if !decodeGraph(w, r, &body) {
		return
	}
	if body.DisplayName != "" {
		a.DisplayName = body.DisplayName
	}
	if body.Description != "" {
		a.Description = body.Description
	}
	if body.Visibility != "" {
		if body.Visibility != "Public" && body.Visibility != "HiddenMembership" {
			httpx.WriteGraphError(w, http.StatusBadRequest, "Request_BadRequest",
				"visibility must be Public or HiddenMembership.")
			return
		}
		a.Visibility = body.Visibility
	}
	if err := g.Store.UpdateAdministrativeUnit(a); err != nil {
		httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, adminUnitShape(a))
}

func (g *Graph) deleteAdminUnit(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	if err := g.Store.DeleteAdministrativeUnit(r.PathValue("id")); err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound", "Administrative unit does not exist.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (g *Graph) listAdminUnitMembers(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	auID := r.PathValue("id")
	if _, err := g.Store.GetAdministrativeUnit(auID); err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound", "Administrative unit does not exist.")
		return
	}
	members, err := g.Store.ListAdminUnitMembers(auID)
	if err != nil {
		httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	shapes := make([]map[string]any, 0, len(members))
	for _, m := range members {
		if m.Type == "group" {
			if gr, err := g.Store.GetGroup(m.ID); err == nil {
				s := groupShape(gr)
				s["@odata.type"] = "#microsoft.graph.group"
				shapes = append(shapes, s)
			}
			continue
		}
		if u, err := g.Store.GetUser(m.ID); err == nil {
			s := userShape(u)
			s["@odata.type"] = "#microsoft.graph.user"
			shapes = append(shapes, s)
		}
	}
	g.writeSimpleCollection(w, "directoryObjects", shapes)
}

// addAdminUnitMember takes Graph's @odata.id reference body, the same shape
// group membership uses.
func (g *Graph) addAdminUnitMember(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	var body struct {
		ODataID string `json:"@odata.id"`
	}
	if !decodeGraph(w, r, &body) {
		return
	}
	memberID := body.ODataID
	if i := strings.LastIndex(memberID, "/"); i >= 0 {
		memberID = memberID[i+1:]
	}
	if memberID == "" {
		httpx.WriteGraphError(w, http.StatusBadRequest, "Request_BadRequest", "@odata.id is required.")
		return
	}
	if err := g.Store.AddAdminUnitMember(r.PathValue("id"), memberID); err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound",
			"The administrative unit or the member object does not exist.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (g *Graph) removeAdminUnitMember(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	if err := g.Store.RemoveAdminUnitMember(r.PathValue("id"), r.PathValue("memberId")); err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound", "Membership does not exist.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
