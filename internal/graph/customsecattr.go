package graph

import (
	"net/http"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// Custom security attributes: tenant-defined typed metadata. Definitions live
// under /directory, and values are assigned onto a user.
//
// Graph does NOT return customSecurityAttributes on a user by default — it is
// only returned when explicitly $select-ed, and only to a caller holding the
// attribute permissions. The emulator matches that, which is also why adding
// this feature does not change the default user shape.

func (g *Graph) registerCustomSecurityAttributes(mux *http.ServeMux, prefix string) {
	p := prefix + "/v1.0/directory"
	mux.HandleFunc("GET "+p+"/attributeSets", g.requireBearer(g.listAttributeSets))
	mux.HandleFunc("POST "+p+"/attributeSets", g.requireBearer(g.createAttributeSet))
	mux.HandleFunc("GET "+p+"/attributeSets/{id}", g.requireBearer(g.getAttributeSet))
	mux.HandleFunc("GET "+p+"/customSecurityAttributeDefinitions", g.requireBearer(g.listCSADefs))
	mux.HandleFunc("POST "+p+"/customSecurityAttributeDefinitions", g.requireBearer(g.createCSADef))
	mux.HandleFunc("GET "+p+"/customSecurityAttributeDefinitions/{id}", g.requireBearer(g.getCSADef))
}

func attributeSetShape(a *store.AttributeSet) map[string]any {
	return map[string]any{
		"@odata.type": "#microsoft.graph.attributeSet",
		"id":          a.ID, "description": nullable(a.Description),
		"maxAttributesPerSet": a.MaxAttributesPerSet,
	}
}

func csaDefShape(d *store.CustomSecurityAttributeDefinition) map[string]any {
	return map[string]any{
		"@odata.type":  "#microsoft.graph.customSecurityAttributeDefinition",
		"id":           d.ID,
		"attributeSet": d.AttributeSet,
		"name":         d.Name,
		"description":  nullable(d.Description),
		"type":         d.Type,
		"status":       d.Status,
		"isCollection": d.IsCollection,
		"isSearchable": d.IsSearchable,
	}
}

func (g *Graph) listAttributeSets(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	sets, err := g.Store.ListAttributeSets()
	if err != nil {
		httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	shapes := make([]map[string]any, 0, len(sets))
	for _, a := range sets {
		shapes = append(shapes, attributeSetShape(a))
	}
	g.writeSimpleCollection(w, "directory/attributeSets", shapes)
}

func (g *Graph) createAttributeSet(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	var body struct {
		ID                  string `json:"id"`
		Description         string `json:"description"`
		MaxAttributesPerSet *int   `json:"maxAttributesPerSet"`
	}
	if !decodeGraph(w, r, &body) {
		return
	}
	if body.ID == "" {
		httpx.WriteGraphError(w, http.StatusBadRequest, "Request_BadRequest", "id is required.")
		return
	}
	a := &store.AttributeSet{ID: body.ID, Description: body.Description, MaxAttributesPerSet: body.MaxAttributesPerSet}
	if err := g.Store.CreateAttributeSet(a); err != nil {
		httpx.WriteGraphError(w, http.StatusConflict, "Request_BadRequest", "Attribute set already exists.")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, attributeSetShape(a))
}

func (g *Graph) getAttributeSet(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	a, err := g.Store.GetAttributeSet(r.PathValue("id"))
	if err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound", "Attribute set does not exist.")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, attributeSetShape(a))
}

func (g *Graph) listCSADefs(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	defs, err := g.Store.ListCSADefinitions()
	if err != nil {
		httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	shapes := make([]map[string]any, 0, len(defs))
	for _, d := range defs {
		shapes = append(shapes, csaDefShape(d))
	}
	g.writeSimpleCollection(w, "directory/customSecurityAttributeDefinitions", shapes)
}

func (g *Graph) createCSADef(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	var body struct {
		AttributeSet string `json:"attributeSet"`
		Name         string `json:"name"`
		Description  string `json:"description"`
		Type         string `json:"type"`
		Status       string `json:"status"`
		IsCollection bool   `json:"isCollection"`
		IsSearchable *bool  `json:"isSearchable"`
	}
	if !decodeGraph(w, r, &body) {
		return
	}
	if body.AttributeSet == "" || body.Name == "" {
		httpx.WriteGraphError(w, http.StatusBadRequest, "Request_BadRequest",
			"attributeSet and name are required.")
		return
	}
	switch body.Type {
	case "String", "Integer", "Boolean":
	default:
		httpx.WriteGraphError(w, http.StatusBadRequest, "Request_BadRequest",
			"type must be String, Integer or Boolean.")
		return
	}
	d := &store.CustomSecurityAttributeDefinition{
		AttributeSet: body.AttributeSet, Name: body.Name, Description: body.Description,
		Type: body.Type, Status: body.Status, IsCollection: body.IsCollection, IsSearchable: true,
	}
	if d.Status == "" {
		d.Status = "Available"
	}
	if body.IsSearchable != nil {
		d.IsSearchable = *body.IsSearchable
	}
	if err := g.Store.CreateCSADefinition(d); err != nil {
		httpx.WriteGraphError(w, http.StatusBadRequest, "Request_BadRequest",
			"Could not create the definition: its attribute set must exist and the name must be unique within it.")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, csaDefShape(d))
}

func (g *Graph) getCSADef(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	d, err := g.Store.GetCSADefinition(r.PathValue("id"))
	if err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound", "Definition does not exist.")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, csaDefShape(d))
}
