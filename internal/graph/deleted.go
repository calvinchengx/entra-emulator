package graph

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// Recycle bin (docs/20-stateful-directory.md): directory/deletedItems. Graph
// DELETE on users/groups/applications soft-deletes into the store's recycle
// bin; these routes list, restore, and permanently delete those objects. The
// object-type cast is a literal path segment (microsoft.graph.user, .group,
// .application), which http.ServeMux prefers over the {id} wildcard.

func (g *Graph) registerDeleted(mux *http.ServeMux, prefix string) {
	base := prefix + "/v1.0/directory/deletedItems"
	mux.HandleFunc("GET "+base+"/microsoft.graph.user", g.requireBearer(g.listDeleted(store.DeletedTypeUser)))
	mux.HandleFunc("GET "+base+"/microsoft.graph.group", g.requireBearer(g.listDeleted(store.DeletedTypeGroup)))
	mux.HandleFunc("GET "+base+"/microsoft.graph.application", g.requireBearer(g.listDeleted(store.DeletedTypeApp)))
	mux.HandleFunc("GET "+base+"/{id}", g.requireBearer(g.getDeleted))
	mux.HandleFunc("POST "+base+"/{id}/restore", g.requireBearer(g.restoreDeleted))
	mux.HandleFunc("DELETE "+base+"/{id}", g.requireBearer(g.purgeDeleted))
}

// deletedODataType maps a stored object type to its Graph cast.
var deletedODataType = map[string]string{
	store.DeletedTypeUser:  "#microsoft.graph.user",
	store.DeletedTypeGroup: "#microsoft.graph.group",
	store.DeletedTypeApp:   "#microsoft.graph.application",
}

// deletedShape reconstructs the directory-object shape from a recycle-bin
// snapshot and stamps @odata.type + deletedDateTime.
func (g *Graph) deletedShape(d *store.DeletedItem) (map[string]any, error) {
	var shape map[string]any
	switch d.ObjectType {
	case store.DeletedTypeUser:
		var p struct {
			User *store.User `json:"user"`
		}
		if err := json.Unmarshal([]byte(d.Payload), &p); err != nil {
			return nil, err
		}
		shape = userShape(p.User)
	case store.DeletedTypeGroup:
		var p struct {
			Group *store.Group `json:"group"`
		}
		if err := json.Unmarshal([]byte(d.Payload), &p); err != nil {
			return nil, err
		}
		shape = groupShape(p.Group)
	case store.DeletedTypeApp:
		var ae store.AppExport
		if err := json.Unmarshal([]byte(d.Payload), &ae); err != nil {
			return nil, err
		}
		shape = g.applicationDTO(ae.App)
	default:
		shape = map[string]any{"id": d.ID}
	}
	shape["@odata.type"] = deletedODataType[d.ObjectType]
	shape["deletedDateTime"] = time.Unix(d.DeletedAt, 0).UTC().Format(time.RFC3339)
	return shape, nil
}

func (g *Graph) listDeleted(objectType string) handler {
	return func(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
		q, err := parseOData(r)
		if err != nil {
			httpx.WriteGraphError(w, http.StatusBadRequest, "BadRequest", err.Error())
			return
		}
		items, err := g.Store.ListDeletedItems(objectType)
		if err != nil {
			httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		shapes := make([]map[string]any, 0, len(items))
		for _, it := range items {
			s, err := g.deletedShape(it)
			if err != nil {
				httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
				return
			}
			shapes = append(shapes, s)
		}
		g.writeCollection(w, r, "directoryObjects/"+deletedODataType[objectType][1:], shapes, q)
	}
}

func (g *Graph) getDeleted(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	it, err := g.Store.GetDeletedItem(r.PathValue("id"))
	if err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound", "The deleted object does not exist.")
		return
	}
	shape, err := g.deletedShape(it)
	if err != nil {
		httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	shape["@odata.context"] = g.contextURL("directoryObjects/$entity")
	httpx.WriteJSON(w, http.StatusOK, g.selectEntity(r, shape))
}

func (g *Graph) restoreDeleted(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	it, err := g.Store.RestoreDeletedItem(r.PathValue("id"))
	if err != nil {
		writeStoreErrGraph(w, err)
		return
	}
	// Restore returns the now-live object (without deletedDateTime).
	shape, err := g.deletedShape(it)
	if err != nil {
		httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	delete(shape, "deletedDateTime")
	shape["@odata.context"] = g.contextURL("directoryObjects/$entity")
	httpx.WriteJSON(w, http.StatusOK, shape)
}

func (g *Graph) purgeDeleted(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	if err := g.Store.PurgeDeletedItem(r.PathValue("id")); err != nil {
		writeStoreErrGraph(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
