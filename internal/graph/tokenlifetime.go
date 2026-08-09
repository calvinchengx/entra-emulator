package graph

import (
	"net/http"
	"strings"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// Token lifetime policies: /policies/tokenLifetimePolicies, and the $ref
// assignment onto an application. These are load-bearing, not catalogue
// entries — an assigned policy changes the `exp` of the tokens the emulator
// actually mints (see Service.lifetimesFor).

func (g *Graph) registerTokenLifetimePolicies(mux *http.ServeMux, prefix string) {
	p := prefix + "/v1.0/policies/tokenLifetimePolicies"
	mux.HandleFunc("GET "+p, g.requireBearer(g.listTLPs))
	mux.HandleFunc("POST "+p, g.requireBearer(g.createTLP))
	mux.HandleFunc("GET "+p+"/{id}", g.requireBearer(g.getTLP))
	mux.HandleFunc("DELETE "+p+"/{id}", g.requireBearer(g.deleteTLP))

	a := prefix + "/v1.0/applications/{id}/tokenLifetimePolicies"
	mux.HandleFunc("GET "+a, g.requireBearer(g.listAppTLPs))
	mux.HandleFunc("POST "+a+"/$ref", g.requireBearer(g.assignTLP))
	mux.HandleFunc("DELETE "+a+"/{policyId}/$ref", g.requireBearer(g.unassignTLP))
}

func tlpShape(p *store.TokenLifetimePolicy) map[string]any {
	return map[string]any{
		"@odata.type":           "#microsoft.graph.tokenLifetimePolicy",
		"id":                    p.ID,
		"displayName":           p.DisplayName,
		"definition":            p.Definition,
		"isOrganizationDefault": p.IsOrganizationDefault,
	}
}

func (g *Graph) listTLPs(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	policies, err := g.Store.ListTokenLifetimePolicies()
	if err != nil {
		httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	shapes := make([]map[string]any, 0, len(policies))
	for _, p := range policies {
		shapes = append(shapes, tlpShape(p))
	}
	g.writeSimpleCollection(w, "policies/tokenLifetimePolicies", shapes)
}

func (g *Graph) createTLP(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	var b struct {
		DisplayName           string   `json:"displayName"`
		Definition            []string `json:"definition"`
		IsOrganizationDefault bool     `json:"isOrganizationDefault"`
	}
	if !decodeGraph(w, r, &b) {
		return
	}
	if b.DisplayName == "" || len(b.Definition) == 0 {
		httpx.WriteGraphError(w, http.StatusBadRequest, "Request_BadRequest",
			"displayName and definition are required.")
		return
	}
	p := &store.TokenLifetimePolicy{
		ID: store.NewGUID(), DisplayName: b.DisplayName, Definition: b.Definition,
		IsOrganizationDefault: b.IsOrganizationDefault, CreatedAt: g.Store.Now(),
	}
	// A definition that parses to nothing would be silently inert, which is
	// worse than a rejection: the caller would believe a lifetime was applied.
	if lt := store.EffectiveFromPolicy(p); lt.AccessToken == 0 && lt.IDToken == 0 && lt.RefreshToken == 0 {
		httpx.WriteGraphError(w, http.StatusBadRequest, "Request_BadRequest",
			"definition sets no recognised lifetime; expected a TokenLifetimePolicy with a [d.]hh:mm:ss duration.")
		return
	}
	if err := g.Store.CreateTokenLifetimePolicy(p); err != nil {
		httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, tlpShape(p))
}

func (g *Graph) getTLP(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	p, err := g.Store.GetTokenLifetimePolicy(r.PathValue("id"))
	if err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound", "Policy does not exist.")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, tlpShape(p))
}

func (g *Graph) deleteTLP(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	if err := g.Store.DeleteTokenLifetimePolicy(r.PathValue("id")); err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound", "Policy does not exist.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (g *Graph) listAppTLPs(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	appID := r.PathValue("id")
	if _, err := g.Store.GetApp(appID); err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound", "Application does not exist.")
		return
	}
	policies, err := g.Store.AppTokenLifetimePolicies(appID)
	if err != nil {
		httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	shapes := make([]map[string]any, 0, len(policies))
	for _, p := range policies {
		shapes = append(shapes, tlpShape(p))
	}
	g.writeSimpleCollection(w, "applications('"+appID+"')/tokenLifetimePolicies", shapes)
}

func (g *Graph) assignTLP(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	appID := r.PathValue("id")
	if _, err := g.Store.GetApp(appID); err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound", "Application does not exist.")
		return
	}
	var b struct {
		ODataID string `json:"@odata.id"`
	}
	if !decodeGraph(w, r, &b) {
		return
	}
	policyID := b.ODataID
	if i := strings.LastIndex(policyID, "/"); i >= 0 {
		policyID = policyID[i+1:]
	}
	if err := g.Store.AssignTokenLifetimePolicy(appID, policyID); err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound", "Policy does not exist.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (g *Graph) unassignTLP(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	if err := g.Store.UnassignTokenLifetimePolicy(r.PathValue("id"), r.PathValue("policyId")); err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound", "Assignment does not exist.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
