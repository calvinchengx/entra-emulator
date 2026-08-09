package graph

import (
	"net/http"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// federatedIdentityCredentials on an application — the Graph route for the
// workload-identity-federation trusts the token endpoint already honours.
// Creating one here is not bookkeeping: the credential it writes is the same
// row the token endpoint matches against, so a trust registered over Graph
// immediately lets an external workload exchange its own OIDC token.
//
// Applications are addressed by the emulator's conflated object id / appId
// (the documented divergence that applies to every /applications route).

func (g *Graph) registerFederatedCredentials(mux *http.ServeMux, prefix string) {
	p := prefix + "/v1.0/applications/{id}/federatedIdentityCredentials"
	mux.HandleFunc("GET "+p, g.requireBearer(g.listFederatedCreds))
	mux.HandleFunc("POST "+p, g.requireBearer(g.createFederatedCred))
	mux.HandleFunc("GET "+p+"/{ficId}", g.requireBearer(g.getFederatedCred))
	mux.HandleFunc("PATCH "+p+"/{ficId}", g.requireBearer(g.patchFederatedCred))
	mux.HandleFunc("DELETE "+p+"/{ficId}", g.requireBearer(g.deleteFederatedCred))
}

func federatedCredShape(c *store.FederatedCredential) map[string]any {
	return map[string]any{
		"@odata.type": "#microsoft.graph.federatedIdentityCredential",
		"id":          c.ID,
		"name":        c.Name,
		"issuer":      c.Issuer,
		"subject":     c.Subject,
		"audiences":   c.Audiences,
		"description": nullable(c.Description),
	}
}

type federatedCredBody struct {
	Name        string   `json:"name"`
	Issuer      string   `json:"issuer"`
	Subject     string   `json:"subject"`
	Audiences   []string `json:"audiences"`
	Description string   `json:"description"`
}

// appForFIC resolves the application, 404-ing consistently for both a missing
// app and a missing credential under it.
func (g *Graph) appForFIC(w http.ResponseWriter, r *http.Request) (string, bool) {
	appID := r.PathValue("id")
	if _, err := g.Store.GetApp(appID); err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound", "Application does not exist.")
		return "", false
	}
	return appID, true
}

func (g *Graph) listFederatedCreds(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	appID, ok := g.appForFIC(w, r)
	if !ok {
		return
	}
	creds, err := g.Store.ListFederatedCredentials(appID)
	if err != nil {
		httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	shapes := make([]map[string]any, 0, len(creds))
	for _, c := range creds {
		shapes = append(shapes, federatedCredShape(c))
	}
	g.writeSimpleCollection(w, "applications('"+appID+"')/federatedIdentityCredentials", shapes)
}

func (g *Graph) createFederatedCred(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	appID, ok := g.appForFIC(w, r)
	if !ok {
		return
	}
	var b federatedCredBody
	if !decodeGraph(w, r, &b) {
		return
	}
	if b.Name == "" || b.Issuer == "" || b.Subject == "" {
		httpx.WriteGraphError(w, http.StatusBadRequest, "Request_BadRequest",
			"name, issuer and subject are required.")
		return
	}
	c := &store.FederatedCredential{
		ID: store.NewGUID(), AppID: appID, Name: b.Name, Issuer: b.Issuer,
		Subject: b.Subject, Audiences: b.Audiences, Description: b.Description,
		CreatedAt: g.Store.Now(),
	}
	if err := g.Store.CreateFederatedCredential(c); err != nil {
		httpx.WriteGraphError(w, http.StatusConflict, "Request_BadRequest",
			"A federated identity credential with that name already exists on this application.")
		return
	}
	shape := federatedCredShape(c)
	shape["@odata.context"] = g.contextURL("applications('" + appID + "')/federatedIdentityCredentials/$entity")
	httpx.WriteJSON(w, http.StatusCreated, shape)
}

func (g *Graph) getFederatedCred(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	appID, ok := g.appForFIC(w, r)
	if !ok {
		return
	}
	c, err := g.Store.GetFederatedCredential(appID, r.PathValue("ficId"))
	if err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound",
			"Federated identity credential does not exist.")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, federatedCredShape(c))
}

func (g *Graph) patchFederatedCred(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	appID, ok := g.appForFIC(w, r)
	if !ok {
		return
	}
	c, err := g.Store.GetFederatedCredential(appID, r.PathValue("ficId"))
	if err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound",
			"Federated identity credential does not exist.")
		return
	}
	var b federatedCredBody
	if !decodeGraph(w, r, &b) {
		return
	}
	if b.Issuer != "" {
		c.Issuer = b.Issuer
	}
	if b.Subject != "" {
		c.Subject = b.Subject
	}
	if b.Audiences != nil {
		c.Audiences = b.Audiences
	}
	if b.Description != "" {
		c.Description = b.Description
	}
	if err := g.Store.UpdateFederatedCredential(c); err != nil {
		httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (g *Graph) deleteFederatedCred(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	appID, ok := g.appForFIC(w, r)
	if !ok {
		return
	}
	if err := g.Store.DeleteFederatedCredential(appID, r.PathValue("ficId")); err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound",
			"Federated identity credential does not exist.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
