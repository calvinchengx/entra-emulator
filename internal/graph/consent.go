package graph

import (
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// Consent grants (docs/19-stateful-directory.md): oauth2PermissionGrants
// (delegated) and appRoleAssignedTo/appRoleAssignments (application) on service
// principals. Because an app registration is its own service principal here,
// {id}, clientId, resourceId, and SP principalId are app ids.

func (g *Graph) registerConsent(mux *http.ServeMux, prefix string) {
	// oauth2PermissionGrants (register both Entra casings).
	for _, coll := range []string{"/oauth2PermissionGrants", "/oAuth2PermissionGrants"} {
		mux.HandleFunc("POST "+prefix+"/v1.0"+coll, g.requireBearer(g.createOAuth2Grant))
		mux.HandleFunc("GET "+prefix+"/v1.0"+coll, g.requireBearer(g.listOAuth2Grants))
		mux.HandleFunc("DELETE "+prefix+"/v1.0"+coll+"/{id}", g.requireBearer(g.deleteOAuth2Grant))
	}
	mux.HandleFunc("GET "+prefix+"/v1.0/servicePrincipals/{id}/oauth2PermissionGrants",
		g.requireBearer(g.listSPOAuth2Grants))

	// appRoleAssignments on service principals.
	mux.HandleFunc("POST "+prefix+"/v1.0/servicePrincipals/{id}/appRoleAssignedTo",
		g.requireBearer(g.createAppRoleAssignment))
	mux.HandleFunc("GET "+prefix+"/v1.0/servicePrincipals/{id}/appRoleAssignedTo",
		g.requireBearer(g.listAppRoleAssignedTo))
	mux.HandleFunc("GET "+prefix+"/v1.0/servicePrincipals/{id}/appRoleAssignments",
		g.requireBearer(g.listAppRoleAssignments))
	mux.HandleFunc("DELETE "+prefix+"/v1.0/servicePrincipals/{id}/appRoleAssignedTo/{assignmentId}",
		g.requireBearer(g.deleteAppRoleAssignment))
}

// ---- oauth2PermissionGrants ----

func (g *Graph) o2pgShape(gr *store.OAuth2PermissionGrant) map[string]any {
	return map[string]any{
		"id":          gr.ID,
		"clientId":    gr.ClientID,
		"consentType": gr.ConsentType,
		"resourceId":  gr.ResourceID,
		"principalId": nullable(gr.PrincipalID),
		"scope":       gr.Scope,
	}
}

func (g *Graph) createOAuth2Grant(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	var b struct {
		ClientID    string `json:"clientId"`
		ConsentType string `json:"consentType"`
		ResourceID  string `json:"resourceId"`
		PrincipalID string `json:"principalId"`
		Scope       string `json:"scope"`
	}
	if !decodeGraph(w, r, &b) {
		return
	}
	if b.ClientID == "" || b.ResourceID == "" || b.Scope == "" {
		httpx.WriteGraphError(w, http.StatusBadRequest, "Request_BadRequest",
			"clientId, resourceId, and scope are required.")
		return
	}
	if b.ConsentType == "" {
		b.ConsentType = "AllPrincipals"
	}
	if b.ConsentType == "Principal" && b.PrincipalID == "" {
		httpx.WriteGraphError(w, http.StatusBadRequest, "Request_BadRequest",
			"principalId is required when consentType is Principal.")
		return
	}
	grant := &store.OAuth2PermissionGrant{
		ID: store.NewGUID(), ClientID: b.ClientID, ConsentType: b.ConsentType,
		ResourceID: b.ResourceID, PrincipalID: b.PrincipalID, Scope: strings.TrimSpace(b.Scope),
		CreatedAt: g.Store.Now(),
	}
	if err := g.Store.CreateOAuth2Grant(grant); err != nil {
		writeStoreErrGraph(w, err)
		return
	}
	shape := g.o2pgShape(grant)
	shape["@odata.context"] = g.contextURL("oauth2PermissionGrants/$entity")
	httpx.WriteJSON(w, http.StatusCreated, shape)
}

// grantFilterField matches a single `field eq 'value'` clause anywhere in a
// $filter (compound `and` clauses are supported by scanning each field).
func grantFilterField(raw, field string) (string, bool) {
	re := regexp.MustCompile(field + `\s+eq\s+'([^']*)'`)
	if m := re.FindStringSubmatch(raw); m != nil {
		return m[1], true
	}
	return "", false
}

func (g *Graph) listOAuth2Grants(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	grants, err := g.Store.ListOAuth2Grants()
	if err != nil {
		httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	raw := r.URL.Query().Get("$filter")
	wantClient, hasClient := grantFilterField(raw, "clientId")
	wantConsent, hasConsent := grantFilterField(raw, "consentType")
	wantResource, hasResource := grantFilterField(raw, "resourceId")
	shapes := make([]map[string]any, 0, len(grants))
	for _, gr := range grants {
		if hasClient && gr.ClientID != wantClient {
			continue
		}
		if hasConsent && gr.ConsentType != wantConsent {
			continue
		}
		if hasResource && gr.ResourceID != wantResource {
			continue
		}
		shapes = append(shapes, g.o2pgShape(gr))
	}
	g.writeSimpleCollection(w, "oauth2PermissionGrants", shapes)
}

func (g *Graph) listSPOAuth2Grants(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	spID := r.PathValue("id")
	grants, err := g.Store.ListOAuth2Grants()
	if err != nil {
		httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	shapes := make([]map[string]any, 0)
	for _, gr := range grants {
		if gr.ClientID == spID {
			shapes = append(shapes, g.o2pgShape(gr))
		}
	}
	g.writeSimpleCollection(w, "oauth2PermissionGrants", shapes)
}

func (g *Graph) deleteOAuth2Grant(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	if err := g.Store.DeleteOAuth2Grant(r.PathValue("id")); err != nil {
		writeStoreErrGraph(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- appRoleAssignments ----

func (g *Graph) araShape(a *store.AppRoleAssignment) map[string]any {
	shape := map[string]any{
		"id":              a.ID,
		"principalId":     a.PrincipalID,
		"principalType":   a.PrincipalType,
		"resourceId":      a.ResourceID,
		"appRoleId":       a.AppRoleID,
		"createdDateTime": time.Unix(a.CreatedAt, 0).UTC().Format(time.RFC3339),
	}
	if app, err := g.Store.GetApp(a.ResourceID); err == nil {
		shape["resourceDisplayName"] = app.DisplayName
	}
	if a.PrincipalType == "User" {
		if u, err := g.Store.GetUser(a.PrincipalID); err == nil {
			shape["principalDisplayName"] = u.DisplayName
		}
	} else if app, err := g.Store.GetApp(a.PrincipalID); err == nil {
		shape["principalDisplayName"] = app.DisplayName
	}
	return shape
}

func (g *Graph) createAppRoleAssignment(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	resourceID := r.PathValue("id")
	var b struct {
		PrincipalID   string `json:"principalId"`
		PrincipalType string `json:"principalType"`
		ResourceID    string `json:"resourceId"`
		AppRoleID     string `json:"appRoleId"`
	}
	if !decodeGraph(w, r, &b) {
		return
	}
	if b.PrincipalID == "" {
		httpx.WriteGraphError(w, http.StatusBadRequest, "Request_BadRequest", "principalId is required.")
		return
	}
	if b.ResourceID == "" {
		b.ResourceID = resourceID
	}
	if b.AppRoleID == "" {
		b.AppRoleID = store.ZeroGUID
	}
	principalType := b.PrincipalType
	if principalType == "" {
		// Infer: a known user id → User, otherwise a service principal.
		if _, err := g.Store.GetUser(b.PrincipalID); err == nil {
			principalType = "User"
		} else {
			principalType = "ServicePrincipal"
		}
	}
	a := &store.AppRoleAssignment{
		ID: store.NewGUID(), PrincipalID: b.PrincipalID, PrincipalType: principalType,
		ResourceID: b.ResourceID, AppRoleID: b.AppRoleID, CreatedAt: g.Store.Now(),
	}
	if err := g.Store.CreateAppRoleAssignment(a); err != nil {
		writeStoreErrGraph(w, err)
		return
	}
	shape := g.araShape(a)
	shape["@odata.context"] = g.contextURL("servicePrincipals('" + resourceID + "')/appRoleAssignedTo/$entity")
	httpx.WriteJSON(w, http.StatusCreated, shape)
}

func (g *Graph) listAppRoleAssignedTo(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	list, err := g.Store.ListAppRoleAssignmentsToResource(r.PathValue("id"))
	if err != nil {
		httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	g.writeARACollection(w, r.PathValue("id"), "appRoleAssignedTo", list)
}

func (g *Graph) listAppRoleAssignments(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	list, err := g.Store.ListAppRoleAssignmentsForPrincipal(r.PathValue("id"))
	if err != nil {
		httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	g.writeARACollection(w, r.PathValue("id"), "appRoleAssignments", list)
}

func (g *Graph) deleteAppRoleAssignment(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	if err := g.Store.DeleteAppRoleAssignment(r.PathValue("assignmentId")); err != nil {
		writeStoreErrGraph(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (g *Graph) writeARACollection(w http.ResponseWriter, spID, rel string, list []*store.AppRoleAssignment) {
	shapes := make([]map[string]any, 0, len(list))
	for _, a := range list {
		shapes = append(shapes, g.araShape(a))
	}
	g.writeSimpleCollection(w, "servicePrincipals('"+spID+"')/"+rel, shapes)
}

// writeSimpleCollection writes an OData collection envelope without paging —
// used by the consent/role resources, which are small at emulator scale.
func (g *Graph) writeSimpleCollection(w http.ResponseWriter, contextSuffix string, shapes []map[string]any) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"@odata.context": g.contextURL(contextSuffix),
		"value":          shapes,
	})
}
