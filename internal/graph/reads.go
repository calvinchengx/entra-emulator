package graph

import (
	"net/http"
	"strings"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// splitCSV splits a comma-separated list into trimmed, non-empty parts.
func splitCSV(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Applications & service-principals read surface (roadmap #19). The emulator
// has no separate service-principal table — each app registration is its own
// SP, and the object id is conflated with appId (documented divergence). Both
// resources honour the basic OData options from odata.go.

func (g *Graph) registerReads(mux *http.ServeMux, prefix string) {
	mux.HandleFunc("GET "+prefix+"/v1.0/applications", g.requireBearer(g.listApplications))
	mux.HandleFunc("GET "+prefix+"/v1.0/applications/{id}", g.requireBearer(g.getApplication))
	mux.HandleFunc("GET "+prefix+"/v1.0/servicePrincipals", g.requireBearer(g.listServicePrincipals))
	mux.HandleFunc("GET "+prefix+"/v1.0/servicePrincipals/{id}", g.requireBearer(g.getServicePrincipal))
}

// oauth2ScopeShapes renders an app's exposed delegated scopes.
func (g *Graph) oauth2ScopeShapes(appID string) []map[string]any {
	scopes, _ := g.Store.ListScopes(appID)
	out := make([]map[string]any, 0, len(scopes))
	for _, sc := range scopes {
		out = append(out, map[string]any{
			"id":                      sc.ID,
			"value":                   sc.Value,
			"adminConsentDisplayName": nullable(sc.AdminConsentDisplayName),
			"isEnabled":               sc.IsEnabled,
			"type":                    "User",
		})
	}
	return out
}

// appRoleShapes renders an app's application roles.
func (g *Graph) appRoleShapes(appID string) []map[string]any {
	roles, _ := g.Store.ListRoles(appID)
	out := make([]map[string]any, 0, len(roles))
	for _, ro := range roles {
		out = append(out, map[string]any{
			"id":                 ro.ID,
			"value":              ro.Value,
			"displayName":        nullable(ro.DisplayName),
			"allowedMemberTypes": splitCSV(ro.AllowedMemberTypes),
			"isEnabled":          ro.IsEnabled,
		})
	}
	return out
}

// applicationDTO renders an application object. object id == appId.
func (g *Graph) applicationDTO(a *store.App) map[string]any {
	uris := []string{}
	if a.AppIDURI != "" {
		uris = []string{a.AppIDURI}
	}
	return map[string]any{
		"id":             a.ID,
		"appId":          a.ID,
		"displayName":    a.DisplayName,
		"signInAudience": "AzureADMyOrg",
		"identifierUris": uris,
		"appRoles":       g.appRoleShapes(a.ID),
		"api":            map[string]any{"oauth2PermissionScopes": g.oauth2ScopeShapes(a.ID)},
	}
}

// servicePrincipalDTO renders the SP view of an app registration.
func (g *Graph) servicePrincipalDTO(a *store.App) map[string]any {
	names := []string{a.ID}
	if a.AppIDURI != "" {
		names = append(names, a.AppIDURI)
	}
	return map[string]any{
		"id":                     a.ID,
		"appId":                  a.ID,
		"displayName":            a.DisplayName,
		"servicePrincipalType":   "Application",
		"accountEnabled":         true,
		"appRoles":               g.appRoleShapes(a.ID),
		"oauth2PermissionScopes": g.oauth2ScopeShapes(a.ID),
		"servicePrincipalNames":  names,
	}
}

func (g *Graph) listApplications(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	q, err := parseOData(r)
	if err != nil {
		httpx.WriteGraphError(w, http.StatusBadRequest, "BadRequest", err.Error())
		return
	}
	apps, _, err := g.Store.ListApps(allRows, 0, "")
	if err != nil {
		httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	shapes := make([]map[string]any, 0, len(apps))
	for _, a := range apps {
		shapes = append(shapes, g.applicationDTO(a))
	}
	g.writeCollection(w, r, "applications", shapes, q)
}

func (g *Graph) getApplication(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	a, err := g.Store.GetApp(r.PathValue("id"))
	if err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound", "Application does not exist.")
		return
	}
	shape := g.selectEntity(r, g.applicationDTO(a))
	shape["@odata.context"] = g.contextURL("applications/$entity")
	httpx.WriteJSON(w, http.StatusOK, shape)
}

func (g *Graph) listServicePrincipals(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	q, err := parseOData(r)
	if err != nil {
		httpx.WriteGraphError(w, http.StatusBadRequest, "BadRequest", err.Error())
		return
	}
	apps, _, err := g.Store.ListApps(allRows, 0, "")
	if err != nil {
		httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	shapes := make([]map[string]any, 0, len(apps))
	for _, a := range apps {
		shapes = append(shapes, g.servicePrincipalDTO(a))
	}
	g.writeCollection(w, r, "servicePrincipals", shapes, q)
}

func (g *Graph) getServicePrincipal(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	a, err := g.Store.GetApp(r.PathValue("id"))
	if err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound", "Service principal does not exist.")
		return
	}
	shape := g.selectEntity(r, g.servicePrincipalDTO(a))
	shape["@odata.context"] = g.contextURL("servicePrincipals/$entity")
	httpx.WriteJSON(w, http.StatusOK, shape)
}
