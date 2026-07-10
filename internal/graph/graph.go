// Package graph implements the minimal read-only Microsoft Graph surface
// plus OIDC UserInfo (docs/06-graph-api.md).
package graph

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/calvinchengx/entra-emulator/internal/config"
	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

type Graph struct {
	Cfg    *config.Config
	Store  *store.Store
	Tokens *tokens.Service
}

func New(cfg *config.Config, st *store.Store, ts *tokens.Service) *Graph {
	return &Graph{Cfg: cfg, Store: st, Tokens: ts}
}

// Register mounts the Graph routes under prefix ("" on the graph host,
// "/graph" on the compat origin).
func (g *Graph) Register(mux *http.ServeMux, prefix string) {
	mux.HandleFunc("GET "+prefix+"/v1.0/me", g.requireDelegated(g.handleMe))
	mux.HandleFunc("GET "+prefix+"/v1.0/users", g.requireBearer(g.handleUsers))
	mux.HandleFunc("GET "+prefix+"/v1.0/users/{id}", g.requireBearer(g.handleUserByID))
	mux.HandleFunc("GET "+prefix+"/v1.0/groups", g.requireBearer(g.handleGroups))
	mux.HandleFunc("GET "+prefix+"/v1.0/groups/{id}", g.requireBearer(g.handleGroupByID))
	mux.HandleFunc("GET "+prefix+"/v1.0/groups/{id}/members", g.requireBearer(g.handleGroupMembers))
	mux.HandleFunc("GET "+prefix+"/oidc/userinfo", g.requireDelegatedUserInfo(g.handleUserInfo))
	mux.HandleFunc("POST "+prefix+"/oidc/userinfo", g.requireDelegatedUserInfo(g.handleUserInfo))
}

type handler func(w http.ResponseWriter, r *http.Request, tok *tokens.ValidatedToken)

func (g *Graph) validate(r *http.Request) (*tokens.ValidatedToken, string) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return nil, "Access token is empty or invalid."
	}
	tok, err := g.Tokens.ValidateAccessToken(strings.TrimPrefix(auth, "Bearer "),
		[]string{g.Cfg.GraphResourceID})
	if err != nil {
		return nil, "Access token validation failure: " + err.Error()
	}
	return tok, ""
}

func (g *Graph) requireBearer(next handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, msg := g.validate(r)
		if tok == nil {
			httpx.WriteGraphError(w, http.StatusUnauthorized, "InvalidAuthenticationToken", msg)
			return
		}
		next(w, r, tok)
	}
}

func (g *Graph) requireDelegated(next handler) http.HandlerFunc {
	return g.requireBearer(func(w http.ResponseWriter, r *http.Request, tok *tokens.ValidatedToken) {
		if tok.OID == "" {
			httpx.WriteGraphError(w, http.StatusForbidden, "Authorization_RequestDenied",
				"An app-only token cannot access /me.")
			return
		}
		next(w, r, tok)
	})
}

// requireDelegatedUserInfo mirrors RFC 6750 shapes for userinfo (401/403
// with error/insufficient_scope bodies rather than Graph codes).
func (g *Graph) requireDelegatedUserInfo(next handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, msg := g.validate(r)
		if tok == nil {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="`+msg+`"`)
			httpx.WriteJSON(w, http.StatusUnauthorized,
				map[string]string{"error": "invalid_token", "error_description": msg})
			return
		}
		if tok.OID == "" {
			w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope"`)
			httpx.WriteJSON(w, http.StatusForbidden,
				map[string]string{"error": "insufficient_scope", "error_description": "UserInfo requires a user (delegated) token."})
			return
		}
		next(w, r, tok)
	}
}

// ---- Shapes ----

func (g *Graph) contextURL(suffix string) string {
	base := g.Cfg.Origins.Graph
	if g.Cfg.Origins.Graph == g.Cfg.Origins.Login { // compat collapse
		base += "/graph"
	}
	return base + "/v1.0/$metadata#" + suffix
}

func userShape(u *store.User) map[string]any {
	return map[string]any{
		"id":                u.ID,
		"displayName":       u.DisplayName,
		"userPrincipalName": u.UserPrincipalName,
		"mail":              nullable(u.Mail),
		"givenName":         nullable(u.GivenName),
		"surname":           nullable(u.Surname),
		"accountEnabled":    u.AccountEnabled,
	}
}

func groupShape(gr *store.Group) map[string]any {
	return map[string]any{
		"id":              gr.ID,
		"displayName":     gr.DisplayName,
		"description":     nullable(gr.Description),
		"mailEnabled":     false,
		"securityEnabled": true,
	}
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// paging parses $top/$skiptoken with Graph defaults.
func paging(r *http.Request) (top, skip int) {
	top = 100
	if v, err := strconv.Atoi(r.URL.Query().Get("$top")); err == nil && v > 0 {
		if v > 999 {
			v = 999
		}
		top = v
	}
	if v, err := strconv.Atoi(r.URL.Query().Get("$skiptoken")); err == nil && v > 0 {
		skip = v
	}
	return top, skip
}

// nextLink rebuilds the caller's URL with an advanced $skiptoken.
func (g *Graph) nextLink(r *http.Request, nextSkip int) string {
	q := r.URL.Query()
	q.Set("$skiptoken", strconv.Itoa(nextSkip))
	base := g.Cfg.Origins.Graph
	path := r.URL.Path
	if g.Cfg.Origins.Graph == g.Cfg.Origins.Login && !strings.HasPrefix(path, "/graph/") {
		path = "/graph" + path
	}
	return base + path + "?" + q.Encode()
}

// ---- Handlers ----

func (g *Graph) handleMe(w http.ResponseWriter, r *http.Request, tok *tokens.ValidatedToken) {
	u, err := g.Store.GetUser(tok.OID)
	if err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound", "The signed-in user no longer exists.")
		return
	}
	shape := userShape(u)
	shape["@odata.context"] = g.contextURL("users/$entity")
	httpx.WriteJSON(w, http.StatusOK, shape)
}

func (g *Graph) handleUsers(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	top, skip := paging(r)
	users, count, err := g.Store.ListUsers(top, skip, "")
	if err != nil {
		httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	value := make([]map[string]any, 0, len(users))
	for _, u := range users {
		value = append(value, userShape(u))
	}
	resp := map[string]any{"@odata.context": g.contextURL("users"), "value": value}
	if skip+len(users) < count {
		resp["@odata.nextLink"] = g.nextLink(r, skip+len(users))
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (g *Graph) handleUserByID(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	id := r.PathValue("id")
	u, err := g.Store.GetUser(id)
	if err != nil {
		u, err = g.Store.GetUserByUPN(id) // Graph accepts GUID or UPN
	}
	if err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound", "Resource '"+id+"' does not exist.")
		return
	}
	shape := userShape(u)
	shape["@odata.context"] = g.contextURL("users/$entity")
	httpx.WriteJSON(w, http.StatusOK, shape)
}

func (g *Graph) handleGroups(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	top, skip := paging(r)
	groups, count, err := g.Store.ListGroups(top, skip, "")
	if err != nil {
		httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	value := make([]map[string]any, 0, len(groups))
	for _, gr := range groups {
		value = append(value, groupShape(gr))
	}
	resp := map[string]any{"@odata.context": g.contextURL("groups"), "value": value}
	if skip+len(groups) < count {
		resp["@odata.nextLink"] = g.nextLink(r, skip+len(groups))
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (g *Graph) handleGroupByID(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	gr, err := g.Store.GetGroup(r.PathValue("id"))
	if err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound", "Group does not exist.")
		return
	}
	shape := groupShape(gr)
	shape["@odata.context"] = g.contextURL("groups/$entity")
	httpx.WriteJSON(w, http.StatusOK, shape)
}

func (g *Graph) handleGroupMembers(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	groupID := r.PathValue("id")
	if _, err := g.Store.GetGroup(groupID); err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound", "Group does not exist.")
		return
	}
	members, err := g.Store.ListGroupMembers(groupID)
	if err != nil {
		httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	value := make([]map[string]any, 0, len(members))
	for _, u := range members {
		value = append(value, userShape(u))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"@odata.context": g.contextURL("directoryObjects"), "value": value,
	})
}

func (g *Graph) handleUserInfo(w http.ResponseWriter, r *http.Request, tok *tokens.ValidatedToken) {
	u, err := g.Store.GetUser(tok.OID)
	if err != nil || !u.AccountEnabled {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		httpx.WriteJSON(w, http.StatusUnauthorized,
			map[string]string{"error": "invalid_token", "error_description": "The token's user no longer exists."})
		return
	}
	claims := map[string]any{
		"sub": tok.Sub, "oid": u.ID, "tid": g.Cfg.TenantID,
		"name": u.DisplayName, "preferred_username": u.UserPrincipalName,
	}
	if u.GivenName != "" {
		claims["given_name"] = u.GivenName
	}
	if u.Surname != "" {
		claims["family_name"] = u.Surname
	}
	if u.Mail != "" {
		claims["email"] = u.Mail
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, http.StatusOK, claims)
}
