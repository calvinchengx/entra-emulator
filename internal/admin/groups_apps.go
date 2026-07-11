package admin

import (
	"encoding/json"
	"net/http"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/store"
)

// ---- groups ----

func (a *Admin) groupDTO(g *store.Group) map[string]any {
	count, _ := a.Store.CountGroupMembers(g.ID)
	return map[string]any{
		"id": g.ID, "displayName": g.DisplayName, "description": nullable(g.Description),
		"memberCount": count, "createdAt": iso(g.CreatedAt),
	}
}

func (a *Admin) listGroups(w http.ResponseWriter, r *http.Request) {
	top, skip, search := pageParams(r)
	groups, count, err := a.Store.ListGroups(top, skip, search)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	dtos := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		dtos = append(dtos, a.groupDTO(g))
	}
	paged(w, dtos, count, top, skip)
}

type groupBody struct {
	DisplayName *string `json:"displayName"`
	Description *string `json:"description"`
}

func (a *Admin) createGroup(w http.ResponseWriter, r *http.Request) {
	var b groupBody
	if !decodeBody(w, r, &b) {
		return
	}
	if b.DisplayName == nil || *b.DisplayName == "" {
		httpx.WriteAdminError(w, http.StatusBadRequest, "validation_error", "Invalid group.",
			httpx.AdminDetail{Field: "displayName", Message: "Required."})
		return
	}
	g := &store.Group{ID: store.NewGUID(), TenantID: a.Cfg.TenantID,
		DisplayName: *b.DisplayName, CreatedAt: a.Store.Now()}
	if b.Description != nil {
		g.Description = *b.Description
	}
	if err := a.Store.CreateGroup(g); err != nil {
		writeStoreErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, a.groupDTO(g))
}

func (a *Admin) getGroup(w http.ResponseWriter, r *http.Request) {
	g, err := a.Store.GetGroup(r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, a.groupDTO(g))
}

func (a *Admin) patchGroup(w http.ResponseWriter, r *http.Request) {
	g, err := a.Store.GetGroup(r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	var b groupBody
	if !decodeBody(w, r, &b) {
		return
	}
	if b.DisplayName != nil {
		g.DisplayName = *b.DisplayName
	}
	if b.Description != nil {
		g.Description = *b.Description
	}
	if err := a.Store.UpdateGroup(g); err != nil {
		writeStoreErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, a.groupDTO(g))
}

func (a *Admin) deleteGroup(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.DeleteGroup(r.PathValue("id")); err != nil {
		writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *Admin) listMembers(w http.ResponseWriter, r *http.Request) {
	if _, err := a.Store.GetGroup(r.PathValue("id")); err != nil {
		writeStoreErr(w, err)
		return
	}
	members, err := a.Store.ListGroupMembers(r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	dtos := make([]map[string]any, 0, len(members))
	for _, u := range members {
		dtos = append(dtos, userDTO(u))
	}
	paged(w, dtos, len(dtos), len(dtos), 0)
}

func (a *Admin) addMember(w http.ResponseWriter, r *http.Request) {
	var b struct {
		UserID string `json:"userId"`
	}
	if !decodeBody(w, r, &b) {
		return
	}
	if _, err := a.Store.GetGroup(r.PathValue("id")); err != nil {
		writeStoreErr(w, err)
		return
	}
	if _, err := a.Store.GetUser(b.UserID); err != nil {
		httpx.WriteAdminError(w, http.StatusBadRequest, "invalid_reference", "The user does not exist.")
		return
	}
	if err := a.Store.AddGroupMember(r.PathValue("id"), b.UserID); err != nil {
		writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *Admin) removeMember(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.RemoveGroupMember(r.PathValue("id"), r.PathValue("userId")); err != nil {
		writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- apps ----

func (a *Admin) appDTO(app *store.App) map[string]any {
	redirects, _ := a.Store.ListRedirectURIs(app.ID)
	scopes, _ := a.Store.ListScopes(app.ID)
	roles, _ := a.Store.ListRoles(app.ID)
	secrets, _ := a.Store.ListSecrets(app.ID)

	redirectDTOs := make([]map[string]any, 0, len(redirects))
	for _, u := range redirects {
		redirectDTOs = append(redirectDTOs, map[string]any{"id": u.ID, "uri": u.URI, "type": u.Type})
	}
	scopeDTOs := make([]map[string]any, 0, len(scopes))
	for _, sc := range scopes {
		scopeDTOs = append(scopeDTOs, map[string]any{
			"id": sc.ID, "value": sc.Value,
			"adminConsentDisplayName": nullable(sc.AdminConsentDisplayName), "isEnabled": sc.IsEnabled,
		})
	}
	roleDTOs := make([]map[string]any, 0, len(roles))
	for _, role := range roles {
		roleDTOs = append(roleDTOs, map[string]any{
			"id": role.ID, "value": role.Value, "displayName": nullable(role.DisplayName),
			"allowedMemberTypes": splitCSV(role.AllowedMemberTypes), "isEnabled": role.IsEnabled,
		})
	}
	secretDTOs := make([]map[string]any, 0, len(secrets))
	for _, sec := range secrets {
		secretDTOs = append(secretDTOs, map[string]any{
			"id": sec.ID, "displayName": nullable(sec.DisplayName), "hint": nullable(sec.Hint),
			"expiresAt": iso(sec.ExpiresAt), "createdAt": iso(sec.CreatedAt),
		})
	}
	return map[string]any{
		"id": app.ID, "displayName": app.DisplayName, "isConfidential": app.IsConfidential,
		"appIdUri": nullable(app.AppIDURI), "redirectUris": redirectDTOs,
		"exposedScopes": scopeDTOs, "appRoles": roleDTOs, "secrets": secretDTOs,
		"groupMembershipClaims": app.GroupMembershipClaims,
		"createdAt":             iso(app.CreatedAt),
	}
}

func splitCSV(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func (a *Admin) listApps(w http.ResponseWriter, r *http.Request) {
	top, skip, search := pageParams(r)
	apps, count, err := a.Store.ListApps(top, skip, search)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	dtos := make([]map[string]any, 0, len(apps))
	for _, app := range apps {
		dtos = append(dtos, a.appDTO(app))
	}
	paged(w, dtos, count, top, skip)
}

type appBody struct {
	DisplayName           *string `json:"displayName"`
	TenantID              *string `json:"tenantId"` // multi-tenant (roadmap #15b); defaults to home
	IsConfidential        *bool   `json:"isConfidential"`
	AppIDURI              *string `json:"appIdUri"`
	GroupMembershipClaims *string `json:"groupMembershipClaims"`
	GroupOverageLimit     *int    `json:"groupOverageLimit"`
	OptionalClaims        any     `json:"optionalClaims"`
	RedirectUris          []struct {
		URI  string `json:"uri"`
		Type string `json:"type"`
	} `json:"redirectUris"`
}

func (a *Admin) createApp(w http.ResponseWriter, r *http.Request) {
	var b appBody
	if !decodeBody(w, r, &b) {
		return
	}
	if b.DisplayName == nil || *b.DisplayName == "" {
		httpx.WriteAdminError(w, http.StatusBadRequest, "validation_error", "Invalid app.",
			httpx.AdminDetail{Field: "displayName", Message: "Required."})
		return
	}
	tenantID := a.Cfg.TenantID
	if b.TenantID != nil && *b.TenantID != "" {
		if _, err := a.Store.GetTenantByID(*b.TenantID); err != nil {
			httpx.WriteAdminError(w, http.StatusBadRequest, "invalid_reference",
				"tenantId does not resolve to a tenant.")
			return
		}
		tenantID = *b.TenantID
	}
	app := &store.App{
		ID: store.NewGUID(), TenantID: tenantID, DisplayName: *b.DisplayName,
		GroupMembershipClaims: "None", CreatedAt: a.Store.Now(),
	}
	applyAppBody(app, &b)
	if err := a.Store.CreateApp(app); err != nil {
		writeStoreErr(w, err)
		return
	}
	for _, ru := range b.RedirectUris {
		if _, err := a.Store.AddRedirectURI(app.ID, ru.URI, ru.Type); err != nil {
			writeStoreErr(w, err)
			return
		}
	}
	httpx.WriteJSON(w, http.StatusCreated, a.appDTO(app))
}

func applyAppBody(app *store.App, b *appBody) {
	if b.DisplayName != nil {
		app.DisplayName = *b.DisplayName
	}
	if b.IsConfidential != nil {
		app.IsConfidential = *b.IsConfidential
	}
	if b.AppIDURI != nil {
		app.AppIDURI = *b.AppIDURI
	}
	if b.GroupMembershipClaims != nil {
		app.GroupMembershipClaims = *b.GroupMembershipClaims
	}
	if b.GroupOverageLimit != nil {
		app.GroupOverageLimit = *b.GroupOverageLimit
	}
	if b.OptionalClaims != nil {
		raw, err := json.Marshal(b.OptionalClaims)
		if err == nil {
			app.OptionalClaims = string(raw)
		}
	}
}

func (a *Admin) getApp(w http.ResponseWriter, r *http.Request) {
	app, err := a.Store.GetApp(r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, a.appDTO(app))
}

func (a *Admin) patchApp(w http.ResponseWriter, r *http.Request) {
	app, err := a.Store.GetApp(r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	var b appBody
	if !decodeBody(w, r, &b) {
		return
	}
	applyAppBody(app, &b)
	if err := a.Store.UpdateApp(app); err != nil {
		writeStoreErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, a.appDTO(app))
}

func (a *Admin) deleteApp(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.DeleteApp(r.PathValue("id")); err != nil {
		writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- app sub-resources ----

func (a *Admin) addRedirectURI(w http.ResponseWriter, r *http.Request) {
	if _, err := a.Store.GetApp(r.PathValue("id")); err != nil {
		writeStoreErr(w, err)
		return
	}
	var b struct {
		URI  string `json:"uri"`
		Type string `json:"type"`
	}
	if !decodeBody(w, r, &b) {
		return
	}
	if b.URI == "" {
		httpx.WriteAdminError(w, http.StatusBadRequest, "validation_error", "uri is required.",
			httpx.AdminDetail{Field: "uri", Message: "Required."})
		return
	}
	ru, err := a.Store.AddRedirectURI(r.PathValue("id"), b.URI, b.Type)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"id": ru.ID, "uri": ru.URI, "type": ru.Type})
}

func (a *Admin) deleteRedirectURI(w http.ResponseWriter, r *http.Request) {
	id, err := parseInt64(r.PathValue("uriId"))
	if err != nil {
		httpx.WriteAdminError(w, http.StatusBadRequest, "validation_error", "Invalid redirect URI id.")
		return
	}
	if err := a.Store.DeleteRedirectURI(r.PathValue("id"), id); err != nil {
		writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func parseInt64(s string) (int64, error) {
	var n int64
	err := json.Unmarshal([]byte(s), &n)
	return n, err
}

// addSecret implements the show-once contract: secretText appears only in
// this response; only the scrypt hash + hint persist.
func (a *Admin) addSecret(w http.ResponseWriter, r *http.Request) {
	if _, err := a.Store.GetApp(r.PathValue("id")); err != nil {
		writeStoreErr(w, err)
		return
	}
	body := struct {
		DisplayName   string `json:"displayName"`
		ExpiresInDays int    `json:"expiresInDays"`
	}{}
	if r.ContentLength > 0 && !decodeBody(w, r, &body) {
		return
	}
	plaintext := store.NewOpaqueToken(32)
	hash, err := store.HashSecret(plaintext)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	now := a.Store.Now()
	sec := &store.AppSecret{
		ID: store.NewGUID(), AppID: r.PathValue("id"), DisplayName: body.DisplayName,
		SecretHash: hash, Hint: plaintext[:3] + "…" + plaintext[len(plaintext)-2:], CreatedAt: now,
	}
	if body.ExpiresInDays > 0 {
		sec.ExpiresAt = now + int64(body.ExpiresInDays)*86400
	}
	if err := a.Store.AddSecret(sec); err != nil {
		writeStoreErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"id": sec.ID, "displayName": nullable(sec.DisplayName), "hint": sec.Hint,
		"secretText": plaintext, "expiresAt": iso(sec.ExpiresAt), "createdAt": iso(sec.CreatedAt),
	})
}

func (a *Admin) deleteSecret(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.DeleteSecret(r.PathValue("id"), r.PathValue("secretId")); err != nil {
		writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *Admin) addScope(w http.ResponseWriter, r *http.Request) {
	if _, err := a.Store.GetApp(r.PathValue("id")); err != nil {
		writeStoreErr(w, err)
		return
	}
	body := struct {
		Value                   string `json:"value"`
		AdminConsentDisplayName string `json:"adminConsentDisplayName"`
		IsEnabled               *bool  `json:"isEnabled"`
	}{}
	if !decodeBody(w, r, &body) {
		return
	}
	if body.Value == "" {
		httpx.WriteAdminError(w, http.StatusBadRequest, "validation_error", "value is required.",
			httpx.AdminDetail{Field: "value", Message: "Required."})
		return
	}
	sc := &store.AppScope{
		ID: store.NewGUID(), AppID: r.PathValue("id"), Value: body.Value,
		AdminConsentDisplayName: body.AdminConsentDisplayName,
		IsEnabled:               body.IsEnabled == nil || *body.IsEnabled,
	}
	if err := a.Store.AddScope(sc); err != nil {
		writeStoreErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"id": sc.ID, "value": sc.Value,
		"adminConsentDisplayName": nullable(sc.AdminConsentDisplayName), "isEnabled": sc.IsEnabled,
	})
}

func (a *Admin) patchScope(w http.ResponseWriter, r *http.Request) {
	scopes, err := a.Store.ListScopes(r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	var target *store.AppScope
	for _, sc := range scopes {
		if sc.ID == r.PathValue("scopeId") {
			target = sc
		}
	}
	if target == nil {
		httpx.WriteAdminError(w, http.StatusNotFound, "not_found", "Scope not found.")
		return
	}
	body := struct {
		AdminConsentDisplayName *string `json:"adminConsentDisplayName"`
		IsEnabled               *bool   `json:"isEnabled"`
	}{}
	if !decodeBody(w, r, &body) {
		return
	}
	if body.AdminConsentDisplayName != nil {
		target.AdminConsentDisplayName = *body.AdminConsentDisplayName
	}
	if body.IsEnabled != nil {
		target.IsEnabled = *body.IsEnabled
	}
	if err := a.Store.UpdateScope(target); err != nil {
		writeStoreErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"id": target.ID, "value": target.Value,
		"adminConsentDisplayName": nullable(target.AdminConsentDisplayName), "isEnabled": target.IsEnabled,
	})
}

func (a *Admin) deleteScope(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.DeleteScope(r.PathValue("id"), r.PathValue("scopeId")); err != nil {
		writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *Admin) addRole(w http.ResponseWriter, r *http.Request) {
	if _, err := a.Store.GetApp(r.PathValue("id")); err != nil {
		writeStoreErr(w, err)
		return
	}
	body := struct {
		Value              string   `json:"value"`
		DisplayName        string   `json:"displayName"`
		AllowedMemberTypes []string `json:"allowedMemberTypes"`
		IsEnabled          *bool    `json:"isEnabled"`
	}{}
	if !decodeBody(w, r, &body) {
		return
	}
	if body.Value == "" {
		httpx.WriteAdminError(w, http.StatusBadRequest, "validation_error", "value is required.",
			httpx.AdminDetail{Field: "value", Message: "Required."})
		return
	}
	types := "Application"
	if len(body.AllowedMemberTypes) > 0 {
		types = joinCSV(body.AllowedMemberTypes)
	}
	role := &store.AppRole{
		ID: store.NewGUID(), AppID: r.PathValue("id"), Value: body.Value,
		DisplayName: body.DisplayName, AllowedMemberTypes: types,
		IsEnabled: body.IsEnabled == nil || *body.IsEnabled,
	}
	if err := a.Store.AddRole(role); err != nil {
		writeStoreErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"id": role.ID, "value": role.Value, "displayName": nullable(role.DisplayName),
		"allowedMemberTypes": splitCSV(role.AllowedMemberTypes), "isEnabled": role.IsEnabled,
	})
}

func joinCSV(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ","
		}
		out += p
	}
	return out
}

func (a *Admin) patchRole(w http.ResponseWriter, r *http.Request) {
	roles, err := a.Store.ListRoles(r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	var target *store.AppRole
	for _, role := range roles {
		if role.ID == r.PathValue("roleId") {
			target = role
		}
	}
	if target == nil {
		httpx.WriteAdminError(w, http.StatusNotFound, "not_found", "Role not found.")
		return
	}
	body := struct {
		DisplayName        *string  `json:"displayName"`
		AllowedMemberTypes []string `json:"allowedMemberTypes"`
		IsEnabled          *bool    `json:"isEnabled"`
	}{}
	if !decodeBody(w, r, &body) {
		return
	}
	if body.DisplayName != nil {
		target.DisplayName = *body.DisplayName
	}
	if len(body.AllowedMemberTypes) > 0 {
		target.AllowedMemberTypes = joinCSV(body.AllowedMemberTypes)
	}
	if body.IsEnabled != nil {
		target.IsEnabled = *body.IsEnabled
	}
	if err := a.Store.UpdateRole(target); err != nil {
		writeStoreErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"id": target.ID, "value": target.Value, "displayName": nullable(target.DisplayName),
		"allowedMemberTypes": splitCSV(target.AllowedMemberTypes), "isEnabled": target.IsEnabled,
	})
}

func (a *Admin) deleteRole(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.DeleteRole(r.PathValue("id"), r.PathValue("roleId")); err != nil {
		writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
