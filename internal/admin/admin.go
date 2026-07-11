// Package admin implements the unauthenticated admin REST API and serves the
// portal assets (docs/07-admin-api.md).
package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"strconv"
	"time"

	"github.com/calvinchengx/entra-emulator/internal/config"
	"github.com/calvinchengx/entra-emulator/internal/faults"
	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tlscert"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

type Admin struct {
	Cfg     *config.Config
	Store   *store.Store
	Tokens  *tokens.Service
	Faults  *faults.Store
	Cert    *tlscert.Material
	Version string
	Started time.Time
}

func New(cfg *config.Config, st *store.Store, ts *tokens.Service, fs *faults.Store, cert *tlscert.Material, version string) *Admin {
	if fs == nil {
		fs = faults.New()
	}
	return &Admin{Cfg: cfg, Store: st, Tokens: ts, Faults: fs, Cert: cert, Version: version, Started: time.Now()}
}

func (a *Admin) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/api/health", a.handleHealth)
	mux.HandleFunc("GET /health", a.handleHealth)

	mux.HandleFunc("GET /admin/api/users", a.listUsers)
	mux.HandleFunc("POST /admin/api/users", a.createUser)
	mux.HandleFunc("GET /admin/api/users/{id}", a.getUser)
	mux.HandleFunc("PATCH /admin/api/users/{id}", a.patchUser)
	mux.HandleFunc("DELETE /admin/api/users/{id}", a.deleteUser)
	mux.HandleFunc("GET /admin/api/users/{id}/groups", a.listUserGroups)

	mux.HandleFunc("GET /admin/api/groups", a.listGroups)
	mux.HandleFunc("POST /admin/api/groups", a.createGroup)
	mux.HandleFunc("GET /admin/api/groups/{id}", a.getGroup)
	mux.HandleFunc("PATCH /admin/api/groups/{id}", a.patchGroup)
	mux.HandleFunc("DELETE /admin/api/groups/{id}", a.deleteGroup)
	mux.HandleFunc("GET /admin/api/groups/{id}/members", a.listMembers)
	mux.HandleFunc("POST /admin/api/groups/{id}/members", a.addMember)
	mux.HandleFunc("DELETE /admin/api/groups/{id}/members/{userId}", a.removeMember)

	mux.HandleFunc("GET /admin/api/apps", a.listApps)
	mux.HandleFunc("POST /admin/api/apps", a.createApp)
	mux.HandleFunc("GET /admin/api/apps/{id}", a.getApp)
	mux.HandleFunc("PATCH /admin/api/apps/{id}", a.patchApp)
	mux.HandleFunc("DELETE /admin/api/apps/{id}", a.deleteApp)
	mux.HandleFunc("POST /admin/api/apps/{id}/redirectUris", a.addRedirectURI)
	mux.HandleFunc("DELETE /admin/api/apps/{id}/redirectUris/{uriId}", a.deleteRedirectURI)
	mux.HandleFunc("POST /admin/api/apps/{id}/secrets", a.addSecret)
	mux.HandleFunc("DELETE /admin/api/apps/{id}/secrets/{secretId}", a.deleteSecret)
	mux.HandleFunc("POST /admin/api/apps/{id}/scopes", a.addScope)
	mux.HandleFunc("PATCH /admin/api/apps/{id}/scopes/{scopeId}", a.patchScope)
	mux.HandleFunc("DELETE /admin/api/apps/{id}/scopes/{scopeId}", a.deleteScope)
	mux.HandleFunc("POST /admin/api/apps/{id}/roles", a.addRole)
	mux.HandleFunc("PATCH /admin/api/apps/{id}/roles/{roleId}", a.patchRole)
	mux.HandleFunc("DELETE /admin/api/apps/{id}/roles/{roleId}", a.deleteRole)

	mux.HandleFunc("POST /admin/api/tokens", a.forgeToken)
	mux.HandleFunc("GET /admin/api/faults", a.getFaults)
	mux.HandleFunc("POST /admin/api/faults", a.setFaults)
	mux.HandleFunc("DELETE /admin/api/faults", a.clearFaults)
	mux.HandleFunc("GET /admin/api/clock", a.getClock)
	mux.HandleFunc("POST /admin/api/clock", a.setClock)
	mux.HandleFunc("DELETE /admin/api/clock", a.resetClock)
	mux.HandleFunc("GET /admin/api/export", a.exportDirectory)
	mux.HandleFunc("POST /admin/api/import", a.importDirectory)
	mux.HandleFunc("POST /admin/api/seed", a.seed)
	mux.HandleFunc("POST /admin/api/reset", a.reset)
	mux.HandleFunc("GET /admin/api/certificate", a.certificateMeta)
	mux.HandleFunc("GET /admin/api/certificate/pem", a.certificatePEM)
}

// ---- shared helpers ----

func iso(epoch int64) any {
	if epoch == 0 {
		return nil
	}
	return time.Unix(epoch, 0).UTC().Format(time.RFC3339)
}

func pageParams(r *http.Request) (top, skip int, search string) {
	top, skip = 50, 0
	if v, err := strconv.Atoi(r.URL.Query().Get("top")); err == nil && v > 0 {
		if v > 200 {
			v = 200
		}
		top = v
	}
	if v, err := strconv.Atoi(r.URL.Query().Get("skip")); err == nil && v > 0 {
		skip = v
	}
	return top, skip, r.URL.Query().Get("search")
}

func decodeBody(w http.ResponseWriter, r *http.Request, into any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		httpx.WriteAdminError(w, http.StatusBadRequest, "validation_error", "Invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func writeStoreErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		httpx.WriteAdminError(w, http.StatusNotFound, "not_found", "The resource does not exist.")
	case errors.Is(err, store.ErrConflict):
		httpx.WriteAdminError(w, http.StatusConflict, "conflict", "A resource with the same unique value already exists.")
	default:
		httpx.WriteAdminError(w, http.StatusInternalServerError, "internal_error", err.Error())
	}
}

func paged(w http.ResponseWriter, value any, count, top, skip int) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"value": value, "count": count, "top": top, "skip": skip,
	})
}

// ---- system ----

func (a *Admin) handleHealth(w http.ResponseWriter, _ *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"status":        "ok",
		"version":       a.Version,
		"uptimeSeconds": int(time.Since(a.Started).Seconds()),
		"tls":           a.Cfg.TLSEnabled,
		"tenantId":      a.Cfg.TenantID,
		"origins": map[string]string{
			"login": a.Cfg.Origins.Login, "portal": a.Cfg.Origins.Portal, "graph": a.Cfg.Origins.Graph,
		},
	})
}

func (a *Admin) seed(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Force bool `json:"force"`
	}
	if r.ContentLength > 0 && !decodeBody(w, r, &body) {
		return
	}
	seeded, err := a.Store.IsSeeded()
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	if seeded && !body.Force {
		httpx.WriteJSON(w, http.StatusOK, map[string]bool{"seeded": false})
		return
	}
	if _, err := a.Store.Seed(a.Cfg.TenantID, a.Cfg.Issuer); err != nil {
		writeStoreErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"seeded": true})
}

func (a *Admin) reset(w http.ResponseWriter, r *http.Request) {
	body := struct {
		Reseed    *bool `json:"reseed"`
		ResetKeys bool  `json:"resetKeys"`
	}{}
	if r.ContentLength > 0 && !decodeBody(w, r, &body) {
		return
	}
	reseed := body.Reseed == nil || *body.Reseed
	reseeded, err := a.Store.Reset(a.Cfg.TenantID, a.Cfg.Issuer, reseed, body.ResetKeys)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"reset": true, "reseeded": reseeded})
}

func (a *Admin) certificateMeta(w http.ResponseWriter, _ *http.Request) {
	if a.Cert == nil {
		httpx.WriteAdminError(w, http.StatusNotFound, "not_found", "TLS is disabled; no certificate.")
		return
	}
	fp, err := a.Cert.Fingerprint()
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"fingerprintSHA256": fp,
		"certPath":          a.Cert.CertPath,
		"baseDomain":        a.Cfg.BaseDomain,
	})
}

func (a *Admin) certificatePEM(w http.ResponseWriter, _ *http.Request) {
	if a.Cert == nil {
		httpx.WriteAdminError(w, http.StatusNotFound, "not_found", "TLS is disabled; no certificate.")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="entra-emulator-cert.pem"`)
	_, _ = w.Write(a.Cert.CertPEM)
}

// ---- users ----

func userDTO(u *store.User) map[string]any {
	return map[string]any{
		"id": u.ID, "userPrincipalName": u.UserPrincipalName, "displayName": u.DisplayName,
		"givenName": nullable(u.GivenName), "surname": nullable(u.Surname), "mail": nullable(u.Mail),
		"accountEnabled": u.AccountEnabled, "hasPassword": u.PasswordHash != "",
		"createdAt": iso(u.CreatedAt),
	}
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (a *Admin) listUsers(w http.ResponseWriter, r *http.Request) {
	top, skip, search := pageParams(r)
	users, count, err := a.Store.ListUsers(top, skip, search)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	dtos := make([]map[string]any, 0, len(users))
	for _, u := range users {
		dtos = append(dtos, userDTO(u))
	}
	paged(w, dtos, count, top, skip)
}

type userBody struct {
	UserPrincipalName *string `json:"userPrincipalName"`
	DisplayName       *string `json:"displayName"`
	GivenName         *string `json:"givenName"`
	Surname           *string `json:"surname"`
	Mail              *string `json:"mail"`
	AccountEnabled    *bool   `json:"accountEnabled"`
	Password          *string `json:"password"`
}

func (b *userBody) validate(create bool) []httpx.AdminDetail {
	var details []httpx.AdminDetail
	if create && (b.UserPrincipalName == nil || *b.UserPrincipalName == "") {
		details = append(details, httpx.AdminDetail{Field: "userPrincipalName", Message: "Required."})
	}
	if create && (b.DisplayName == nil || *b.DisplayName == "") {
		details = append(details, httpx.AdminDetail{Field: "displayName", Message: "Required."})
	}
	if b.Mail != nil && *b.Mail != "" {
		if _, err := mail.ParseAddress(*b.Mail); err != nil {
			details = append(details, httpx.AdminDetail{Field: "mail", Message: "Invalid email."})
		}
	}
	return details
}

func (a *Admin) createUser(w http.ResponseWriter, r *http.Request) {
	var b userBody
	if !decodeBody(w, r, &b) {
		return
	}
	if details := b.validate(true); len(details) > 0 {
		httpx.WriteAdminError(w, http.StatusBadRequest, "validation_error", "Invalid user.", details...)
		return
	}
	u := &store.User{
		ID: store.NewGUID(), TenantID: a.Cfg.TenantID,
		UserPrincipalName: *b.UserPrincipalName, DisplayName: *b.DisplayName,
		AccountEnabled: true, CreatedAt: a.Store.Now(),
	}
	applyUserBody(u, &b)
	if b.Password != nil && *b.Password != "" {
		hash, err := store.HashSecret(*b.Password)
		if err != nil {
			writeStoreErr(w, err)
			return
		}
		u.PasswordHash = hash
	}
	if err := a.Store.CreateUser(u); err != nil {
		writeStoreErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, userDTO(u))
}

func applyUserBody(u *store.User, b *userBody) {
	if b.UserPrincipalName != nil {
		u.UserPrincipalName = *b.UserPrincipalName
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
	if b.AccountEnabled != nil {
		u.AccountEnabled = *b.AccountEnabled
	}
}

func (a *Admin) getUser(w http.ResponseWriter, r *http.Request) {
	u, err := a.Store.GetUser(r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, userDTO(u))
}

func (a *Admin) patchUser(w http.ResponseWriter, r *http.Request) {
	u, err := a.Store.GetUser(r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	var raw map[string]json.RawMessage
	if !decodeBody(w, r, &raw) {
		return
	}
	var b userBody
	full, _ := json.Marshal(raw)
	_ = json.Unmarshal(full, &b)
	if details := b.validate(false); len(details) > 0 {
		httpx.WriteAdminError(w, http.StatusBadRequest, "validation_error", "Invalid user.", details...)
		return
	}
	applyUserBody(u, &b)
	// password: null clears; string sets; absent leaves unchanged.
	if pwRaw, present := raw["password"]; present {
		if string(pwRaw) == "null" {
			u.PasswordHash = ""
		} else if b.Password != nil && *b.Password != "" {
			hash, err := store.HashSecret(*b.Password)
			if err != nil {
				writeStoreErr(w, err)
				return
			}
			u.PasswordHash = hash
		}
	}
	if err := a.Store.UpdateUser(u); err != nil {
		writeStoreErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, userDTO(u))
}

func (a *Admin) deleteUser(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.DeleteUser(r.PathValue("id")); err != nil {
		writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *Admin) listUserGroups(w http.ResponseWriter, r *http.Request) {
	if _, err := a.Store.GetUser(r.PathValue("id")); err != nil {
		writeStoreErr(w, err)
		return
	}
	groups, err := a.Store.ListGroupsForUser(r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	dtos := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		dtos = append(dtos, a.groupDTO(g))
	}
	paged(w, dtos, len(dtos), len(dtos), 0)
}
