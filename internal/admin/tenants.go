package admin

import (
	"net/http"
	"strings"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/store"
)

// Multi-tenant directories (roadmap #15b). Each tenant carries its own tid,
// GUID-form issuer, and signing key; realistic display names and
// <slug>.onmicrosoft.com initial domains are generated with gofakeit when the
// caller does not supply them.

func (a *Admin) tenantDTO(t *store.Tenant, home bool) map[string]any {
	return map[string]any{
		"id":            t.ID,
		"displayName":   t.DisplayName,
		"issuer":        t.Issuer,
		"initialDomain": nullable(t.InitialDomain),
		"isHome":        home,
		"createdAt":     iso(t.CreatedAt),
	}
}

func (a *Admin) listTenants(w http.ResponseWriter, r *http.Request) {
	tenants, err := a.Store.ListTenants()
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	dtos := make([]map[string]any, 0, len(tenants))
	for _, t := range tenants {
		dtos = append(dtos, a.tenantDTO(t, t.ID == a.Cfg.TenantID))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"value": dtos})
}

func (a *Admin) getTenant(w http.ResponseWriter, r *http.Request) {
	t, err := a.Store.GetTenantByID(r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, a.tenantDTO(t, t.ID == a.Cfg.TenantID))
}

type tenantBody struct {
	DisplayName   *string `json:"displayName"`
	InitialDomain *string `json:"initialDomain"`
}

func (a *Admin) createTenant(w http.ResponseWriter, r *http.Request) {
	var b tenantBody
	if r.ContentLength > 0 && !decodeBody(w, r, &b) {
		return
	}

	display := ""
	if b.DisplayName != nil {
		display = strings.TrimSpace(*b.DisplayName)
	}
	if display == "" {
		display = gofakeit.Company()
	}

	domain := ""
	if b.InitialDomain != nil {
		domain = strings.ToLower(strings.TrimSpace(*b.InitialDomain))
	}
	if domain == "" {
		domain = domainSlug(display) + ".onmicrosoft.com"
	}

	id := store.NewGUID()
	t := &store.Tenant{
		ID:            id,
		DisplayName:   display,
		Issuer:        a.Cfg.Origins.Login + "/" + id + "/v2.0",
		InitialDomain: domain,
		CreatedAt:     a.Store.Now(),
	}
	if err := a.Store.CreateTenant(t); err != nil {
		writeStoreErr(w, err)
		return
	}
	// Eagerly provision the tenant's active signing key so discovery/JWKS and
	// the first token issuance in this tenant are ready immediately.
	if _, err := a.Tokens.SignerForTenant(id); err != nil {
		httpx.WriteAdminError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, a.tenantDTO(t, false))
}

func (a *Admin) deleteTenant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == a.Cfg.TenantID {
		httpx.WriteAdminError(w, http.StatusBadRequest, "validation_error",
			"The home tenant cannot be deleted.")
		return
	}
	if err := a.Store.DeleteTenant(id); err != nil {
		writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// domainSlug reduces a display name to a DNS-label-safe slug for the initial
// onmicrosoft.com domain, mirroring how Entra derives it from the tenant name.
func domainSlug(name string) string {
	var sb strings.Builder
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
		}
	}
	slug := sb.String()
	if slug == "" {
		slug = "contoso" + strings.ToLower(gofakeit.LetterN(6))
	}
	return slug
}
