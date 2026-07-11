// Package scim implements a minimal SCIM 2.0 service provider (RFC 7643/7644)
// over the emulator's directory — the "server" phase of docs/15-scim-provisioning.md.
// External SCIM clients can CRUD the emulator's users and groups; bearer-token
// auth mirrors Entra's SCIM "secret token" model.
package scim

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/calvinchengx/entra-emulator/internal/config"
	"github.com/calvinchengx/entra-emulator/internal/store"
)

// DefaultToken is the seeded SCIM bearer secret — a public dev value, insecure
// like the other seeded secrets.
const DefaultToken = "scim-secret-token"

type Service struct {
	Store    *store.Store
	TenantID string
	Token    string // bearer secret clients must present
}

func New(cfg *config.Config, st *store.Store) *Service {
	return &Service{Store: st, TenantID: cfg.TenantID, Token: DefaultToken}
}

// Register mounts the SCIM routes under prefix ("" on the scim host, "/scim" on
// the compat origin).
func (s *Service) Register(mux *http.ServeMux, prefix string) {
	p := prefix + "/v2"
	mux.HandleFunc("GET "+p+"/ServiceProviderConfig", s.auth(s.serviceProviderConfig))
	mux.HandleFunc("GET "+p+"/ResourceTypes", s.auth(s.resourceTypes))
	mux.HandleFunc("GET "+p+"/Schemas", s.auth(s.schemas))

	mux.HandleFunc("GET "+p+"/Users", s.auth(s.listUsers))
	mux.HandleFunc("POST "+p+"/Users", s.auth(s.createUser))
	mux.HandleFunc("GET "+p+"/Users/{id}", s.auth(s.getUser))
	mux.HandleFunc("PUT "+p+"/Users/{id}", s.auth(s.replaceUser))
	mux.HandleFunc("PATCH "+p+"/Users/{id}", s.auth(s.patchUser))
	mux.HandleFunc("DELETE "+p+"/Users/{id}", s.auth(s.deleteUser))

	mux.HandleFunc("GET "+p+"/Groups", s.auth(s.listGroups))
	mux.HandleFunc("POST "+p+"/Groups", s.auth(s.createGroup))
	mux.HandleFunc("GET "+p+"/Groups/{id}", s.auth(s.getGroup))
	mux.HandleFunc("PATCH "+p+"/Groups/{id}", s.auth(s.patchGroup))
	mux.HandleFunc("DELETE "+p+"/Groups/{id}", s.auth(s.deleteGroup))
}

// auth enforces the SCIM bearer secret.
func (s *Service) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") != s.Token {
			scimErr(w, http.StatusUnauthorized, "Invalid or missing bearer token.")
			return
		}
		next(w, r)
	}
}

const allRows = 1 << 30

// ---- helpers ----

func writeSCIM(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func scimErr(w http.ResponseWriter, status int, detail string) {
	writeSCIM(w, status, map[string]any{
		"schemas": []string{errorSchema}, "status": strconv.Itoa(status), "detail": detail,
	})
}

// base builds the absolute SCIM base URL for meta.location.
func base(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	// r.URL.Path is ".../v2/<resource>..."; keep up to and including "/v2".
	path := r.URL.Path
	if i := strings.Index(path, "/v2"); i >= 0 {
		path = path[:i+3]
	}
	return scheme + "://" + r.Host + path
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		scimErr(w, http.StatusBadRequest, "Malformed SCIM payload: "+err.Error())
		return false
	}
	return true
}

// writeStoreErr maps a store error onto the SCIM wire.
func writeStoreErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		scimErr(w, http.StatusNotFound, "Resource not found.")
	case errors.Is(err, store.ErrConflict):
		scimErr(w, http.StatusConflict, "A resource with that identifier already exists.")
	default:
		scimErr(w, http.StatusInternalServerError, err.Error())
	}
}

// ---- discovery ----

func (s *Service) serviceProviderConfig(w http.ResponseWriter, r *http.Request) {
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":               []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri":      "https://calvinchengx.github.io/entra-emulator/15-scim-provisioning/",
		"patch":                 map[string]any{"supported": true},
		"bulk":                  map[string]any{"supported": false},
		"filter":                map[string]any{"supported": true, "maxResults": 200},
		"changePassword":        map[string]any{"supported": true},
		"sort":                  map[string]any{"supported": false},
		"etag":                  map[string]any{"supported": false},
		"authenticationSchemes": []map[string]any{{"type": "oauthbearertoken", "name": "OAuth Bearer Token"}},
	})
}

func (s *Service) resourceTypes(w http.ResponseWriter, r *http.Request) {
	b := base(r)
	writeSCIM(w, http.StatusOK, listResponse([]any{
		map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id": "User", "name": "User", "endpoint": "/Users", "schema": userSchema,
			"meta": map[string]any{"resourceType": "ResourceType", "location": b + "/ResourceTypes/User"}},
		map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id": "Group", "name": "Group", "endpoint": "/Groups", "schema": groupSchema,
			"meta": map[string]any{"resourceType": "ResourceType", "location": b + "/ResourceTypes/Group"}},
	}, 1))
}

func (s *Service) schemas(w http.ResponseWriter, r *http.Request) {
	writeSCIM(w, http.StatusOK, listResponse([]any{
		map[string]any{"id": userSchema, "name": "User"},
		map[string]any{"id": groupSchema, "name": "Group"},
	}, 1))
}

func listResponse(resources []any, startIndex int) map[string]any {
	return map[string]any{
		"schemas":      []string{listSchema},
		"totalResults": len(resources),
		"startIndex":   startIndex,
		"itemsPerPage": len(resources),
		"Resources":    resources,
	}
}
