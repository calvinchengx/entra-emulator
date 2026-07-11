package identity

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
)

// RegisterMSI mounts the App Service managed-identity token endpoint
// (roadmap #3). A workload sets IDENTITY_ENDPOINT=<origin>/msi/token and
// IDENTITY_HEADER=<secret>; azidentity.ManagedIdentityCredential /
// DefaultAzureCredential then acquires an app-only token with no secret in
// the app. We emulate the env-var endpoint (not raw IMDS, whose link-local
// 169.254.169.254 can't be redirected without network shims).
func (i *Identity) RegisterMSI(mux *http.ServeMux) {
	mux.HandleFunc("GET /msi/token", i.handleMSIToken)
}

// handleMSIToken issues a managed-identity token in the App Service response
// format. The identity is a directory app: system-assigned (default) or
// user-assigned selected by client_id/object_id/mi_res_id.
func (i *Identity) handleMSIToken(w http.ResponseWriter, r *http.Request) {
	// SSRF mitigation in real Azure: the platform-injected secret header.
	if got := r.Header.Get("X-IDENTITY-HEADER"); got == "" || got != i.Cfg.ManagedIdentitySecret {
		httpx.WriteJSON(w, http.StatusUnauthorized, map[string]any{
			"error":             "unauthorized",
			"error_description": "Missing or invalid X-IDENTITY-HEADER.",
		})
		return
	}

	q := r.URL.Query()
	resource := q.Get("resource")
	if resource == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{
			"error":             "invalid_request",
			"error_description": "The 'resource' query parameter is required.",
		})
		return
	}

	// Identity selection: an explicit id => user-assigned; else system-assigned.
	clientID := firstNonEmpty(q.Get("client_id"), q.Get("object_id"), q.Get("mi_res_id"))
	systemAssigned := clientID == ""
	if systemAssigned {
		clientID = i.Cfg.ManagedIdentityClientID
	}
	// object_id resolves against the user's oid space; mi_res_id is an ARM
	// resource id we don't model — for those, fall back to matching an app by
	// appId only (client_id case). Unknown => identity_not_found.
	app, err := i.Store.GetApp(clientID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{
			"error":             "invalid_request",
			"error_description": "identity_not_found: no managed identity matches the request.",
		})
		return
	}

	// aud = the requested resource (Azure keeps the trailing slash if present).
	aud := resource
	// Roles: auto-grant from the resource app's Application roles, mirroring
	// the client-credentials model, when the resource resolves to a local app.
	roles := []string{}
	if resourceApp := i.findResourceApp(strings.TrimSuffix(resource, "/")); resourceApp != nil {
		if all, err := i.Store.ListRoles(resourceApp.ID); err == nil {
			for _, role := range all {
				if role.IsEnabled && strings.Contains(role.AllowedMemberTypes, "Application") {
					roles = append(roles, role.Value)
				}
			}
		}
	}

	resp, err := i.Tokens.BuildAppOnlyResponse(app, aud, roles, resource)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{
			"error": "server_error", "error_description": err.Error(),
		})
		return
	}

	now := i.Store.Now()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"access_token": resp.AccessToken,
		"resource":     resource,
		"token_type":   "Bearer",
		"client_id":    app.ID,
		// App Service emits these as strings.
		"expires_on": strconv.FormatInt(now+int64(resp.ExpiresIn), 10),
		"expires_in": strconv.Itoa(resp.ExpiresIn),
		"not_before": strconv.FormatInt(now, 10),
	})
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
