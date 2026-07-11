package identity

import (
	"net/http"
	"strconv"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
)

// Microsoft Fabric / Power BI identity plumbing (roadmap #16) — the Entra
// token layer only. The emulator recognizes the Fabric resource identifiers so
// client-credentials and delegated grants mint correct-aud tokens without a
// registered resource app, and models the workspace-identity directory object
// whose tokens are minted internally (no caller-held credential). The Fabric
// control plane itself is out of scope (see docs/12-fabric-companion.md).

const (
	fabricResource  = "https://api.fabric.microsoft.com"
	powerBIResource = "https://analysis.windows.net/powerbi/api"
	// Well-known first-party app id for the Power BI / Fabric service.
	fabricFirstPartyAppID = "00000009-0000-0000-c000-000000000000"
)

// Delegated Fabric scopes auto-consented like the Graph carve-out.
var knownFabricScopes = map[string]bool{
	"Fabric.Embed": true, "Item.Read.All": true,
}

// fabricAud maps a recognized Fabric resource identifier (canonical URI, the
// legacy Power BI URI, or the first-party app id) to the audience used in
// issued tokens. Returns "" when the resource is not a Fabric identifier.
func fabricAud(resource string) string {
	switch resource {
	case fabricResource, fabricFirstPartyAppID:
		return fabricResource
	case powerBIResource:
		return powerBIResource
	}
	return ""
}

// handleWorkspaceIdentityToken mints an app-only token for a Fabric workspace
// identity (roadmap #16b). Like managed identity (#3), the platform holds the
// credential — the caller supplies no secret, only the identity id. The
// identity must be Active. The default resource is the Fabric API; any
// recognized Fabric resource may be requested.
func (i *Identity) handleWorkspaceIdentityToken(w http.ResponseWriter, r *http.Request) {
	wi, err := i.Store.GetWorkspaceIdentity(r.PathValue("id"))
	if err != nil {
		httpx.WriteJSON(w, http.StatusNotFound, map[string]any{
			"error": "not_found", "error_description": "No workspace identity matches the id.",
		})
		return
	}
	if wi.State != "Active" {
		httpx.WriteJSON(w, http.StatusConflict, map[string]any{
			"error":             "identity_not_ready",
			"error_description": "The workspace identity is in state " + wi.State + "; only Active identities issue tokens.",
		})
		return
	}

	resource := r.URL.Query().Get("resource")
	if resource == "" {
		resource = fabricResource
	}
	aud := fabricAud(resource)
	if aud == "" {
		aud = resource // echo non-Fabric resources, mirroring managed identity
	}

	app, err := i.Store.GetApp(wi.AppID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]any{
			"error": "server_error", "error_description": "workspace identity SP missing",
		})
		return
	}
	resp, err := i.Tokens.BuildAppOnlyResponse(app, aud, []string{}, resource, app.TenantID)
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
		"workspace_id": wi.WorkspaceID,
		"expires_on":   strconv.FormatInt(now+int64(resp.ExpiresIn), 10),
		"expires_in":   strconv.Itoa(resp.ExpiresIn),
		"not_before":   strconv.FormatInt(now, 10),
	})
}
