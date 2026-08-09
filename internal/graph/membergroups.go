package graph

import (
	"net/http"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// getMemberObjects / getMemberGroups — the endpoints a client calls when its
// token could not carry the group list.
//
// This is not an optional extra. Above the group-overage limit the token drops
// the `groups` claim and carries `_claim_names` / `_claim_sources` instead,
// pointing here. A client that follows that pointer and gets a 404 cannot
// recover its groups at all, so the overage payload would be a promise the
// emulator does not keep.
//
// Entra returns transitive membership; the emulator's directory has no nested
// groups, so direct membership IS the transitive closure. `getMemberObjects`
// additionally returns directory-role object ids, which is why the two
// endpoints are separate rather than aliases.

func (g *Graph) registerMemberGroups(mux *http.ServeMux, prefix string) {
	p := prefix + "/v1.0"
	for _, route := range []string{"/users/{id}/", "/me/"} {
		mux.HandleFunc("POST "+p+route+"getMemberObjects", g.requireBearer(g.getMemberObjects(true)))
		mux.HandleFunc("POST "+p+route+"getMemberGroups", g.requireBearer(g.getMemberObjects(false)))
	}
}

// getMemberObjects returns the ids a user belongs to. withRoles includes
// directory-role template ids, matching Entra's split between the two calls.
func (g *Graph) getMemberObjects(withRoles bool) func(http.ResponseWriter, *http.Request, *tokens.ValidatedToken) {
	return func(w http.ResponseWriter, r *http.Request, tok *tokens.ValidatedToken) {
		userID := r.PathValue("id")
		if userID == "" { // /me/…
			userID = tok.OID
		}
		if _, err := g.Store.GetUser(userID); err != nil {
			httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound",
				"Resource '"+userID+"' does not exist.")
			return
		}

		// securityEnabledOnly is accepted and, with every emulator group being
		// security-enabled, changes nothing — decoded rather than ignored so a
		// malformed body is still a 400.
		var body struct {
			SecurityEnabledOnly bool `json:"securityEnabledOnly"`
		}
		if r.ContentLength > 0 && !decodeGraph(w, r, &body) {
			return
		}

		groups, err := g.Store.ListGroupsForUser(userID)
		if err != nil {
			httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		ids := make([]string, 0, len(groups))
		for _, gr := range groups {
			ids = append(ids, gr.ID)
		}
		if withRoles {
			if wids, err := g.Store.TenantWideRoleTemplateIDs(userID); err == nil {
				ids = append(ids, wids...)
			}
		}

		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"@odata.context": g.contextURL("Collection(Edm.String)"),
			"value":          ids,
		})
	}
}
