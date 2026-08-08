package graph

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// B2B guest invitations. POST /invitations creates a real guest user in the
// directory — userType "Guest", externalUserState "PendingAcceptance", and the
// mangled UPN Entra gives external identities — and returns a redeem URL.
// Redeeming flips the state to "Accepted", which is the bit an app actually
// branches on when it asks "has this guest accepted yet?".

func (g *Graph) registerInvitations(mux *http.ServeMux, prefix string) {
	mux.HandleFunc("POST "+prefix+"/v1.0/invitations", g.requireBearer(g.createInvitation))
	// Redemption is a user-facing link, not a Graph call, so it has no bearer.
	mux.HandleFunc("GET "+prefix+"/invitations/redeem", g.redeemInvitation)
}

// guestUPN builds Entra's external-identity UPN: the invited address with @
// replaced by _, then "#EXT#@" and the tenant's own domain.
func guestUPN(email, tenantDomain string) string {
	local := strings.ReplaceAll(email, "@", "_")
	return local + "#EXT#@" + tenantDomain
}

// tenantDomain is the host part of the issuer — good enough to stand in for the
// tenant's initial domain in the emulator.
func (g *Graph) tenantDomain() string {
	if u, err := url.Parse(g.Cfg.Origins.Login); err == nil && u.Host != "" {
		return strings.ReplaceAll(u.Host, ":", "-")
	}
	return "entraemulator.dev"
}

func (g *Graph) createInvitation(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	var body struct {
		InvitedUserEmailAddress string `json:"invitedUserEmailAddress"`
		InviteRedirectURL       string `json:"inviteRedirectUrl"`
		InvitedUserDisplayName  string `json:"invitedUserDisplayName"`
		InvitedUserType         string `json:"invitedUserType"`
		SendInvitationMessage   bool   `json:"sendInvitationMessage"`
	}
	if !decodeGraph(w, r, &body) {
		return
	}
	if body.InvitedUserEmailAddress == "" || body.InviteRedirectURL == "" {
		httpx.WriteGraphError(w, http.StatusBadRequest, "Request_BadRequest",
			"invitedUserEmailAddress and inviteRedirectUrl are required.")
		return
	}
	userType := body.InvitedUserType
	if userType == "" {
		userType = "Guest"
	}
	if userType != "Guest" && userType != "Member" {
		httpx.WriteGraphError(w, http.StatusBadRequest, "Request_BadRequest",
			"invitedUserType must be Guest or Member.")
		return
	}
	display := body.InvitedUserDisplayName
	if display == "" {
		display = body.InvitedUserEmailAddress
	}

	now := g.Store.Now()
	guest := &store.User{
		ID: store.NewGUID(), TenantID: g.Cfg.TenantID,
		UserPrincipalName: guestUPN(body.InvitedUserEmailAddress, g.tenantDomain()),
		DisplayName:       display,
		Mail:              body.InvitedUserEmailAddress,
		AccountEnabled:    true,
		UserType:          userType,
		ExternalUserState: "PendingAcceptance",
		CreatedAt:         now,
	}
	if err := g.Store.CreateUser(guest); err != nil {
		httpx.WriteGraphError(w, http.StatusBadRequest, "Request_BadRequest",
			"Could not invite this address: "+err.Error())
		return
	}

	redeem := g.Cfg.Origins.Graph
	if g.Cfg.Origins.Graph == g.Cfg.Origins.Login {
		redeem += "/graph"
	}
	redeem += "/invitations/redeem?" + url.Values{
		"id": {guest.ID}, "redirect": {body.InviteRedirectURL},
	}.Encode()

	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"@odata.context":          g.contextURL("invitations/$entity"),
		"id":                      store.NewGUID(),
		"inviteRedeemUrl":         redeem,
		"invitedUserEmailAddress": body.InvitedUserEmailAddress,
		"invitedUserDisplayName":  display,
		"invitedUserType":         userType,
		"inviteRedirectUrl":       body.InviteRedirectURL,
		"sendInvitationMessage":   body.SendInvitationMessage,
		"status":                  "PendingAcceptance",
		"invitedUser":             map[string]any{"id": guest.ID},
	})
}

// redeemInvitation is what the guest's link hits: it accepts the invitation and
// redirects on to the inviting app.
func (g *Graph) redeemInvitation(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	u, err := g.Store.GetUser(id)
	if err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound", "Invitation does not exist.")
		return
	}
	if u.ExternalUserState != "Accepted" {
		u.ExternalUserState = "Accepted"
		if err := g.Store.UpdateUser(u); err != nil {
			httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
	}
	if target := r.URL.Query().Get("redirect"); target != "" {
		http.Redirect(w, r, target, http.StatusFound)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"id": u.ID, "externalUserState": u.ExternalUserState,
	})
}
