package graph

import (
	"net/http"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// Password reset over Graph's documented authentication-methods API:
//
//	POST /users/{id}/authentication/passwordMethods/{methodId}/resetPassword
//
// The reset is REAL: the new password is scrypt-hashed into the directory, so
// the old one immediately stops working and the new one signs in. Omit
// newPassword and the emulator generates one and returns it, as Entra does for
// system-generated resets.
//
// What this is NOT: Entra's interactive SSPR portal (verify by email/SMS/
// questions at passwordreset.microsoftonline.com). That is a first-party web
// flow, not a documented protocol, so emulating it would mean inventing a wire
// format — see docs/parity.md.

func (g *Graph) registerPasswordReset(mux *http.ServeMux, prefix string) {
	p := prefix + "/v1.0"
	mux.HandleFunc("POST "+p+"/users/{id}/authentication/passwordMethods/{methodId}/resetPassword",
		g.requireBearer(g.resetPassword))
}

func (g *Graph) resetPassword(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	if r.PathValue("methodId") != passwordMethodID {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound",
			"Password authentication method does not exist.")
		return
	}
	u, err := g.Store.GetUser(r.PathValue("id"))
	if err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound", "User does not exist.")
		return
	}

	var body struct {
		NewPassword string `json:"newPassword"`
	}
	if r.ContentLength > 0 && !decodeGraph(w, r, &body) {
		return
	}

	generated := body.NewPassword == ""
	newPassword := body.NewPassword
	if generated {
		// Entra returns a system-generated password when none is supplied.
		newPassword = store.NewOpaqueToken(16) + "aA1!"
	}

	hash, err := store.HashSecret(newPassword)
	if err != nil {
		httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}
	u.PasswordHash = hash
	if err := g.Store.UpdateUser(u); err != nil {
		httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return
	}

	// Graph answers 202 for this long-running operation.
	w.Header().Set("Location", g.contextURL("users/"+u.ID+"/authentication/passwordMethods/"+passwordMethodID))
	if generated {
		httpx.WriteJSON(w, http.StatusAccepted, map[string]any{
			"@odata.type": "#microsoft.graph.passwordResetResponse",
			"newPassword": newPassword,
		})
		return
	}
	w.WriteHeader(http.StatusAccepted)
}
