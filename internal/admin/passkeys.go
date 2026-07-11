package admin

import (
	"net/http"
)

// listPasskeys returns a user's registered passkeys (roadmap #11), never the
// public-key bytes.
func (a *Admin) listPasskeys(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	if _, err := a.Store.GetUser(userID); err != nil {
		writeStoreErr(w, err)
		return
	}
	creds, err := a.Store.ListWebAuthnCredentials(userID)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	dtos := make([]map[string]any, 0, len(creds))
	for _, c := range creds {
		dtos = append(dtos, map[string]any{
			"id": c.ID, "name": nullable(c.Name), "signCount": c.SignCount,
			"transports": nullable(c.Transports), "createdAt": iso(c.CreatedAt),
		})
	}
	paged(w, dtos, len(dtos), len(dtos), 0)
}

// deletePasskey removes one of a user's passkeys.
func (a *Admin) deletePasskey(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.DeleteWebAuthnCredential(r.PathValue("id"), r.PathValue("credId")); err != nil {
		writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
