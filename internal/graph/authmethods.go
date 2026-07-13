package graph

import (
	"encoding/hex"
	"net/http"
	"time"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// Authentication methods (docs/20-stateful-directory.md): the Graph
// authentication/methods surface over a user's stored credentials — the
// password (from the user's hash) and any registered passkeys (from
// webauthn_credentials). Read-and-delete; registration is via the WebAuthn
// ceremonies (docs/14-passkey-sign-in.md).

// passwordMethodID is Graph's fixed well-known id for the password method.
const passwordMethodID = "28c10230-6103-485e-b985-444c60001490"

func (g *Graph) registerAuthMethods(mux *http.ServeMux, prefix string) {
	p := prefix + "/v1.0"
	mux.HandleFunc("GET "+p+"/users/{id}/authentication/methods", g.requireBearer(g.authMethods(false)))
	mux.HandleFunc("GET "+p+"/me/authentication/methods", g.requireDelegated(g.authMethods(true)))
	mux.HandleFunc("GET "+p+"/users/{id}/authentication/passwordMethods", g.requireBearer(g.passwordMethods(false)))
	mux.HandleFunc("GET "+p+"/me/authentication/passwordMethods", g.requireDelegated(g.passwordMethods(true)))
	mux.HandleFunc("GET "+p+"/users/{id}/authentication/fido2Methods", g.requireBearer(g.fido2Methods(false)))
	mux.HandleFunc("GET "+p+"/me/authentication/fido2Methods", g.requireDelegated(g.fido2Methods(true)))
	mux.HandleFunc("DELETE "+p+"/users/{id}/authentication/fido2Methods/{methodId}", g.requireBearer(g.deleteFido2Method))
}

// authUserID resolves the target user: the /me token subject, or the path id.
func authUserID(r *http.Request, me bool, tok *tokens.ValidatedToken) string {
	if me {
		return tok.OID
	}
	return r.PathValue("id")
}

func passwordMethodShape() map[string]any {
	return map[string]any{
		"@odata.type": "#microsoft.graph.passwordAuthenticationMethod",
		"id":          passwordMethodID,
	}
}

func fido2MethodShape(c *store.WebAuthnCredential) map[string]any {
	shape := map[string]any{
		"@odata.type":     "#microsoft.graph.fido2AuthenticationMethod",
		"id":              c.ID,
		"displayName":     nullable(c.Name),
		"createdDateTime": time.Unix(c.CreatedAt, 0).UTC().Format(time.RFC3339),
	}
	if len(c.AAGUID) == 16 {
		shape["aaGuid"] = formatGUID(c.AAGUID)
	}
	return shape
}

// userMethods returns (password?, fido2 credentials) for a user, or an error
// response written to w. ok is false when the user does not exist.
func (g *Graph) userMethods(w http.ResponseWriter, userID string) (hasPassword bool, creds []*store.WebAuthnCredential, ok bool) {
	u, err := g.Store.GetUser(userID)
	if err != nil {
		httpx.WriteGraphError(w, http.StatusNotFound, "Request_ResourceNotFound", "Resource '"+userID+"' does not exist.")
		return false, nil, false
	}
	creds, err = g.Store.ListWebAuthnCredentials(userID)
	if err != nil {
		httpx.WriteGraphError(w, http.StatusInternalServerError, "InternalServerError", err.Error())
		return false, nil, false
	}
	return u.PasswordHash != "", creds, true
}

func (g *Graph) authMethods(me bool) handler {
	return func(w http.ResponseWriter, r *http.Request, tok *tokens.ValidatedToken) {
		hasPw, creds, ok := g.userMethods(w, authUserID(r, me, tok))
		if !ok {
			return
		}
		shapes := make([]map[string]any, 0, len(creds)+1)
		if hasPw {
			shapes = append(shapes, passwordMethodShape())
		}
		for _, c := range creds {
			shapes = append(shapes, fido2MethodShape(c))
		}
		g.writeSimpleCollection(w, "authenticationMethods", shapes)
	}
}

func (g *Graph) passwordMethods(me bool) handler {
	return func(w http.ResponseWriter, r *http.Request, tok *tokens.ValidatedToken) {
		hasPw, _, ok := g.userMethods(w, authUserID(r, me, tok))
		if !ok {
			return
		}
		shapes := []map[string]any{}
		if hasPw {
			shapes = append(shapes, passwordMethodShape())
		}
		g.writeSimpleCollection(w, "passwordAuthenticationMethods", shapes)
	}
}

func (g *Graph) fido2Methods(me bool) handler {
	return func(w http.ResponseWriter, r *http.Request, tok *tokens.ValidatedToken) {
		_, creds, ok := g.userMethods(w, authUserID(r, me, tok))
		if !ok {
			return
		}
		shapes := make([]map[string]any, 0, len(creds))
		for _, c := range creds {
			shapes = append(shapes, fido2MethodShape(c))
		}
		g.writeSimpleCollection(w, "fido2AuthenticationMethods", shapes)
	}
}

func (g *Graph) deleteFido2Method(w http.ResponseWriter, r *http.Request, _ *tokens.ValidatedToken) {
	if err := g.Store.DeleteWebAuthnCredential(r.PathValue("id"), r.PathValue("methodId")); err != nil {
		writeStoreErrGraph(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// formatGUID renders 16 bytes as a canonical (mixed-endian) Entra AAGUID string.
func formatGUID(b []byte) string {
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
