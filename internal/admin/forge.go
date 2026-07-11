package admin

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"

	"github.com/calvinchengx/entra-emulator/internal/httpx"
	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// forgeRequest drives the token forge (roadmap #2). Every field is optional;
// the defaults produce a normal, valid access token for the seeded SPA. The
// point is negative-testing power: mint expired, wrong-audience, or
// bad-signature tokens, or inject arbitrary claims, without running a flow.
type forgeRequest struct {
	TokenType        string         `json:"tokenType"`        // "access" (default) | "id"
	ClientID         string         `json:"clientId"`         // default: seeded SPA
	UserID           string         `json:"userId"`           // set => delegated; omit => app-only
	Scopes           []string       `json:"scopes"`           // access delegated: scp
	Roles            []string       `json:"roles"`            // access app-only: roles
	Audience         string         `json:"audience"`         // override aud
	ExpiresInSeconds *int           `json:"expiresInSeconds"` // default 3600; negative => already expired
	NotBeforeSeconds *int           `json:"notBeforeSeconds"` // default 0
	Nonce            string         `json:"nonce"`            // id tokens
	ExtraClaims      map[string]any `json:"extraClaims"`      // merged last; can override anything
	Signature        string         `json:"signature"`        // "valid" (default) | "invalid"
}

// forgeToken mints an arbitrary signed JWT.
func (a *Admin) forgeToken(w http.ResponseWriter, r *http.Request) {
	var req forgeRequest
	if r.ContentLength > 0 && !decodeBody(w, r, &req) {
		return
	}

	clientID := req.ClientID
	if clientID == "" {
		clientID = store.SeedAppSPAID
	}
	app, err := a.Store.GetApp(clientID)
	if err != nil {
		httpx.WriteAdminError(w, http.StatusBadRequest, "invalid_reference",
			"clientId does not resolve to a registered app.")
		return
	}

	var user *store.User
	if req.UserID != "" {
		user, err = a.Store.GetUser(req.UserID)
		if err != nil {
			httpx.WriteAdminError(w, http.StatusBadRequest, "invalid_reference",
				"userId does not resolve to a user.")
			return
		}
	}

	now := a.Store.Now()
	lifetime := 3600
	if req.ExpiresInSeconds != nil {
		lifetime = *req.ExpiresInSeconds
	}
	nbfOffset := 0
	if req.NotBeforeSeconds != nil {
		nbfOffset = *req.NotBeforeSeconds
	}

	tokenType := req.TokenType
	if tokenType == "" {
		tokenType = "access"
	}

	claims := map[string]any{
		"iss": a.Cfg.Issuer,
		"iat": now,
		"nbf": now + int64(nbfOffset),
		"exp": now + int64(lifetime),
		"tid": a.Cfg.TenantID,
		"ver": "2.0",
	}

	switch tokenType {
	case "id":
		claims["aud"] = app.ID
		if user != nil {
			claims["sub"] = a.Tokens.PairwiseSub(user.ID, app.ID, app.TenantID)
			claims["oid"] = user.ID
			claims["name"] = user.DisplayName
			claims["preferred_username"] = user.UserPrincipalName
			if user.Mail != "" {
				claims["email"] = user.Mail
			}
		}
		if req.Nonce != "" {
			claims["nonce"] = req.Nonce
		}
	default: // access
		aud := req.Audience
		if aud == "" {
			aud = a.Cfg.GraphResourceID
		}
		claims["aud"] = aud
		claims["azp"] = app.ID
		claims["appid"] = app.ID
		if user != nil {
			claims["sub"] = a.Tokens.PairwiseSub(user.ID, app.ID, app.TenantID)
			claims["oid"] = user.ID
			claims["scp"] = joinSpace(req.Scopes)
		} else {
			claims["sub"] = app.ID
			roles := req.Roles
			if roles == nil {
				roles = []string{}
			}
			claims["roles"] = roles
		}
	}

	// extraClaims win — full control, including overriding registered claims
	// or setting nonsense for negative tests.
	for k, v := range req.ExtraClaims {
		claims[k] = v
	}

	// Sign with the active key, or a throwaway key (valid structure, signature
	// that fails JWKS verification) when signature=invalid.
	key := a.Tokens.Signer.PrivateKey
	kid := a.Tokens.Signer.Kid
	if req.Signature == "invalid" {
		bogus, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			httpx.WriteAdminError(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		key = bogus // header keeps the real kid, so JWKS verification fails
	}

	jwt, err := tokens.SignRS256(key, kid, claims)
	if err != nil {
		httpx.WriteAdminError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"token":     jwt,
		"tokenType": tokenType,
		"kid":       kid,
		"claims":    claims,
	})
}

func joinSpace(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += " "
		}
		out += p
	}
	return out
}
