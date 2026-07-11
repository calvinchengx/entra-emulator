package tokens

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/calvinchengx/entra-emulator/internal/config"
	"github.com/calvinchengx/entra-emulator/internal/store"
)

// Service mints and validates tokens and grant artifacts.
type Service struct {
	Store  *store.Store
	Signer *Signer
	Cfg    *config.Config
	// ClaimsEnricher, when set, is called during delegated-token minting to
	// merge additional claims from a custom authentication extension
	// (roadmap #10). It returns claims to add; protocol claims are protected
	// at the merge site and can never be overridden. nil = no enrichment.
	ClaimsEnricher func(app *store.App, user *store.User, tokenKind string) map[string]any
}

// protectedClaims can never be set or overridden by a custom extension.
var protectedClaims = map[string]bool{
	"iss": true, "aud": true, "exp": true, "iat": true, "nbf": true,
	"sub": true, "tid": true, "oid": true, "azp": true, "appid": true,
	"scp": true, "roles": true, "ver": true, "nonce": true,
	"name": true, "preferred_username": true, "email": true,
}

// MintSystemToken mints a short-lived app-only token the emulator uses to
// authenticate its own outbound callouts (e.g. custom-extension webhooks),
// mirroring Entra authenticating to a customer's Function with its own token.
func (s *Service) MintSystemToken(audience string) string {
	now := s.Store.Now()
	claims := map[string]any{
		"iss": s.Cfg.Issuer, "sub": "entra-emulator-system", "aud": audience,
		"iat": now, "nbf": now, "exp": now + 300,
		"tid": s.Cfg.TenantID, "idtyp": "app", "ver": "2.0",
	}
	jwt, _ := SignRS256(s.Signer.PrivateKey, s.Signer.Kid, claims)
	return jwt
}

// enrich merges extension-provided claims into base, skipping protected ones.
func (s *Service) enrich(claims map[string]any, app *store.App, user *store.User, kind string) {
	if s.ClaimsEnricher == nil {
		return
	}
	for k, v := range s.ClaimsEnricher(app, user, kind) {
		if protectedClaims[k] {
			continue // extensions may add claims, never override protocol claims
		}
		claims[k] = v
	}
}

// TokenResponse is the OAuth token-endpoint success JSON.
type TokenResponse struct {
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	ExtExpiresIn int    `json:"ext_expires_in"`
	Scope        string `json:"scope"`
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ClientInfo   string `json:"client_info,omitempty"`
}

// defaultGroupOverageLimit mirrors Entra's JWT groups-claim cap.
const defaultGroupOverageLimit = 200

// PairwiseSub derives the stable pairwise subject for (user, app).
func (s *Service) PairwiseSub(userID, appID string) string {
	sum := sha256.Sum256([]byte(userID + "|" + appID + "|" + s.Cfg.TenantID))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (s *Service) clientInfo(userOID string) string {
	raw, _ := json.Marshal(map[string]string{"uid": userOID, "utid": s.Cfg.TenantID})
	return base64.RawURLEncoding.EncodeToString(raw)
}

// DelegatedGrant carries everything needed to build a delegated response.
type DelegatedGrant struct {
	App      *store.App
	User     *store.User
	Scopes   []string // granted scope names (OIDC + short resource names)
	Resource string   // resolved audience ("" -> GraphResourceID)
	Nonce    string   // echoed into the ID token when present
	AMR      string   // authentication method reference (e.g. "fido") -> amr claim
	// SkipRefreshToken suppresses issuing a fresh refresh token — used by
	// the refresh grant, whose rotation already produced the successor.
	SkipRefreshToken bool
}

// BuildDelegatedResponse mints access (+ID +refresh) tokens for a user grant.
func (s *Service) BuildDelegatedResponse(g DelegatedGrant) (*TokenResponse, error) {
	now := s.Store.Now()
	aud := g.Resource
	if aud == "" {
		aud = s.Cfg.GraphResourceID
	}

	access, err := s.mintAccessDelegated(g, aud, now)
	if err != nil {
		return nil, err
	}
	resp := &TokenResponse{
		TokenType:    "Bearer",
		ExpiresIn:    s.Cfg.Lifetimes.AccessToken,
		ExtExpiresIn: s.Cfg.Lifetimes.AccessToken,
		Scope:        strings.Join(g.Scopes, " "),
		AccessToken:  access,
		ClientInfo:   s.clientInfo(g.User.ID),
	}
	if hasScope(g.Scopes, "openid") {
		idt, err := s.mintIDToken(g, now)
		if err != nil {
			return nil, err
		}
		resp.IDToken = idt
	}
	if hasScope(g.Scopes, "offline_access") && !g.SkipRefreshToken {
		rt, err := s.IssueRefreshToken(g.App.ID, g.User.ID, g.Scopes, g.Resource, "")
		if err != nil {
			return nil, err
		}
		resp.RefreshToken = rt
	}
	return resp, nil
}

// BuildAppOnlyResponse mints the client-credentials response (no user).
func (s *Service) BuildAppOnlyResponse(app *store.App, aud string, roles []string, scopeEcho string) (*TokenResponse, error) {
	now := s.Store.Now()
	claims := map[string]any{
		"iss": s.Cfg.Issuer, "sub": app.ID, "aud": aud,
		"iat": now, "nbf": now, "exp": now + int64(s.Cfg.Lifetimes.AccessToken),
		"tid": s.Cfg.TenantID, "azp": app.ID, "appid": app.ID,
		"roles": roles, "ver": "2.0",
	}
	jwt, err := SignRS256(s.Signer.PrivateKey, s.Signer.Kid, claims)
	if err != nil {
		return nil, err
	}
	return &TokenResponse{
		TokenType: "Bearer", ExpiresIn: s.Cfg.Lifetimes.AccessToken,
		ExtExpiresIn: s.Cfg.Lifetimes.AccessToken, Scope: scopeEcho, AccessToken: jwt,
	}, nil
}

func (s *Service) mintIDToken(g DelegatedGrant, now int64) (string, error) {
	claims := map[string]any{
		"iss": s.Cfg.Issuer,
		"sub": s.PairwiseSub(g.User.ID, g.App.ID),
		"aud": g.App.ID,
		"iat": now, "nbf": now, "exp": now + int64(s.Cfg.Lifetimes.IDToken),
		"tid": s.Cfg.TenantID, "oid": g.User.ID,
		"name": g.User.DisplayName, "preferred_username": g.User.UserPrincipalName,
		"ver": "2.0",
	}
	if g.User.Mail != "" {
		claims["email"] = g.User.Mail
	}
	if g.Nonce != "" {
		claims["nonce"] = g.Nonce
	}
	if g.AMR != "" {
		claims["amr"] = []string{g.AMR}
	}
	s.applyTokenConfig(claims, g.App, g.User, "idToken")
	s.enrich(claims, g.App, g.User, "idToken")
	return SignRS256(s.Signer.PrivateKey, s.Signer.Kid, claims)
}

func (s *Service) mintAccessDelegated(g DelegatedGrant, aud string, now int64) (string, error) {
	claims := map[string]any{
		"iss": s.Cfg.Issuer,
		"sub": s.PairwiseSub(g.User.ID, g.App.ID),
		"aud": aud,
		"iat": now, "nbf": now, "exp": now + int64(s.Cfg.Lifetimes.AccessToken),
		"tid": s.Cfg.TenantID, "oid": g.User.ID,
		"azp": g.App.ID, "appid": g.App.ID,
		"scp": strings.Join(scopeNamesOnly(g.Scopes), " "),
		"ver": "2.0",
	}
	// Access-token optional claims come from the RESOURCE app's config; the
	// emulator resolves the resource app when the audience is a local app.
	resourceApp := g.App
	if aud != s.Cfg.GraphResourceID {
		if byURI, err := s.Store.GetAppByIDURI(aud); err == nil {
			resourceApp = byURI
		} else if byID, err := s.Store.GetApp(aud); err == nil {
			resourceApp = byID
		}
	}
	s.applyTokenConfig(claims, resourceApp, g.User, "accessToken")
	s.enrich(claims, g.App, g.User, "accessToken")
	return SignRS256(s.Signer.PrivateKey, s.Signer.Kid, claims)
}

// ---- Optional claims & group claims (docs/04, token configuration) ----

type optionalClaimEntry struct {
	Name string `json:"name"`
}

type optionalClaimsConfig struct {
	IDToken     []optionalClaimEntry `json:"idToken"`
	AccessToken []optionalClaimEntry `json:"accessToken"`
}

var supportedOptionalClaims = map[string]map[string]bool{
	"idToken":     {"given_name": true, "family_name": true, "upn": true, "ipaddr": true, "groups": true},
	"accessToken": {"given_name": true, "family_name": true, "upn": true, "ipaddr": true, "groups": true},
}

func (s *Service) applyTokenConfig(claims map[string]any, app *store.App, user *store.User, kind string) {
	var cfg optionalClaimsConfig
	if app.OptionalClaims != "" {
		_ = json.Unmarshal([]byte(app.OptionalClaims), &cfg)
	}
	entries := cfg.IDToken
	if kind == "accessToken" {
		entries = cfg.AccessToken
	}

	groupsRequested := false
	for _, e := range entries {
		if !supportedOptionalClaims[kind][e.Name] {
			continue // preserved in config, never emitted
		}
		switch e.Name {
		case "groups":
			groupsRequested = true
		case "given_name":
			if user.GivenName != "" {
				claims["given_name"] = user.GivenName
			}
		case "family_name":
			if user.Surname != "" {
				claims["family_name"] = user.Surname
			}
		case "upn":
			claims["upn"] = user.UserPrincipalName
		case "ipaddr":
			claims["ipaddr"] = "127.0.0.1"
		}
	}

	if app.GroupMembershipClaims != "" && app.GroupMembershipClaims != "None" || groupsRequested {
		groups, err := s.Store.ListGroupsForUser(user.ID)
		if err != nil {
			return
		}
		limit := app.GroupOverageLimit
		if limit == 0 {
			limit = defaultGroupOverageLimit
		}
		if len(groups) > limit {
			// Entra-style overage payload instead of the groups list.
			claims["_claim_names"] = map[string]string{"groups": "src1"}
			claims["_claim_sources"] = map[string]any{
				"src1": map[string]string{
					"endpoint": s.Cfg.Origins.Graph + "/v1.0/users/" + user.ID + "/getMemberObjects",
				},
			}
			return
		}
		ids := make([]string, 0, len(groups))
		for _, g := range groups {
			ids = append(ids, g.ID)
		}
		claims["groups"] = ids
	}
}

// ---- Authorization codes ----

type AuthCodeRequest struct {
	AppID, UserID, RedirectURI            string
	Scopes                                []string
	Resource                              string
	CodeChallenge, ChallengeMethod, Nonce string
	AMR                                   string // authentication method reference
}

// IssueAuthCode persists a single-use opaque code.
func (s *Service) IssueAuthCode(r AuthCodeRequest) (string, error) {
	code := store.NewOpaqueToken(32)
	now := s.Store.Now()
	err := s.Store.InsertAuthCode(&store.AuthCode{
		Code: code, AppID: r.AppID, UserID: r.UserID, RedirectURI: r.RedirectURI,
		Scopes: strings.Join(r.Scopes, " "), Resource: r.Resource,
		CodeChallenge: r.CodeChallenge, CodeChallengeMethod: r.ChallengeMethod,
		Nonce: r.Nonce, AMR: r.AMR, ExpiresAt: now + int64(s.Cfg.Lifetimes.AuthCode), CreatedAt: now,
	})
	if err != nil {
		return "", err
	}
	return code, nil
}

// RedeemErr is a typed redemption failure mapping to an OAuth error code.
type RedeemErr struct{ Code, Description string }

func (e *RedeemErr) Error() string { return e.Code + ": " + e.Description }

func invalidGrant(desc string) *RedeemErr {
	return &RedeemErr{Code: "invalid_grant", Description: desc}
}

// RedeemAuthCode validates and atomically consumes an authorization code.
func (s *Service) RedeemAuthCode(code, appID, redirectURI, codeVerifier string) (*store.AuthCode, error) {
	row, err := s.Store.GetAuthCode(code)
	if err == store.ErrNotFound {
		return nil, invalidGrant("AADSTS70008: The provided authorization code is invalid.")
	}
	if err != nil {
		return nil, err
	}
	switch {
	case row.Consumed:
		return nil, invalidGrant("AADSTS54005: The authorization code was already redeemed.")
	case row.ExpiresAt <= s.Store.Now():
		return nil, invalidGrant("AADSTS70008: The provided authorization code has expired.")
	case row.AppID != appID:
		return nil, invalidGrant("AADSTS70008: The code was issued to a different client.")
	case row.RedirectURI != redirectURI:
		return nil, invalidGrant("AADSTS50011: The redirect URI does not match the authorization request.")
	}
	if row.CodeChallenge != "" {
		if codeVerifier == "" {
			return nil, invalidGrant("AADSTS501481: code_verifier is required.")
		}
		if !verifyPKCE(row.CodeChallenge, row.CodeChallengeMethod, codeVerifier) {
			return nil, invalidGrant("AADSTS501481: The code_verifier does not match the code_challenge.")
		}
	}
	ok, err := s.Store.ConsumeAuthCode(code)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, invalidGrant("AADSTS54005: The authorization code was already redeemed.")
	}
	return row, nil
}

func verifyPKCE(challenge, method, verifier string) bool {
	switch method {
	case "plain":
		return challenge == verifier
	default: // S256 (default when a challenge was stored)
		sum := sha256.Sum256([]byte(verifier))
		return base64.RawURLEncoding.EncodeToString(sum[:]) == challenge
	}
}

// ---- Refresh tokens ----

// IssueRefreshToken stores the SHA-256 of a fresh opaque token and returns
// the plaintext.
func (s *Service) IssueRefreshToken(appID, userID string, scopes []string, resource, rotatedFrom string) (string, error) {
	plain := store.NewOpaqueToken(32)
	now := s.Store.Now()
	err := s.Store.InsertRefreshToken(&store.RefreshToken{
		TokenHash: store.HashToken(plain), AppID: appID, UserID: userID,
		Scopes: strings.Join(scopes, " "), Resource: resource,
		ExpiresAt:   now + int64(s.Cfg.Lifetimes.RefreshToken),
		RotatedFrom: rotatedFrom, CreatedAt: now,
	})
	if err != nil {
		return "", err
	}
	return plain, nil
}

// RedeemedRefresh is the result of a successful rotation.
type RedeemedRefresh struct {
	UserID, Resource string
	Scopes           []string
	NewRefreshToken  string // plaintext successor (issued iff offline_access kept)
}

// RedeemRefreshToken implements rotation with family revocation on reuse
// (docs/04). requestedScopes narrows the grant (must be a subset).
func (s *Service) RedeemRefreshToken(plaintext, appID string, requestedScopes []string) (*RedeemedRefresh, error) {
	hash := store.HashToken(plaintext)
	row, err := s.Store.GetRefreshTokenByHash(hash)
	if err == store.ErrNotFound {
		return nil, invalidGrant("AADSTS70008: The refresh token is invalid.")
	}
	if err != nil {
		return nil, err
	}
	if row.Revoked {
		// Reuse takes precedence over expiry: revoke the whole family.
		if err := s.Store.RevokeRefreshTokenFamily(hash); err != nil {
			return nil, err
		}
		return nil, invalidGrant("AADSTS70008: The refresh token was already rotated (reuse detected).")
	}
	if row.AppID != appID {
		return nil, invalidGrant("AADSTS70008: The refresh token is bound to a different client.")
	}
	if row.ExpiresAt <= s.Store.Now() {
		return nil, invalidGrant("AADSTS70008: The refresh token has expired.")
	}

	granted := strings.Fields(row.Scopes)
	scopes := granted
	if len(requestedScopes) > 0 {
		for _, sc := range requestedScopes {
			if !hasScope(granted, sc) {
				return nil, &RedeemErr{Code: "invalid_scope",
					Description: "AADSTS70011: Requested scope is not a subset of the original grant: " + sc}
			}
		}
		scopes = requestedScopes
	}

	successorPlain := store.NewOpaqueToken(32)
	now := s.Store.Now()
	won, err := s.Store.RotateRefreshToken(hash, &store.RefreshToken{
		TokenHash: store.HashToken(successorPlain), AppID: appID, UserID: row.UserID,
		Scopes: row.Scopes, Resource: row.Resource,
		ExpiresAt: now + int64(s.Cfg.Lifetimes.RefreshToken), CreatedAt: now,
	})
	if err != nil {
		return nil, err
	}
	if !won {
		// Concurrent redemption lost the race — treated as reuse.
		if err := s.Store.RevokeRefreshTokenFamily(hash); err != nil {
			return nil, err
		}
		return nil, invalidGrant("AADSTS70008: The refresh token was already rotated (reuse detected).")
	}

	out := &RedeemedRefresh{UserID: row.UserID, Resource: row.Resource, Scopes: scopes}
	if hasScope(scopes, "offline_access") {
		out.NewRefreshToken = successorPlain
	}
	return out, nil
}

// ---- Access-token validation (Graph / userinfo) ----

const clockSkewSeconds = 60

// ValidatedToken is the decoded, verified access token.
type ValidatedToken struct {
	Claims map[string]any
	OID    string // empty for app-only tokens
	Sub    string
	Scopes []string
}

// ValidateAccessToken verifies signature, issuer, expiry, and audience.
func (s *Service) ValidateAccessToken(bearer string, audiences []string) (*ValidatedToken, error) {
	parts := strings.Split(bearer, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed token")
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("malformed token header")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil || header.Alg != "RS256" {
		return nil, fmt.Errorf("unsupported token algorithm")
	}
	pub, err := VerificationKey(s.Store, header.Kid)
	if err != nil {
		return nil, fmt.Errorf("unknown signing key")
	}
	claims, err := VerifyRS256(pub, bearer)
	if err != nil {
		return nil, err
	}

	if iss, _ := claims["iss"].(string); iss != s.Cfg.Issuer {
		return nil, fmt.Errorf("wrong issuer")
	}
	now := s.Store.Now()
	if exp, ok := numClaim(claims, "exp"); !ok || now > exp+clockSkewSeconds {
		return nil, fmt.Errorf("token expired")
	}
	if nbf, ok := numClaim(claims, "nbf"); ok && now < nbf-clockSkewSeconds {
		return nil, fmt.Errorf("token not yet valid")
	}
	aud, _ := claims["aud"].(string)
	accepted := false
	for _, a := range audiences {
		if aud == a {
			accepted = true
			break
		}
	}
	if !accepted {
		return nil, fmt.Errorf("wrong audience")
	}

	v := &ValidatedToken{Claims: claims}
	v.OID, _ = claims["oid"].(string)
	v.Sub, _ = claims["sub"].(string)
	if scp, ok := claims["scp"].(string); ok {
		v.Scopes = strings.Fields(scp)
	}
	return v, nil
}

func numClaim(claims map[string]any, key string) (int64, bool) {
	f, ok := claims[key].(float64)
	return int64(f), ok
}

func hasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}

// scopeNamesOnly strips any resource prefix from scope values for `scp`
// (Entra emits short names: "User.Read", "access_as_user").
func scopeNamesOnly(scopes []string) []string {
	out := make([]string, 0, len(scopes))
	for _, sc := range scopes {
		if sc == "openid" || sc == "profile" || sc == "email" || sc == "offline_access" {
			continue // OIDC scopes are not resource scopes; still granted, not in scp? see note
		}
		if i := strings.LastIndex(sc, "/"); i >= 0 {
			sc = sc[i+1:]
		}
		out = append(out, sc)
	}
	if len(out) == 0 {
		// OIDC-only grant: Entra still emits the OIDC scopes in scp for
		// Graph-audience tokens so userinfo/Graph calls carry them.
		for _, sc := range scopes {
			if sc != "offline_access" {
				out = append(out, sc)
			}
		}
	}
	return out
}
