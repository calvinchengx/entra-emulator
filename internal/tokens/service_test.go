package tokens

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/config"
	"github.com/calvinchengx/entra-emulator/internal/store"
)

const otherTenant = "22222222-2222-2222-2222-222222222222"

// newService builds a Service backed by a fresh store with an active home-tenant
// signer and a minimal but realistic config.
func newService(t *testing.T) (*store.Store, *Service, *int64) {
	t.Helper()
	st := newStore(t)
	signer, err := EnsureActiveKey(st, testTenant)
	if err != nil {
		t.Fatal(err)
	}
	now := int64(1_700_000_000)
	st.Now = func() int64 { return now }
	cfg := &config.Config{
		TenantID:        testTenant,
		Issuer:          "https://issuer/" + testTenant + "/v2.0",
		GraphResourceID: "https://graph.microsoft.com",
		Lifetimes: config.TokenLifetimes{
			AuthCode: 300, IDToken: 3600, AccessToken: 3600, RefreshToken: 86400, DeviceCode: 900,
		},
		Origins: config.Origins{
			Login:  "https://login.example",
			Portal: "https://portal.example",
			Graph:  "https://graph.example",
		},
	}
	return st, &Service{Store: st, Signer: signer, Cfg: cfg}, &now
}

func makeApp(t *testing.T, st *store.Store, a *store.App) *store.App {
	t.Helper()
	if a.DisplayName == "" {
		a.DisplayName = "Test App"
	}
	a.TenantID = testTenant
	a.CreatedAt = st.Now()
	if err := st.CreateApp(a); err != nil {
		t.Fatalf("CreateApp(%s): %v", a.ID, err)
	}
	return a
}

func makeUser(t *testing.T, st *store.Store, id string, given, surname string) *store.User {
	t.Helper()
	u := &store.User{
		ID: id, TenantID: testTenant,
		UserPrincipalName: id + "@example.com",
		DisplayName:       "User " + id,
		GivenName:         given, Surname: surname,
		Mail:           id + "@example.com",
		AccountEnabled: true, CreatedAt: st.Now(),
	}
	if err := st.CreateUser(u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return u
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// ---- PairwiseSub / clientInfo / issuerForTenant ----

func TestPairwiseSubAndClientInfo(t *testing.T) {
	_, svc, _ := newService(t)

	a := svc.PairwiseSub("user1", "app1", "")
	b := svc.PairwiseSub("user1", "app1", testTenant) // "" resolves to home
	if a != b {
		t.Fatalf("PairwiseSub not stable across empty/home tenant: %s vs %s", a, b)
	}
	if svc.PairwiseSub("user2", "app1", "") == a {
		t.Fatal("PairwiseSub should differ per user")
	}

	ci := svc.clientInfo("user1", "")
	raw, err := base64.RawURLEncoding.DecodeString(ci)
	if err != nil {
		t.Fatalf("clientInfo not base64url: %v", err)
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["uid"] != "user1" || m["utid"] != testTenant {
		t.Fatalf("clientInfo payload = %v", m)
	}
}

func TestIssuerForTenant(t *testing.T) {
	_, svc, _ := newService(t)
	if got := svc.issuerForTenant(testTenant); got != svc.Cfg.Issuer {
		t.Fatalf("home issuer = %s, want %s", got, svc.Cfg.Issuer)
	}
	want := svc.Cfg.Origins.Login + "/" + otherTenant + "/v2.0"
	if got := svc.issuerForTenant(otherTenant); got != want {
		t.Fatalf("non-home issuer = %s, want %s", got, want)
	}
}

// ---- BuildDelegatedResponse (id + access + refresh) ----

func TestBuildDelegatedResponseFull(t *testing.T) {
	st, svc, _ := newService(t)
	app := makeApp(t, st, &store.App{ID: "app-deleg"})
	user := makeUser(t, st, "user-deleg", "Ada", "Lovelace")

	g := DelegatedGrant{
		App: app, User: user,
		Scopes: []string{"openid", "profile", "offline_access", "User.Read"},
		Nonce:  "nonce123", AMR: "pwd",
	}
	resp, err := svc.BuildDelegatedResponse(g)
	if err != nil {
		t.Fatal(err)
	}
	if resp.AccessToken == "" || resp.IDToken == "" || resp.RefreshToken == "" {
		t.Fatalf("missing tokens: %+v", resp)
	}
	if resp.ClientInfo == "" || resp.TokenType != "Bearer" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if resp.Scope != "openid profile offline_access User.Read" {
		t.Fatalf("scope echo = %q", resp.Scope)
	}

	// Access token validates against the Graph audience.
	vt, err := svc.ValidateAccessToken(resp.AccessToken, []string{svc.Cfg.GraphResourceID})
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if vt.OID != user.ID {
		t.Fatalf("oid = %q", vt.OID)
	}
	if !hasScope(vt.Scopes, "User.Read") {
		t.Fatalf("scopes = %v", vt.Scopes)
	}

	// ID token carries nonce, amr, email, name.
	idClaims, err := DecodeUnverified(resp.IDToken)
	if err != nil {
		t.Fatal(err)
	}
	if idClaims["nonce"] != "nonce123" {
		t.Fatalf("nonce = %v", idClaims["nonce"])
	}
	if idClaims["email"] != user.Mail {
		t.Fatalf("email = %v", idClaims["email"])
	}
	amr, _ := idClaims["amr"].([]any)
	if len(amr) != 1 || amr[0] != "pwd" {
		t.Fatalf("amr = %v", idClaims["amr"])
	}

	// The refresh token is redeemable.
	if _, err := svc.RedeemRefreshToken(resp.RefreshToken, app.ID, nil); err != nil {
		t.Fatalf("issued refresh token not redeemable: %v", err)
	}
}

func TestBuildDelegatedResponseNoOptionalTokens(t *testing.T) {
	st, svc, _ := newService(t)
	app := makeApp(t, st, &store.App{ID: "app-min"})
	user := makeUser(t, st, "user-min", "", "") // no given/surname -> email still set

	// No openid, no offline_access -> only access token; resource resolves to Graph.
	resp, err := svc.BuildDelegatedResponse(DelegatedGrant{
		App: app, User: user, Scopes: []string{"User.Read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.IDToken != "" || resp.RefreshToken != "" {
		t.Fatalf("unexpected optional tokens: %+v", resp)
	}

	// SkipRefreshToken path: offline_access present but suppressed.
	resp2, err := svc.BuildDelegatedResponse(DelegatedGrant{
		App: app, User: user, Scopes: []string{"openid", "offline_access"},
		SkipRefreshToken: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp2.RefreshToken != "" {
		t.Fatal("SkipRefreshToken should suppress refresh token")
	}
	if resp2.IDToken == "" {
		t.Fatal("expected id token for openid scope")
	}
}

// mintAccessDelegated resolves a non-Graph resource app (by URI and by ID) to
// source access-token optional claims.
func TestMintAccessDelegatedResourceApp(t *testing.T) {
	st, svc, _ := newService(t)
	clientApp := makeApp(t, st, &store.App{ID: "client-app"})
	resourceApp := makeApp(t, st, &store.App{
		ID: "resource-app", AppIDURI: "api://myapi",
		OptionalClaims: `{"accessToken":[{"name":"upn"}]}`,
	})
	user := makeUser(t, st, "u-res", "Grace", "Hopper")

	// Audience by app-id URI.
	resp, err := svc.BuildDelegatedResponse(DelegatedGrant{
		App: clientApp, User: user, Scopes: []string{"access_as_user"},
		Resource: resourceApp.AppIDURI,
	})
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := DecodeUnverified(resp.AccessToken)
	if claims["upn"] != user.UserPrincipalName {
		t.Fatalf("expected upn from resource app optional claims, got %v", claims["upn"])
	}
	if claims["aud"] != "api://myapi" {
		t.Fatalf("aud = %v", claims["aud"])
	}

	// Audience by app id (GetApp branch).
	resp2, err := svc.BuildDelegatedResponse(DelegatedGrant{
		App: clientApp, User: user, Scopes: []string{"access_as_user"},
		Resource: resourceApp.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	claims2, _ := DecodeUnverified(resp2.AccessToken)
	if claims2["upn"] != user.UserPrincipalName {
		t.Fatalf("GetApp branch: upn = %v", claims2["upn"])
	}
}

// ---- BuildAppOnlyResponse (home + non-home tenant) ----

func TestBuildAppOnlyResponse(t *testing.T) {
	st, svc, _ := newService(t)
	app := makeApp(t, st, &store.App{ID: "daemon-app"})

	resp, err := svc.BuildAppOnlyResponse(app, svc.Cfg.GraphResourceID,
		[]string{"Mail.Read"}, "https://graph.microsoft.com/.default", "")
	if err != nil {
		t.Fatal(err)
	}
	if resp.AccessToken == "" || resp.Scope != "https://graph.microsoft.com/.default" {
		t.Fatalf("bad app-only response: %+v", resp)
	}
	vt, err := svc.ValidateAccessToken(resp.AccessToken, []string{svc.Cfg.GraphResourceID})
	if err != nil {
		t.Fatalf("validate app-only: %v", err)
	}
	if vt.OID != "" {
		t.Fatal("app-only token should have no oid")
	}
	if vt.Claims["appid"] != app.ID {
		t.Fatalf("appid = %v", vt.Claims["appid"])
	}
}

func TestBuildAppOnlyResponseNonHomeTenant(t *testing.T) {
	st, svc, _ := newService(t)
	if err := st.EnsureTenant(otherTenant, svc.Cfg.Origins.Login+"/"+otherTenant+"/v2.0"); err != nil {
		t.Fatal(err)
	}
	// App is created under the home tenant row constraints; only the token's
	// issuing tenant differs.
	app := makeApp(t, st, &store.App{ID: "multi-tenant-app"})

	resp, err := svc.BuildAppOnlyResponse(app, svc.Cfg.GraphResourceID,
		[]string{"Directory.Read.All"}, ".default", otherTenant)
	if err != nil {
		t.Fatalf("BuildAppOnlyResponse non-home: %v", err)
	}
	claims, _ := DecodeUnverified(resp.AccessToken)
	if claims["tid"] != otherTenant {
		t.Fatalf("tid = %v, want %s", claims["tid"], otherTenant)
	}
	if claims["iss"] != svc.issuerForTenant(otherTenant) {
		t.Fatalf("iss = %v", claims["iss"])
	}
	// Token validates as the non-home tenant's issuer.
	if _, err := svc.ValidateAccessToken(resp.AccessToken, []string{svc.Cfg.GraphResourceID}); err != nil {
		t.Fatalf("validate non-home: %v", err)
	}

	// signerForTenant caches the non-home signer (second call hits the cache).
	s1, err := svc.SignerForTenant(otherTenant)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := svc.SignerForTenant(otherTenant)
	if err != nil {
		t.Fatal(err)
	}
	if s1 != s2 {
		t.Fatal("signerForTenant should cache the non-home signer")
	}
	// Home tenant returns the primary signer.
	if hs, _ := svc.SignerForTenant(testTenant); hs != svc.Signer {
		t.Fatal("home SignerForTenant should return primary signer")
	}
}

// ---- applyTokenConfig: optional + group claims ----

func TestApplyTokenConfigOptionalAndGroups(t *testing.T) {
	st, svc, _ := newService(t)
	app := makeApp(t, st, &store.App{
		ID: "claims-app",
		// "bogus" is unsupported and must be ignored.
		OptionalClaims:        `{"idToken":[{"name":"given_name"},{"name":"family_name"},{"name":"upn"},{"name":"ipaddr"},{"name":"bogus"}]}`,
		GroupMembershipClaims: "SecurityGroup",
	})
	user := makeUser(t, st, "u-claims", "Alan", "Turing")

	grp := &store.Group{ID: "grp-1", TenantID: testTenant, DisplayName: "Engineers", CreatedAt: st.Now()}
	if err := st.CreateGroup(grp); err != nil {
		t.Fatal(err)
	}
	if err := st.AddGroupMember(grp.ID, user.ID); err != nil {
		t.Fatal(err)
	}

	resp, err := svc.BuildDelegatedResponse(DelegatedGrant{
		App: app, User: user, Scopes: []string{"openid"},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := DecodeUnverified(resp.IDToken)
	if c["given_name"] != "Alan" || c["family_name"] != "Turing" {
		t.Fatalf("name claims = %v / %v", c["given_name"], c["family_name"])
	}
	if c["upn"] != user.UserPrincipalName || c["ipaddr"] != "127.0.0.1" {
		t.Fatalf("upn/ipaddr = %v / %v", c["upn"], c["ipaddr"])
	}
	if _, ok := c["bogus"]; ok {
		t.Fatal("unsupported optional claim should not be emitted")
	}
	groups, ok := c["groups"].([]any)
	if !ok || len(groups) != 1 || groups[0] != "grp-1" {
		t.Fatalf("groups = %v", c["groups"])
	}
}

func TestApplyTokenConfigGroupOverage(t *testing.T) {
	st, svc, _ := newService(t)
	app := makeApp(t, st, &store.App{
		ID:                    "overage-app",
		GroupMembershipClaims: "All",
		GroupOverageLimit:     1,
	})
	user := makeUser(t, st, "u-over", "", "")
	for _, id := range []string{"g-a", "g-b"} {
		if err := st.CreateGroup(&store.Group{ID: id, TenantID: testTenant, DisplayName: id, CreatedAt: st.Now()}); err != nil {
			t.Fatal(err)
		}
		if err := st.AddGroupMember(id, user.ID); err != nil {
			t.Fatal(err)
		}
	}

	resp, err := svc.BuildDelegatedResponse(DelegatedGrant{
		App: app, User: user, Scopes: []string{"openid"},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := DecodeUnverified(resp.IDToken)
	if _, ok := c["groups"]; ok {
		t.Fatal("overage should replace groups list with source pointer")
	}
	names, ok := c["_claim_names"].(map[string]any)
	if !ok || names["groups"] != "src1" {
		t.Fatalf("_claim_names = %v", c["_claim_names"])
	}
	if _, ok := c["_claim_sources"]; !ok {
		t.Fatal("expected _claim_sources for overage")
	}
}

// groups requested purely via the optional "groups" claim (no
// GroupMembershipClaims configured).
func TestApplyTokenConfigGroupsViaOptionalClaim(t *testing.T) {
	st, svc, _ := newService(t)
	app := makeApp(t, st, &store.App{
		ID:             "groups-optional-app",
		OptionalClaims: `{"accessToken":[{"name":"groups"}]}`,
	})
	user := makeUser(t, st, "u-go", "", "")
	if err := st.CreateGroup(&store.Group{ID: "og-1", TenantID: testTenant, DisplayName: "og", CreatedAt: st.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddGroupMember("og-1", user.ID); err != nil {
		t.Fatal(err)
	}

	resp, err := svc.BuildDelegatedResponse(DelegatedGrant{
		App: app, User: user, Scopes: []string{"User.Read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := DecodeUnverified(resp.AccessToken)
	groups, ok := c["groups"].([]any)
	if !ok || len(groups) != 1 {
		t.Fatalf("groups via optional claim = %v", c["groups"])
	}
}

// ---- enrich (ClaimsEnricher) ----

func TestEnrich(t *testing.T) {
	st, svc, _ := newService(t)
	app := makeApp(t, st, &store.App{ID: "enrich-app"})
	user := makeUser(t, st, "u-enrich", "E", "R")

	svc.ClaimsEnricher = func(a *store.App, u *store.User, kind string) map[string]any {
		return map[string]any{
			"custom_claim": "hello-" + kind,
			"sub":          "HIJACKED", // protected: must be ignored
		}
	}
	resp, err := svc.BuildDelegatedResponse(DelegatedGrant{
		App: app, User: user, Scopes: []string{"openid", "User.Read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := DecodeUnverified(resp.IDToken)
	if c["custom_claim"] != "hello-idToken" {
		t.Fatalf("custom_claim = %v", c["custom_claim"])
	}
	if c["sub"] == "HIJACKED" {
		t.Fatal("enricher must not override protected sub claim")
	}
	ac, _ := DecodeUnverified(resp.AccessToken)
	if ac["custom_claim"] != "hello-accessToken" {
		t.Fatalf("access custom_claim = %v", ac["custom_claim"])
	}

	// nil enricher is a no-op.
	svc.ClaimsEnricher = nil
	claims := map[string]any{"x": 1}
	svc.enrich(claims, app, user, "idToken")
	if len(claims) != 1 {
		t.Fatal("nil enricher must not modify claims")
	}
}

// ---- MintSystemToken ----

func TestMintSystemToken(t *testing.T) {
	_, svc, _ := newService(t)
	jwt := svc.MintSystemToken("https://webhook.example")
	c, err := DecodeUnverified(jwt)
	if err != nil {
		t.Fatal(err)
	}
	if c["sub"] != "entra-emulator-system" || c["aud"] != "https://webhook.example" {
		t.Fatalf("system token claims = %v", c)
	}
	if c["idtyp"] != "app" || c["iss"] != svc.Cfg.Issuer {
		t.Fatalf("system token iss/idtyp = %v / %v", c["iss"], c["idtyp"])
	}
}

// ---- Rotate + ActiveKid ----

func TestRotate(t *testing.T) {
	st, svc, _ := newService(t)
	old := svc.ActiveKid()

	newKid, err := svc.Rotate(600)
	if err != nil {
		t.Fatal(err)
	}
	if newKid == old || newKid != svc.ActiveKid() {
		t.Fatalf("Rotate kid = %s, old = %s, active = %s", newKid, old, svc.ActiveKid())
	}
	// Both old and new keys are still publishable within the grace window.
	raw, err := JWKS(st, testTenant)
	if err != nil {
		t.Fatal(err)
	}
	var set struct {
		Keys []map[string]string `json:"keys"`
	}
	_ = json.Unmarshal(raw, &set)
	if len(set.Keys) < 2 {
		t.Fatalf("expected old+new keys in JWKS during grace, got %d", len(set.Keys))
	}
}

// ---- ValidateAccessToken error paths ----

func TestValidateAccessTokenErrors(t *testing.T) {
	_, svc, nowp := newService(t)
	now := *nowp
	kid := svc.Signer.Kid
	sign := func(claims map[string]any) string {
		j, err := SignRS256(svc.Signer.PrivateKey, kid, claims)
		if err != nil {
			t.Fatal(err)
		}
		return j
	}
	auds := []string{"api://aud"}
	good := map[string]any{
		"iss": svc.Cfg.Issuer, "tid": testTenant, "aud": "api://aud",
		"exp": now + 3600, "nbf": now, "iat": now, "oid": "o", "sub": "s",
		"scp": "User.Read",
	}
	// Sanity: the good token validates and exposes scope/oid/sub.
	vt, err := svc.ValidateAccessToken(sign(good), auds)
	if err != nil {
		t.Fatalf("good token: %v", err)
	}
	if vt.OID != "o" || vt.Sub != "s" || !hasScope(vt.Scopes, "User.Read") {
		t.Fatalf("validated token fields = %+v", vt)
	}

	clone := func(mut func(m map[string]any)) map[string]any {
		m := map[string]any{}
		for k, v := range good {
			m[k] = v
		}
		mut(m)
		return m
	}

	cases := []struct {
		name  string
		token string
		want  string
	}{
		{"malformed", "a.b", "malformed token"},
		{"bad-header-b64", "!!!." + b64url([]byte(`{}`)) + ".sig", "malformed token header"},
		{"unsupported-alg", func() string {
			h := b64url([]byte(`{"alg":"none","kid":"x"}`))
			return h + "." + b64url([]byte(`{}`)) + ".sig"
		}(), "unsupported token algorithm"},
		{"unknown-kid", func() string {
			k, _ := rsa.GenerateKey(rand.Reader, 2048)
			j, _ := SignRS256(k, "no-such-kid", good)
			return j
		}(), "unknown signing key"},
		{"bad-signature", func() string {
			k, _ := rsa.GenerateKey(rand.Reader, 2048)
			j, _ := SignRS256(k, kid, good) // registered kid, wrong key
			return j
		}(), "signature verification failed"},
		{"wrong-issuer", sign(clone(func(m map[string]any) { m["iss"] = "https://evil" })), "wrong issuer"},
		{"empty-tid", sign(clone(func(m map[string]any) { delete(m, "tid") })), "wrong issuer"},
		{"expired", sign(clone(func(m map[string]any) { m["exp"] = now - 3600 })), "token expired"},
		{"not-yet-valid", sign(clone(func(m map[string]any) { m["nbf"] = now + 3600 })), "token not yet valid"},
		{"wrong-aud", sign(clone(func(m map[string]any) { m["aud"] = "api://other" })), "wrong audience"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.ValidateAccessToken(tc.token, auds)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want contains %q", err, tc.want)
			}
		})
	}
}

// ---- Authorization codes ----

func TestAuthCodeLifecycle(t *testing.T) {
	st, svc, nowp := newService(t)
	makeApp(t, st, &store.App{ID: "code-app"})
	makeUser(t, st, "code-user", "", "")

	base := AuthCodeRequest{
		AppID: "code-app", UserID: "code-user",
		RedirectURI: "https://app/cb", Scopes: []string{"openid", "User.Read"},
	}

	// Happy path, no PKCE.
	code, err := svc.IssueAuthCode(base)
	if err != nil {
		t.Fatal(err)
	}
	row, err := svc.RedeemAuthCode(code, "code-app", "https://app/cb", "")
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if row.UserID != "code-user" {
		t.Fatalf("row = %+v", row)
	}
	// Second redeem -> already redeemed.
	if _, err := svc.RedeemAuthCode(code, "code-app", "https://app/cb", ""); err == nil ||
		!strings.Contains(err.Error(), "already redeemed") {
		t.Fatalf("reuse err = %v", err)
	}

	// Not found.
	if _, err := svc.RedeemAuthCode("nope", "code-app", "https://app/cb", ""); err == nil ||
		!strings.Contains(err.Error(), "invalid") {
		t.Fatalf("not-found err = %v", err)
	}

	// Wrong client.
	c2, _ := svc.IssueAuthCode(base)
	if _, err := svc.RedeemAuthCode(c2, "other-app", "https://app/cb", ""); err == nil ||
		!strings.Contains(err.Error(), "different client") {
		t.Fatalf("wrong-client err = %v", err)
	}

	// Wrong redirect.
	c3, _ := svc.IssueAuthCode(base)
	if _, err := svc.RedeemAuthCode(c3, "code-app", "https://evil/cb", ""); err == nil ||
		!strings.Contains(err.Error(), "redirect URI") {
		t.Fatalf("wrong-redirect err = %v", err)
	}

	// Expired.
	c4, _ := svc.IssueAuthCode(base)
	*nowp += int64(svc.Cfg.Lifetimes.AuthCode) + 1
	if _, err := svc.RedeemAuthCode(c4, "code-app", "https://app/cb", ""); err == nil ||
		!strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired err = %v", err)
	}
	*nowp -= int64(svc.Cfg.Lifetimes.AuthCode) + 1
}

func TestAuthCodePKCE(t *testing.T) {
	st, svc, _ := newService(t)
	makeApp(t, st, &store.App{ID: "pkce-app"})
	makeUser(t, st, "pkce-user", "", "")

	verifier := "the-code-verifier-value-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	newCode := func(method, chal string) string {
		c, err := svc.IssueAuthCode(AuthCodeRequest{
			AppID: "pkce-app", UserID: "pkce-user", RedirectURI: "https://app/cb",
			Scopes: []string{"openid"}, CodeChallenge: chal, ChallengeMethod: method,
		})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	// S256 happy path.
	if _, err := svc.RedeemAuthCode(newCode("S256", challenge), "pkce-app", "https://app/cb", verifier); err != nil {
		t.Fatalf("S256 redeem: %v", err)
	}
	// Missing verifier.
	if _, err := svc.RedeemAuthCode(newCode("S256", challenge), "pkce-app", "https://app/cb", ""); err == nil ||
		!strings.Contains(err.Error(), "code_verifier is required") {
		t.Fatalf("missing verifier err = %v", err)
	}
	// Wrong verifier.
	if _, err := svc.RedeemAuthCode(newCode("S256", challenge), "pkce-app", "https://app/cb", "wrong"); err == nil ||
		!strings.Contains(err.Error(), "does not match") {
		t.Fatalf("bad verifier err = %v", err)
	}
	// plain method.
	if _, err := svc.RedeemAuthCode(newCode("plain", verifier), "pkce-app", "https://app/cb", verifier); err != nil {
		t.Fatalf("plain redeem: %v", err)
	}
}

// ---- Refresh tokens ----

func TestRefreshTokenRotationAndReuse(t *testing.T) {
	st, svc, nowp := newService(t)
	makeApp(t, st, &store.App{ID: "rt-app"})
	makeUser(t, st, "rt-user", "", "")

	rt, err := svc.IssueRefreshToken("rt-app", "rt-user",
		[]string{"openid", "offline_access", "User.Read"}, "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Rotate: get a successor because offline_access is kept.
	red, err := svc.RedeemRefreshToken(rt, "rt-app", nil)
	if err != nil {
		t.Fatal(err)
	}
	if red.NewRefreshToken == "" || red.UserID != "rt-user" {
		t.Fatalf("rotation result = %+v", red)
	}

	// Reusing the original (now revoked) token revokes the whole family.
	if _, err := svc.RedeemRefreshToken(rt, "rt-app", nil); err == nil ||
		!strings.Contains(err.Error(), "reuse detected") {
		t.Fatalf("reuse err = %v", err)
	}
	// The successor is now revoked too (family revocation).
	if _, err := svc.RedeemRefreshToken(red.NewRefreshToken, "rt-app", nil); err == nil ||
		!strings.Contains(err.Error(), "reuse detected") {
		t.Fatalf("successor should be revoked: %v", err)
	}

	// Scope narrowing to a valid subset.
	rt2, _ := svc.IssueRefreshToken("rt-app", "rt-user",
		[]string{"openid", "offline_access", "User.Read", "Mail.Read"}, "", "")
	red2, err := svc.RedeemRefreshToken(rt2, "rt-app", []string{"openid", "User.Read"})
	if err != nil {
		t.Fatalf("subset redeem: %v", err)
	}
	if len(red2.Scopes) != 2 {
		t.Fatalf("narrowed scopes = %v", red2.Scopes)
	}
	// Without offline_access in the narrowed set, no successor is issued.
	if red2.NewRefreshToken != "" {
		t.Fatal("no offline_access -> no successor")
	}

	// Requesting a scope outside the grant -> invalid_scope.
	rt3, _ := svc.IssueRefreshToken("rt-app", "rt-user", []string{"User.Read"}, "", "")
	if _, err := svc.RedeemRefreshToken(rt3, "rt-app", []string{"Files.ReadWrite"}); err == nil ||
		!strings.Contains(err.Error(), "invalid_scope") {
		t.Fatalf("invalid_scope err = %v", err)
	}

	// Not found.
	if _, err := svc.RedeemRefreshToken("does-not-exist", "rt-app", nil); err == nil ||
		!strings.Contains(err.Error(), "invalid") {
		t.Fatalf("not-found err = %v", err)
	}

	// Wrong client.
	rt4, _ := svc.IssueRefreshToken("rt-app", "rt-user", []string{"User.Read"}, "", "")
	makeApp(t, st, &store.App{ID: "rt-app-other"})
	if _, err := svc.RedeemRefreshToken(rt4, "rt-app-other", nil); err == nil ||
		!strings.Contains(err.Error(), "different client") {
		t.Fatalf("wrong-client err = %v", err)
	}

	// Expired.
	rt5, _ := svc.IssueRefreshToken("rt-app", "rt-user", []string{"User.Read"}, "", "")
	*nowp += int64(svc.Cfg.Lifetimes.RefreshToken) + 1
	if _, err := svc.RedeemRefreshToken(rt5, "rt-app", nil); err == nil ||
		!strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired err = %v", err)
	}
	*nowp -= int64(svc.Cfg.Lifetimes.RefreshToken) + 1
}

// ---- RedeemErr ----

func TestRedeemErrError(t *testing.T) {
	e := &RedeemErr{Code: "invalid_grant", Description: "boom"}
	if e.Error() != "invalid_grant: boom" {
		t.Fatalf("Error() = %q", e.Error())
	}
}

// ---- scopeNamesOnly ----

func TestScopeNamesOnly(t *testing.T) {
	// Resource scopes: OIDC scopes stripped, resource prefix removed.
	got := scopeNamesOnly([]string{"openid", "profile", "offline_access",
		"api://resource/access_as_user", "User.Read"})
	if strings.Join(got, " ") != "access_as_user User.Read" {
		t.Fatalf("resource scopes = %v", got)
	}
	// OIDC-only grant: falls back to OIDC scopes (minus offline_access).
	got2 := scopeNamesOnly([]string{"openid", "profile", "offline_access"})
	if strings.Join(got2, " ") != "openid profile" {
		t.Fatalf("oidc-only = %v", got2)
	}
}

// ---- VerifyClientAssertion ----

func rsaPKIXPEM(t *testing.T, pub *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func TestVerifyClientAssertion(t *testing.T) {
	const clientID = "client-abc"
	const tokenEndpoint = "https://login/token"
	now := int64(1_700_000_000)

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemStr := rsaPKIXPEM(t, &key.PublicKey)
	keys := []string{"garbage-not-pem", pemStr} // first entry exercises the parse-error continue
	auds := []string{tokenEndpoint}

	mkAssertion := func(k *rsa.PrivateKey, claims map[string]any) string {
		j, err := SignRS256(k, "cred-kid", claims)
		if err != nil {
			t.Fatal(err)
		}
		return j
	}
	goodClaims := map[string]any{
		"iss": clientID, "sub": clientID, "aud": tokenEndpoint,
		"exp": now + 300, "nbf": now, "iat": now, "jti": "j1",
	}

	// Happy path.
	if err := VerifyClientAssertion(mkAssertion(key, goodClaims), clientID, keys, auds, now); err != nil {
		t.Fatalf("happy path: %v", err)
	}

	clone := func(mut func(m map[string]any)) map[string]any {
		m := map[string]any{}
		for k, v := range goodClaims {
			m[k] = v
		}
		mut(m)
		return m
	}

	// No registered keys.
	if err := VerifyClientAssertion(mkAssertion(key, goodClaims), clientID, nil, auds, now); err == nil ||
		!strings.Contains(err.Error(), "no registered key") {
		t.Fatalf("no-keys err = %v", err)
	}

	// Signature from an unregistered key.
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	if err := VerifyClientAssertion(mkAssertion(otherKey, goodClaims), clientID, keys, auds, now); err == nil ||
		!strings.Contains(err.Error(), "does not match") {
		t.Fatalf("bad-sig err = %v", err)
	}

	// iss/sub != clientID.
	if err := VerifyClientAssertion(mkAssertion(key, clone(func(m map[string]any) { m["iss"] = "someone-else" })),
		clientID, keys, auds, now); err == nil || !strings.Contains(err.Error(), "iss/sub") {
		t.Fatalf("iss err = %v", err)
	}

	// Expired.
	if err := VerifyClientAssertion(mkAssertion(key, clone(func(m map[string]any) { m["exp"] = now - 1000 })),
		clientID, keys, auds, now); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired err = %v", err)
	}

	// Not yet valid.
	if err := VerifyClientAssertion(mkAssertion(key, clone(func(m map[string]any) { m["nbf"] = now + 1000 })),
		clientID, keys, auds, now); err == nil || !strings.Contains(err.Error(), "not yet valid") {
		t.Fatalf("nbf err = %v", err)
	}

	// Wrong audience.
	if err := VerifyClientAssertion(mkAssertion(key, clone(func(m map[string]any) { m["aud"] = "https://evil/token" })),
		clientID, keys, auds, now); err == nil || !strings.Contains(err.Error(), "not an accepted") {
		t.Fatalf("aud err = %v", err)
	}
}

// ---- parsePublicKeyPEM: non-RSA branches ----

func TestParsePublicKeyPEMNonRSA(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// PKIX EC public key -> "public key is not RSA".
	der, _ := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	ecPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if _, err := parsePublicKeyPEM(ecPEM); err == nil || !strings.Contains(err.Error(), "not RSA") {
		t.Fatalf("EC PKIX err = %v", err)
	}

	// EC certificate -> "certificate is not RSA".
	tmpl := &x509.Certificate{SerialNumber: bigOne(), Subject: pkix.Name{CommonName: "ec"}}
	cder, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ecKey.PublicKey, ecKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cder}))
	if _, err := parsePublicKeyPEM(certPEM); err == nil || !strings.Contains(err.Error(), "not RSA") {
		t.Fatalf("EC cert err = %v", err)
	}

	// Malformed certificate bytes.
	badCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-a-cert")}))
	if _, err := parsePublicKeyPEM(badCert); err == nil {
		t.Fatal("malformed certificate should error")
	}
	// Malformed PKIX bytes.
	badPKIX := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("not-a-key")}))
	if _, err := parsePublicKeyPEM(badPKIX); err == nil {
		t.Fatal("malformed PKIX should error")
	}
}

// ---- parsePrivatePEM: non-RSA PKCS8 branch ----

func TestParsePrivatePEMNonRSA(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	ecPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if _, err := parsePrivatePEM(ecPEM); err == nil || !strings.Contains(err.Error(), "not an RSA") {
		t.Fatalf("EC PKCS8 err = %v", err)
	}
}

// ---- low-level JWT decode/verify error branches ----

func TestVerifyRS256AndDecodeUnverifiedErrors(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Malformed (not 3 parts).
	if _, err := VerifyRS256(&key.PublicKey, "a.b"); err == nil {
		t.Fatal("VerifyRS256 should reject malformed token")
	}
	if _, err := DecodeUnverified("a.b"); err == nil {
		t.Fatal("DecodeUnverified should reject malformed token")
	}

	// Bad signature encoding (part[2] not base64url).
	if _, err := VerifyRS256(&key.PublicKey, "h.p.@@@"); err == nil ||
		!strings.Contains(err.Error(), "bad signature encoding") {
		t.Fatalf("bad sig encoding err = %v", err)
	}

	// Sign a raw (non-base64) payload so the signature verifies but decoding the
	// payload fails -> "bad payload encoding".
	signRaw := func(header, payload string) string {
		input := header + "." + payload
		sum := sha256.Sum256([]byte(input))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		return input + "." + base64.RawURLEncoding.EncodeToString(sig)
	}
	if _, err := VerifyRS256(&key.PublicKey, signRaw("h", "@@@")); err == nil ||
		!strings.Contains(err.Error(), "bad payload encoding") {
		t.Fatalf("bad payload encoding err = %v", err)
	}
	// Valid base64 payload that is not JSON -> "bad payload JSON".
	notJSON := base64.RawURLEncoding.EncodeToString([]byte("not-json"))
	if _, err := VerifyRS256(&key.PublicKey, signRaw("h", notJSON)); err == nil ||
		!strings.Contains(err.Error(), "bad payload JSON") {
		t.Fatalf("bad payload JSON err = %v", err)
	}

	// DecodeUnverified with a non-base64 payload.
	if _, err := DecodeUnverified("h.@@@.s"); err == nil {
		t.Fatal("DecodeUnverified should reject bad base64 payload")
	}
	// DecodeUnverified with valid base64 but non-JSON payload.
	if _, err := DecodeUnverified("h." + notJSON + ".s"); err == nil {
		t.Fatal("DecodeUnverified should reject non-JSON payload")
	}
}

// ---- EnsureActiveKey / generateAndActivate error (FK violation) ----

func TestEnsureActiveKeyInsertError(t *testing.T) {
	st := newStore(t)
	// Tenant row does not exist -> InsertSigningKey violates the FK.
	if _, err := EnsureActiveKey(st, "99999999-9999-9999-9999-999999999999"); err == nil {
		t.Fatal("EnsureActiveKey should fail when the tenant does not exist")
	}
}

// ---- VerificationKey: malformed persisted JWK ----

func TestVerificationKeyMalformedJWK(t *testing.T) {
	st := newStore(t)
	insert := func(kid, jwk string) {
		if err := st.InsertSigningKey(&store.SigningKey{
			Kid: kid, TenantID: testTenant, Alg: "RS256",
			PublicJWK: jwk, PrivatePKCS8: "unused", CreatedAt: st.Now(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	insert("bad-json", "not json")
	insert("bad-n", `{"kty":"RSA","n":"@@@","e":"AQAB"}`)
	insert("bad-e", `{"kty":"RSA","n":"AQAB","e":"@@@"}`)

	for _, kid := range []string{"bad-json", "bad-n", "bad-e"} {
		if _, err := VerificationKey(st, kid); err == nil {
			t.Fatalf("VerificationKey(%s) should error on malformed JWK", kid)
		}
	}
}

// ---- EnsureActiveKey / parsePrivatePEM: corrupt persisted private key ----

func TestEnsureActiveKeyCorruptPersistedKey(t *testing.T) {
	st := newStore(t)
	// An active key whose PEM has no decodable block.
	if err := st.InsertSigningKey(&store.SigningKey{
		Kid: "corrupt", TenantID: testTenant, Alg: "RS256",
		PublicJWK: "{}", PrivatePKCS8: "-----garbage-----", IsActive: true, CreatedAt: st.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureActiveKey(st, testTenant); err == nil {
		t.Fatal("EnsureActiveKey should fail parsing a corrupt persisted key")
	}

	// parsePrivatePEM: valid PEM block, invalid PKCS8 bytes.
	badPKCS8 := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not-pkcs8")}))
	if _, err := parsePrivatePEM(badPKCS8); err == nil {
		t.Fatal("parsePrivatePEM should reject invalid PKCS8 bytes")
	}
}

// ---- store-failure error branches (closed DB) ----

func TestServiceStoreErrorPaths(t *testing.T) {
	st, svc, _ := newService(t)
	app := &store.App{ID: "closed-app", TenantID: testTenant}
	user := &store.User{ID: "closed-user", TenantID: testTenant, UserPrincipalName: "c@x", DisplayName: "C"}

	// Close the underlying DB so every store call now errors.
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if _, err := svc.Rotate(60); err == nil {
		t.Fatal("Rotate should fail on a closed store")
	}
	if _, err := svc.IssueAuthCode(AuthCodeRequest{AppID: app.ID, UserID: user.ID}); err == nil {
		t.Fatal("IssueAuthCode should fail on a closed store")
	}
	if _, err := svc.RedeemAuthCode("code", app.ID, "r", ""); err == nil {
		t.Fatal("RedeemAuthCode should surface a store error")
	}
	if _, err := svc.IssueRefreshToken(app.ID, user.ID, []string{"openid"}, "", ""); err == nil {
		t.Fatal("IssueRefreshToken should fail on a closed store")
	}
	if _, err := svc.RedeemRefreshToken("plain", app.ID, nil); err == nil {
		t.Fatal("RedeemRefreshToken should surface a store error")
	}
	if _, err := svc.SignerForTenant(otherTenant); err == nil {
		t.Fatal("SignerForTenant should fail loading a non-home key on a closed store")
	}
	if _, err := svc.BuildAppOnlyResponse(app, svc.Cfg.GraphResourceID, []string{"r"}, "", otherTenant); err == nil {
		t.Fatal("BuildAppOnlyResponse should fail signing for a non-home tenant on a closed store")
	}
	if _, err := svc.BuildDelegatedResponse(DelegatedGrant{App: app, User: user, Scopes: []string{"User.Read"}, TenantID: otherTenant}); err == nil {
		t.Fatal("BuildDelegatedResponse should fail signing for a non-home tenant on a closed store")
	}
	if _, err := JWKS(st, testTenant); err == nil {
		t.Fatal("JWKS should fail on a closed store")
	}
	if _, err := VerificationKey(st, "some-kid"); err == nil {
		t.Fatal("VerificationKey should fail on a closed store")
	}

	// Home-tenant mint still signs in-memory, but applyTokenConfig's group
	// lookup fails against the closed store and is swallowed (no groups claim).
	groupApp := &store.App{ID: "grp-closed", TenantID: testTenant, GroupMembershipClaims: "All"}
	resp, err := svc.BuildDelegatedResponse(DelegatedGrant{App: groupApp, User: user, Scopes: []string{"openid"}})
	if err != nil {
		t.Fatalf("home mint should still succeed: %v", err)
	}
	c, _ := DecodeUnverified(resp.IDToken)
	if _, ok := c["groups"]; ok {
		t.Fatal("group lookup failure should leave the groups claim unset")
	}
}
