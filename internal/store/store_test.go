package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const (
	testTenantID = "11111111-1111-1111-1111-111111111111"
	testIssuer   = "https://issuer/11111111-1111-1111-1111-111111111111/v2.0"
)

// newTestStore opens a fresh store with the test tenant ensured.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.EnsureTenant(testTenantID, testIssuer); err != nil {
		t.Fatalf("EnsureTenant: %v", err)
	}
	return st
}

// seededStore returns a store with the full deterministic seed applied.
func seededStore(t *testing.T) *Store {
	t.Helper()
	st := newTestStore(t)
	if _, err := st.Seed(testTenantID, testIssuer); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	return st
}

func mustUser(t *testing.T, st *Store, upn string) *User {
	t.Helper()
	u := &User{
		ID:                NewGUID(),
		TenantID:          testTenantID,
		UserPrincipalName: upn,
		DisplayName:       "Test " + upn,
		GivenName:         "Test",
		Surname:           "User",
		Mail:              upn,
		AccountEnabled:    true,
		CreatedAt:         st.Now(),
	}
	hash, err := HashSecret("Password1!")
	if err != nil {
		t.Fatal(err)
	}
	u.PasswordHash = hash
	if err := st.CreateUser(u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return u
}

func mustApp(t *testing.T, st *Store, name string) *App {
	t.Helper()
	a := &App{
		ID:                    NewGUID(),
		TenantID:              testTenantID,
		DisplayName:           name,
		IsConfidential:        true,
		GroupMembershipClaims: "None",
		CreatedAt:             st.Now(),
	}
	if err := st.CreateApp(a); err != nil {
		t.Fatalf("CreateApp: %v", err)
	}
	return a
}

func mustGroup(t *testing.T, st *Store, name string) *Group {
	t.Helper()
	g := &Group{
		ID:          NewGUID(),
		TenantID:    testTenantID,
		DisplayName: name,
		Description: "desc",
		CreatedAt:   st.Now(),
	}
	if err := st.CreateGroup(g); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	return g
}

// ---- Open / migrate ----

func TestOpenAndMigrateIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", "store.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("Open with nested dir: %v", err)
	}
	// Re-running migrate is idempotent (schema + additive ALTERs already present).
	if err := st.migrate(); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopening an existing DB re-applies the additive migrations harmlessly.
	st2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	st2.Close()
}

func TestOpenBadPath(t *testing.T) {
	// Create a regular file, then try to open a DB path *under* it. MkdirAll
	// on a path whose ancestor is a file must fail → Open returns an error.
	f := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	badPath := filepath.Join(f, "child", "store.db")
	if _, err := Open(badPath); err == nil {
		t.Fatal("Open should fail when an ancestor path is a file")
	}
}

// ---- Tenants ----

func TestTenantLifecycle(t *testing.T) {
	st := newTestStore(t)

	// Home tenant is the one EnsureTenant created.
	home, err := st.GetTenant()
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if home.ID != testTenantID || home.Issuer != testIssuer {
		t.Fatalf("unexpected home tenant: %+v", home)
	}

	// GetTenantByID hit + miss.
	if _, err := st.GetTenantByID(testTenantID); err != nil {
		t.Fatalf("GetTenantByID hit: %v", err)
	}
	if _, err := st.GetTenantByID("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetTenantByID miss = %v, want ErrNotFound", err)
	}

	// EnsureTenant is idempotent (INSERT OR IGNORE).
	if err := st.EnsureTenant(testTenantID, "other"); err != nil {
		t.Fatalf("EnsureTenant idempotent: %v", err)
	}

	// CreateTenant success + duplicate conflict.
	t2 := &Tenant{ID: "22222222-2222-2222-2222-222222222222", DisplayName: "Two",
		Issuer: "https://issuer/two", InitialDomain: "two.onmicrosoft.com", CreatedAt: st.Now() + 1}
	if err := st.CreateTenant(t2); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if err := st.CreateTenant(t2); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate CreateTenant = %v, want ErrConflict", err)
	}

	// ListTenants returns both, home first (ordered by created_at).
	tenants, err := st.ListTenants()
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}
	if len(tenants) != 2 || tenants[0].ID != testTenantID {
		t.Fatalf("ListTenants order = %+v", tenants)
	}
}

func TestGetTenantEmpty(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "empty.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.GetTenant(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetTenant on empty = %v, want ErrNotFound", err)
	}
}

func TestDeleteTenantCascade(t *testing.T) {
	st := seededStore(t)

	// Populate grants so the cascade paths are exercised.
	app, _ := st.GetApp(SeedAppSPAID)
	user, _ := st.GetUser(SeedUserAliceID)
	if err := st.InsertAuthCode(&AuthCode{Code: "c1", AppID: app.ID, UserID: user.ID,
		RedirectURI: "https://localhost:3000", Scopes: "openid", ExpiresAt: st.Now() + 60, CreatedAt: st.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertRefreshToken(&RefreshToken{TokenHash: HashToken("rt"), AppID: app.ID,
		UserID: user.ID, Scopes: "openid", ExpiresAt: st.Now() + 60, CreatedAt: st.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertDeviceCode(&DeviceCode{DeviceCodeHash: HashToken("dc"), UserCode: "USER-CODE",
		AppID: app.ID, Scopes: "openid", Interval: 5, ExpiresAt: st.Now() + 60, CreatedAt: st.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertSigningKey(&SigningKey{Kid: "k1", TenantID: testTenantID,
		PublicJWK: "{}", PrivatePKCS8: "pem", IsActive: true, CreatedAt: st.Now()}); err != nil {
		t.Fatal(err)
	}

	if err := st.DeleteTenant(testTenantID); err != nil {
		t.Fatalf("DeleteTenant: %v", err)
	}
	if _, err := st.GetTenantByID(testTenantID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tenant still present after delete: %v", err)
	}
	// Users/apps gone.
	if _, err := st.GetUser(SeedUserAliceID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("user survived tenant delete: %v", err)
	}

	// Deleting a missing tenant → ErrNotFound.
	if err := st.DeleteTenant("no-such"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteTenant missing = %v, want ErrNotFound", err)
	}
}

// ---- Users ----

func TestUserCRUD(t *testing.T) {
	st := newTestStore(t)
	u := mustUser(t, st, "carol@entraemulator.dev")

	// Get hit + miss.
	got, err := st.GetUser(u.ID)
	if err != nil || got.UserPrincipalName != u.UserPrincipalName {
		t.Fatalf("GetUser: %v %+v", err, got)
	}
	if _, err := st.GetUser("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetUser miss = %v", err)
	}

	// GetUserByUPN (case-insensitive) hit + miss.
	if _, err := st.GetUserByUPN("CAROL@entraemulator.dev"); err != nil {
		t.Fatalf("GetUserByUPN case-insensitive: %v", err)
	}
	if _, err := st.GetUserByUPN("ghost@x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetUserByUPN miss = %v", err)
	}

	// Duplicate UPN → conflict.
	dup := *u
	dup.ID = NewGUID()
	if err := st.CreateUser(&dup); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate UPN = %v, want ErrConflict", err)
	}

	// Update success.
	u.DisplayName = "Carol Renamed"
	u.GivenName = ""
	if err := st.UpdateUser(u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	got, _ = st.GetUser(u.ID)
	if got.DisplayName != "Carol Renamed" || got.GivenName != "" {
		t.Fatalf("update not applied: %+v", got)
	}
	// Update missing → ErrNotFound.
	missing := &User{ID: "nope", UserPrincipalName: "x@x", DisplayName: "x", AccountEnabled: true}
	if err := st.UpdateUser(missing); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateUser missing = %v", err)
	}
	// Update to a taken UPN → conflict.
	other := mustUser(t, st, "dave@entraemulator.dev")
	other.UserPrincipalName = u.UserPrincipalName
	if err := st.UpdateUser(other); !errors.Is(err, ErrConflict) {
		t.Fatalf("UpdateUser conflict = %v", err)
	}

	// Delete success + missing.
	if err := st.DeleteUser(u.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if err := st.DeleteUser(u.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteUser missing = %v", err)
	}
}

func TestDeleteUserClearsGrants(t *testing.T) {
	st := newTestStore(t)
	app := mustApp(t, st, "grant-app")
	u := mustUser(t, st, "grants@x")

	st.InsertAuthCode(&AuthCode{Code: "gc", AppID: app.ID, UserID: u.ID, RedirectURI: "r",
		Scopes: "openid", ExpiresAt: st.Now() + 60, CreatedAt: st.Now()})
	st.InsertRefreshToken(&RefreshToken{TokenHash: HashToken("grt"), AppID: app.ID, UserID: u.ID,
		Scopes: "openid", ExpiresAt: st.Now() + 60, CreatedAt: st.Now()})
	st.InsertDeviceCode(&DeviceCode{DeviceCodeHash: HashToken("gdc"), UserCode: "GC-1", AppID: app.ID,
		UserID: u.ID, Scopes: "openid", Status: "approved", Interval: 5, ExpiresAt: st.Now() + 60, CreatedAt: st.Now()})

	if err := st.DeleteUser(u.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	// Device code kept but user_id nulled.
	d, err := st.GetDeviceCodeByUserCode("GC-1")
	if err != nil {
		t.Fatalf("device code should survive: %v", err)
	}
	if d.UserID != "" {
		t.Fatalf("device code user_id not cleared: %q", d.UserID)
	}
}

func TestListUsersAndSearch(t *testing.T) {
	st := newTestStore(t)
	mustUser(t, st, "aaa@x")
	mustUser(t, st, "bbb@x")
	mustUser(t, st, "abc@x")

	all, count, err := st.ListUsers(10, 0, "")
	if err != nil || count != 3 || len(all) != 3 {
		t.Fatalf("ListUsers all: %v count=%d len=%d", err, count, len(all))
	}
	// Search matches UPN substring.
	hits, count, err := st.ListUsers(10, 0, "ab")
	if err != nil || count != 1 || len(hits) != 1 {
		t.Fatalf("ListUsers search: %v count=%d len=%d", err, count, len(hits))
	}
	// Paging.
	page, _, err := st.ListUsers(1, 1, "")
	if err != nil || len(page) != 1 {
		t.Fatalf("ListUsers paging: %v len=%d", err, len(page))
	}
}

func TestVerifyPassword(t *testing.T) {
	st := newTestStore(t)
	u := mustUser(t, st, "login@x")

	if _, err := st.VerifyPassword("login@x", "Password1!"); err != nil {
		t.Fatalf("valid password: %v", err)
	}
	if _, err := st.VerifyPassword("login@x", "wrong"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong password = %v", err)
	}
	if _, err := st.VerifyPassword("ghost@x", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user = %v", err)
	}
	// Disabled account.
	u.AccountEnabled = false
	if err := st.UpdateUser(u); err != nil {
		t.Fatal(err)
	}
	if _, err := st.VerifyPassword("login@x", "Password1!"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disabled account = %v", err)
	}
	// No password hash set.
	np := mustUser(t, st, "nopass@x")
	np.PasswordHash = ""
	st.UpdateUser(np)
	if _, err := st.VerifyPassword("nopass@x", "anything"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty hash = %v", err)
	}
}

// ---- Groups & membership ----

func TestGroupCRUD(t *testing.T) {
	st := newTestStore(t)
	g := mustGroup(t, st, "Eng")

	if got, err := st.GetGroup(g.ID); err != nil || got.DisplayName != "Eng" {
		t.Fatalf("GetGroup: %v %+v", err, got)
	}
	if _, err := st.GetGroup("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetGroup miss = %v", err)
	}

	g.DisplayName = "Engineering"
	g.Description = ""
	if err := st.UpdateGroup(g); err != nil {
		t.Fatalf("UpdateGroup: %v", err)
	}
	if err := st.UpdateGroup(&Group{ID: "nope", DisplayName: "x"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateGroup missing = %v", err)
	}

	// List + search.
	mustGroup(t, st, "Sales")
	all, count, err := st.ListGroups(10, 0, "")
	if err != nil || count != 2 || len(all) != 2 {
		t.Fatalf("ListGroups: %v count=%d", err, count)
	}
	hits, count, err := st.ListGroups(10, 0, "sale")
	if err != nil || count != 1 || len(hits) != 1 {
		t.Fatalf("ListGroups search: %v count=%d", err, count)
	}

	if err := st.DeleteGroup(g.ID); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}
	if err := st.DeleteGroup(g.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteGroup missing = %v", err)
	}
}

func TestGroupMembership(t *testing.T) {
	st := newTestStore(t)
	g := mustGroup(t, st, "Team")
	u1 := mustUser(t, st, "m1@x")
	u2 := mustUser(t, st, "m2@x")

	if err := st.AddGroupMember(g.ID, u1.ID); err != nil {
		t.Fatalf("AddGroupMember: %v", err)
	}
	// Idempotent.
	if err := st.AddGroupMember(g.ID, u1.ID); err != nil {
		t.Fatalf("AddGroupMember idempotent: %v", err)
	}
	if err := st.AddGroupMember(g.ID, u2.ID); err != nil {
		t.Fatal(err)
	}
	// Missing group / user.
	if err := st.AddGroupMember("no-group", u1.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("AddGroupMember missing group = %v", err)
	}
	if err := st.AddGroupMember(g.ID, "no-user"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("AddGroupMember missing user = %v", err)
	}

	members, err := st.ListGroupMembers(g.ID)
	if err != nil || len(members) != 2 {
		t.Fatalf("ListGroupMembers: %v len=%d", err, len(members))
	}
	if n, err := st.CountGroupMembers(g.ID); err != nil || n != 2 {
		t.Fatalf("CountGroupMembers: %v n=%d", err, n)
	}
	groups, err := st.ListGroupsForUser(u1.ID)
	if err != nil || len(groups) != 1 || groups[0].ID != g.ID {
		t.Fatalf("ListGroupsForUser: %v %+v", err, groups)
	}

	if err := st.RemoveGroupMember(g.ID, u1.ID); err != nil {
		t.Fatalf("RemoveGroupMember: %v", err)
	}
	if n, _ := st.CountGroupMembers(g.ID); n != 1 {
		t.Fatalf("after remove count = %d", n)
	}
	// Removing a non-member is a no-op, not an error.
	if err := st.RemoveGroupMember(g.ID, "ghost"); err != nil {
		t.Fatalf("RemoveGroupMember non-member: %v", err)
	}
}

// ---- Apps ----

func TestAppCRUD(t *testing.T) {
	st := newTestStore(t)
	a := &App{ID: NewGUID(), TenantID: testTenantID, DisplayName: "App", IsConfidential: true,
		AppIDURI: "api://app-one", GroupMembershipClaims: "All", GroupOverageLimit: 100, CreatedAt: st.Now()}
	if err := st.CreateApp(a); err != nil {
		t.Fatalf("CreateApp: %v", err)
	}

	if got, err := st.GetApp(a.ID); err != nil || got.AppIDURI != "api://app-one" {
		t.Fatalf("GetApp: %v %+v", err, got)
	}
	if _, err := st.GetApp("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetApp miss = %v", err)
	}
	if got, err := st.GetAppByIDURI("api://app-one"); err != nil || got.ID != a.ID {
		t.Fatalf("GetAppByIDURI: %v", err)
	}
	if _, err := st.GetAppByIDURI("api://none"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetAppByIDURI miss = %v", err)
	}

	// A second app claiming the same URI → conflict.
	b := &App{ID: NewGUID(), TenantID: testTenantID, DisplayName: "B", AppIDURI: "api://app-one", CreatedAt: st.Now()}
	if err := st.CreateApp(b); !errors.Is(err, ErrConflict) {
		t.Fatalf("CreateApp dup URI = %v, want ErrConflict", err)
	}
	// Duplicate PK → conflict (mapConstraint path).
	if err := st.CreateApp(&App{ID: a.ID, TenantID: testTenantID, DisplayName: "dup", CreatedAt: st.Now()}); !errors.Is(err, ErrConflict) {
		t.Fatalf("CreateApp dup PK = %v, want ErrConflict", err)
	}

	// Update success.
	a.DisplayName = "App Renamed"
	a.AppIDURI = "api://app-renamed"
	if err := st.UpdateApp(a); err != nil {
		t.Fatalf("UpdateApp: %v", err)
	}
	// Update missing → ErrNotFound.
	if err := st.UpdateApp(&App{ID: "nope", DisplayName: "x"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateApp missing = %v", err)
	}
	// Update to a taken URI → conflict.
	c := mustApp(t, st, "C")
	c.AppIDURI = "api://app-renamed"
	if err := st.UpdateApp(c); !errors.Is(err, ErrConflict) {
		t.Fatalf("UpdateApp conflict = %v", err)
	}

	// List + search + paging.
	_, count, err := st.ListApps(10, 0, "")
	if err != nil || count < 2 {
		t.Fatalf("ListApps: %v count=%d", err, count)
	}
	hits, count, err := st.ListApps(10, 0, "Renamed")
	if err != nil || count != 1 || len(hits) != 1 {
		t.Fatalf("ListApps search: %v count=%d", err, count)
	}

	if err := st.DeleteApp(a.ID); err != nil {
		t.Fatalf("DeleteApp: %v", err)
	}
	if err := st.DeleteApp(a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteApp missing = %v", err)
	}
}

func TestDeleteAppClearsGrants(t *testing.T) {
	st := newTestStore(t)
	app := mustApp(t, st, "grantapp")
	u := mustUser(t, st, "au@x")
	st.InsertAuthCode(&AuthCode{Code: "ac", AppID: app.ID, UserID: u.ID, RedirectURI: "r",
		Scopes: "openid", ExpiresAt: st.Now() + 60, CreatedAt: st.Now()})
	st.InsertRefreshToken(&RefreshToken{TokenHash: HashToken("art"), AppID: app.ID, UserID: u.ID,
		Scopes: "openid", ExpiresAt: st.Now() + 60, CreatedAt: st.Now()})
	st.InsertDeviceCode(&DeviceCode{DeviceCodeHash: HashToken("adc"), UserCode: "AD-1", AppID: app.ID,
		Scopes: "openid", Interval: 5, ExpiresAt: st.Now() + 60, CreatedAt: st.Now()})

	if err := st.DeleteApp(app.ID); err != nil {
		t.Fatalf("DeleteApp: %v", err)
	}
	if _, err := st.GetAuthCode("ac"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("auth code survived: %v", err)
	}
	if _, err := st.GetDeviceCodeByUserCode("AD-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("device code survived: %v", err)
	}
}

// ---- Redirect URIs ----

func TestRedirectURIs(t *testing.T) {
	st := newTestStore(t)
	app := mustApp(t, st, "redir")

	r, err := st.AddRedirectURI(app.ID, "https://localhost/cb", "")
	if err != nil || r.Type != "web" {
		t.Fatalf("AddRedirectURI default type: %v %+v", err, r)
	}
	if _, err := st.AddRedirectURI(app.ID, "https://spa", "spa"); err != nil {
		t.Fatalf("AddRedirectURI spa: %v", err)
	}
	// Duplicate URI → conflict.
	if _, err := st.AddRedirectURI(app.ID, "https://localhost/cb", "web"); !errors.Is(err, ErrConflict) {
		t.Fatalf("dup redirect = %v, want ErrConflict", err)
	}

	list, err := st.ListRedirectURIs(app.ID)
	if err != nil || len(list) != 2 {
		t.Fatalf("ListRedirectURIs: %v len=%d", err, len(list))
	}

	ok, err := st.HasRedirectURI(app.ID, "https://localhost/cb")
	if err != nil || !ok {
		t.Fatalf("HasRedirectURI hit: %v %v", err, ok)
	}
	ok, _ = st.HasRedirectURI(app.ID, "https://none")
	if ok {
		t.Fatal("HasRedirectURI should be false for unknown")
	}

	if err := st.DeleteRedirectURI(app.ID, r.ID); err != nil {
		t.Fatalf("DeleteRedirectURI: %v", err)
	}
	if err := st.DeleteRedirectURI(app.ID, r.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteRedirectURI missing = %v", err)
	}
}

// ---- Secrets ----

func TestSecrets(t *testing.T) {
	st := newTestStore(t)
	app := mustApp(t, st, "secretapp")
	hash, _ := HashSecret("s3cr3t")

	sec := &AppSecret{ID: NewGUID(), AppID: app.ID, DisplayName: "primary", SecretHash: hash,
		Hint: "s3…t", ExpiresAt: st.Now() + 3600, CreatedAt: st.Now()}
	if err := st.AddSecret(sec); err != nil {
		t.Fatalf("AddSecret: %v", err)
	}
	// Duplicate PK → conflict.
	if err := st.AddSecret(sec); !errors.Is(err, ErrConflict) {
		t.Fatalf("dup secret = %v", err)
	}

	list, err := st.ListSecrets(app.ID)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListSecrets: %v len=%d", err, len(list))
	}

	ok, err := st.VerifyAppSecret(app.ID, "s3cr3t")
	if err != nil || !ok {
		t.Fatalf("VerifyAppSecret valid: %v %v", err, ok)
	}
	ok, _ = st.VerifyAppSecret(app.ID, "wrong")
	if ok {
		t.Fatal("VerifyAppSecret should reject wrong plaintext")
	}

	// Expired secret is skipped.
	expiredHash, _ := HashSecret("expired")
	st.AddSecret(&AppSecret{ID: NewGUID(), AppID: app.ID, SecretHash: expiredHash,
		ExpiresAt: st.Now() - 10, CreatedAt: st.Now() - 100})
	ok, _ = st.VerifyAppSecret(app.ID, "expired")
	if ok {
		t.Fatal("expired secret should not verify")
	}
	// Never-expiring secret (ExpiresAt 0).
	neverHash, _ := HashSecret("forever")
	st.AddSecret(&AppSecret{ID: NewGUID(), AppID: app.ID, SecretHash: neverHash, CreatedAt: st.Now()})
	ok, _ = st.VerifyAppSecret(app.ID, "forever")
	if !ok {
		t.Fatal("never-expiring secret should verify")
	}

	if err := st.DeleteSecret(app.ID, sec.ID); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	if err := st.DeleteSecret(app.ID, sec.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteSecret missing = %v", err)
	}
}

// ---- Scopes ----

func TestScopes(t *testing.T) {
	st := newTestStore(t)
	app := mustApp(t, st, "scopeapp")

	sc := &AppScope{ID: NewGUID(), AppID: app.ID, Value: "read", AdminConsentDisplayName: "Read", IsEnabled: true}
	if err := st.AddScope(sc); err != nil {
		t.Fatalf("AddScope: %v", err)
	}
	// Duplicate (app_id,value) → conflict.
	if err := st.AddScope(&AppScope{ID: NewGUID(), AppID: app.ID, Value: "read"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("dup scope = %v", err)
	}

	list, err := st.ListScopes(app.ID)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListScopes: %v", err)
	}

	sc.IsEnabled = false
	sc.AdminConsentDisplayName = ""
	if err := st.UpdateScope(sc); err != nil {
		t.Fatalf("UpdateScope: %v", err)
	}
	if err := st.UpdateScope(&AppScope{ID: "nope", AppID: app.ID}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateScope missing = %v", err)
	}

	if err := st.DeleteScope(app.ID, sc.ID); err != nil {
		t.Fatalf("DeleteScope: %v", err)
	}
	if err := st.DeleteScope(app.ID, sc.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteScope missing = %v", err)
	}
}

// ---- Roles ----

func TestRoles(t *testing.T) {
	st := newTestStore(t)
	app := mustApp(t, st, "roleapp")

	r := &AppRole{ID: NewGUID(), AppID: app.ID, Value: "Admin", DisplayName: "Administrator",
		AllowedMemberTypes: "", IsEnabled: true}
	if err := st.AddRole(r); err != nil {
		t.Fatalf("AddRole: %v", err)
	}
	if err := st.AddRole(&AppRole{ID: NewGUID(), AppID: app.ID, Value: "Admin"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("dup role = %v", err)
	}

	list, err := st.ListRoles(app.ID)
	if err != nil || len(list) != 1 || list[0].AllowedMemberTypes != "Application" {
		t.Fatalf("ListRoles default member type: %v %+v", err, list)
	}

	r.DisplayName = ""
	r.IsEnabled = false
	if err := st.UpdateRole(r); err != nil {
		t.Fatalf("UpdateRole: %v", err)
	}
	if err := st.UpdateRole(&AppRole{ID: "nope", AppID: app.ID}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateRole missing = %v", err)
	}

	if err := st.DeleteRole(app.ID, r.ID); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
	if err := st.DeleteRole(app.ID, r.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteRole missing = %v", err)
	}
}

// ---- Signing keys ----

func TestSigningKeys(t *testing.T) {
	st := newTestStore(t)
	k := &SigningKey{Kid: "kid-1", TenantID: testTenantID, PublicJWK: "{}", PrivatePKCS8: "pem",
		IsActive: true, CreatedAt: st.Now()}
	if err := st.InsertSigningKey(k); err != nil {
		t.Fatalf("InsertSigningKey: %v", err)
	}
	if err := st.InsertSigningKey(k); !errors.Is(err, ErrConflict) {
		t.Fatalf("dup key = %v", err)
	}

	if got, err := st.GetActiveSigningKey(testTenantID); err != nil || got.Kid != "kid-1" {
		t.Fatalf("GetActiveSigningKey: %v %+v", err, got)
	}
	if got, err := st.GetSigningKey("kid-1"); err != nil || got.Alg != "RS256" {
		t.Fatalf("GetSigningKey: %v %+v", err, got)
	}
	if _, err := st.GetSigningKey("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetSigningKey miss = %v", err)
	}
	if _, err := st.GetActiveSigningKey("other-tenant"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetActiveSigningKey miss = %v", err)
	}

	// Publishable: active key present.
	keys, err := st.ListPublishableKeys(testTenantID, st.Now())
	if err != nil || len(keys) != 1 {
		t.Fatalf("ListPublishableKeys active: %v len=%d", err, len(keys))
	}

	// Demote with a future not_after → still publishable; then a new active key.
	future := st.Now() + 3600
	if err := st.DemoteActiveSigningKeys(testTenantID, future); err != nil {
		t.Fatalf("DemoteActiveSigningKeys: %v", err)
	}
	if _, err := st.GetActiveSigningKey(testTenantID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("active key still present after demote: %v", err)
	}
	k2 := &SigningKey{Kid: "kid-2", TenantID: testTenantID, PublicJWK: "{}", PrivatePKCS8: "pem",
		IsActive: true, CreatedAt: st.Now() + 1}
	st.InsertSigningKey(k2)
	// Now active(kid-2) + retired-but-unexpired(kid-1) = 2.
	keys, _ = st.ListPublishableKeys(testTenantID, st.Now())
	if len(keys) != 2 {
		t.Fatalf("ListPublishableKeys union = %d, want 2", len(keys))
	}
	// After the grace window, kid-1 drops out.
	keys, _ = st.ListPublishableKeys(testTenantID, future+1)
	if len(keys) != 1 {
		t.Fatalf("ListPublishableKeys post-grace = %d, want 1", len(keys))
	}
}

// ---- Auth codes ----

func TestAuthCodes(t *testing.T) {
	st := newTestStore(t)
	app := mustApp(t, st, "codeapp")
	u := mustUser(t, st, "code@x")

	c := &AuthCode{Code: "abc", AppID: app.ID, UserID: u.ID, RedirectURI: "https://cb",
		Scopes: "openid profile", Resource: "api://res", CodeChallenge: "chal", CodeChallengeMethod: "S256",
		Nonce: "n", AMR: "pwd", ExpiresAt: st.Now() + 60, CreatedAt: st.Now()}
	if err := st.InsertAuthCode(c); err != nil {
		t.Fatalf("InsertAuthCode: %v", err)
	}
	if err := st.InsertAuthCode(c); !errors.Is(err, ErrConflict) {
		t.Fatalf("dup auth code = %v", err)
	}

	got, err := st.GetAuthCode("abc")
	if err != nil || got.Resource != "api://res" || got.AMR != "pwd" {
		t.Fatalf("GetAuthCode: %v %+v", err, got)
	}
	if _, err := st.GetAuthCode("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetAuthCode miss = %v", err)
	}

	// First consume wins; replay returns false.
	ok, err := st.ConsumeAuthCode("abc")
	if err != nil || !ok {
		t.Fatalf("ConsumeAuthCode: %v %v", err, ok)
	}
	ok, err = st.ConsumeAuthCode("abc")
	if err != nil || ok {
		t.Fatalf("ConsumeAuthCode replay = %v %v", err, ok)
	}
	// Unknown code → false.
	ok, _ = st.ConsumeAuthCode("ghost")
	if ok {
		t.Fatal("ConsumeAuthCode unknown should be false")
	}
}

// ---- Refresh tokens ----

func TestRefreshTokenRotationAndRevocation(t *testing.T) {
	st := newTestStore(t)
	app := mustApp(t, st, "rtapp")
	u := mustUser(t, st, "rt@x")

	rt1 := &RefreshToken{TokenHash: HashToken("t1"), AppID: app.ID, UserID: u.ID,
		Scopes: "openid", Resource: "api://r", ExpiresAt: st.Now() + 3600, CreatedAt: st.Now()}
	if err := st.InsertRefreshToken(rt1); err != nil {
		t.Fatalf("InsertRefreshToken: %v", err)
	}
	if err := st.InsertRefreshToken(rt1); !errors.Is(err, ErrConflict) {
		t.Fatalf("dup rt = %v", err)
	}

	got, err := st.GetRefreshTokenByHash(HashToken("t1"))
	if err != nil || got.Resource != "api://r" {
		t.Fatalf("GetRefreshTokenByHash: %v %+v", err, got)
	}
	if _, err := st.GetRefreshTokenByHash("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetRefreshTokenByHash miss = %v", err)
	}

	// Rotate: t1 -> t2, wins.
	rt2 := &RefreshToken{TokenHash: HashToken("t2"), AppID: app.ID, UserID: u.ID,
		Scopes: "openid", ExpiresAt: st.Now() + 3600, CreatedAt: st.Now()}
	won, err := st.RotateRefreshToken(HashToken("t1"), rt2)
	if err != nil || !won {
		t.Fatalf("RotateRefreshToken: %v won=%v", err, won)
	}
	// t1 now revoked; rotating it again loses the race.
	rt3 := &RefreshToken{TokenHash: HashToken("t3"), AppID: app.ID, UserID: u.ID,
		Scopes: "openid", ExpiresAt: st.Now() + 3600, CreatedAt: st.Now()}
	won, err = st.RotateRefreshToken(HashToken("t1"), rt3)
	if err != nil || won {
		t.Fatalf("RotateRefreshToken replay = %v won=%v", err, won)
	}
	// t2 recorded rotated_from=t1.
	got2, _ := st.GetRefreshTokenByHash(HashToken("t2"))
	if got2.RotatedFrom != HashToken("t1") {
		t.Fatalf("rotated_from = %q", got2.RotatedFrom)
	}

	// Rotate t2 -> t4 to form a longer chain, then revoke the whole family.
	rt4 := &RefreshToken{TokenHash: HashToken("t4"), AppID: app.ID, UserID: u.ID,
		Scopes: "openid", ExpiresAt: st.Now() + 3600, CreatedAt: st.Now()}
	st.RotateRefreshToken(HashToken("t2"), rt4)

	if err := st.RevokeRefreshTokenFamily(HashToken("t2")); err != nil {
		t.Fatalf("RevokeRefreshTokenFamily: %v", err)
	}
	for _, h := range []string{"t1", "t2", "t4"} {
		row, _ := st.GetRefreshTokenByHash(HashToken(h))
		if !row.Revoked {
			t.Fatalf("token %s not revoked after family revoke", h)
		}
	}

	// Revoking a family for an unknown token is a harmless no-op.
	if err := st.RevokeRefreshTokenFamily(HashToken("ghost")); err != nil {
		t.Fatalf("RevokeRefreshTokenFamily unknown: %v", err)
	}
}

// ---- Sessions ----

func TestSessions(t *testing.T) {
	st := newTestStore(t)
	u := mustUser(t, st, "sess@x")

	// Default auth method fills in as "pwd".
	sess := &Session{ID: NewGUID(), UserID: u.ID, CreatedAt: st.Now(), ExpiresAt: st.Now() + 3600}
	if err := st.CreateSession(sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	got, err := st.GetSession(sess.ID)
	if err != nil || got.AuthMethod != "pwd" {
		t.Fatalf("GetSession default method: %v %+v", err, got)
	}
	// Explicit method.
	sess2 := &Session{ID: NewGUID(), UserID: u.ID, AuthMethod: "fido", CreatedAt: st.Now(), ExpiresAt: st.Now() + 3600}
	st.CreateSession(sess2)
	got2, _ := st.GetSession(sess2.ID)
	if got2.AuthMethod != "fido" {
		t.Fatalf("session method = %q", got2.AuthMethod)
	}
	// Duplicate id → conflict.
	if err := st.CreateSession(sess); !errors.Is(err, ErrConflict) {
		t.Fatalf("dup session = %v", err)
	}
	if _, err := st.GetSession("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetSession miss = %v", err)
	}

	if err := st.DeleteSession(sess.ID); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	// Deleting a missing session is a no-op.
	if err := st.DeleteSession("ghost"); err != nil {
		t.Fatalf("DeleteSession missing: %v", err)
	}
	if _, err := st.GetSession(sess.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session still present: %v", err)
	}
}

// ---- Device codes ----

func TestDeviceCodes(t *testing.T) {
	st := newTestStore(t)
	app := mustApp(t, st, "deviceapp")
	u := mustUser(t, st, "dev@x")

	d := &DeviceCode{DeviceCodeHash: HashToken("dc1"), UserCode: "WXYZ-1234", AppID: app.ID,
		Scopes: "openid", Interval: 5, ExpiresAt: st.Now() + 600, CreatedAt: st.Now()}
	if err := st.InsertDeviceCode(d); err != nil {
		t.Fatalf("InsertDeviceCode: %v", err)
	}
	if err := st.InsertDeviceCode(d); !errors.Is(err, ErrConflict) {
		t.Fatalf("dup device code = %v", err)
	}

	if got, err := st.GetDeviceCodeByHash(HashToken("dc1")); err != nil || got.Status != "pending" {
		t.Fatalf("GetDeviceCodeByHash: %v %+v", err, got)
	}
	if _, err := st.GetDeviceCodeByHash("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetDeviceCodeByHash miss = %v", err)
	}
	if got, err := st.GetDeviceCodeByUserCode("WXYZ-1234"); err != nil || got.AppID != app.ID {
		t.Fatalf("GetDeviceCodeByUserCode: %v", err)
	}
	if _, err := st.GetDeviceCodeByUserCode("none"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetDeviceCodeByUserCode miss = %v", err)
	}

	if ok, err := st.UserCodeExists("WXYZ-1234"); err != nil || !ok {
		t.Fatalf("UserCodeExists hit: %v %v", err, ok)
	}
	if ok, _ := st.UserCodeExists("nope"); ok {
		t.Fatal("UserCodeExists false expected")
	}

	// Approve (pending → approved with user).
	if err := st.SetDeviceCodeDecision("WXYZ-1234", "approved", u.ID); err != nil {
		t.Fatalf("SetDeviceCodeDecision: %v", err)
	}
	// Second decision on non-pending → ErrNotFound (guard status='pending').
	if err := st.SetDeviceCodeDecision("WXYZ-1234", "denied", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetDeviceCodeDecision non-pending = %v", err)
	}

	// Consume: mismatched app → nil, nil.
	res, err := st.ConsumeApprovedDeviceCode(HashToken("dc1"), "other-app", st.Now())
	if err != nil || res != nil {
		t.Fatalf("ConsumeApprovedDeviceCode mismatch = %+v %v", res, err)
	}
	// Consume: correct app, unexpired → returns row, deletes it.
	res, err = st.ConsumeApprovedDeviceCode(HashToken("dc1"), app.ID, st.Now())
	if err != nil || res == nil || res.UserID != u.ID {
		t.Fatalf("ConsumeApprovedDeviceCode = %+v %v", res, err)
	}
	// Now gone → second consume returns nil.
	res, err = st.ConsumeApprovedDeviceCode(HashToken("dc1"), app.ID, st.Now())
	if err != nil || res != nil {
		t.Fatalf("ConsumeApprovedDeviceCode after delete = %+v %v", res, err)
	}

	// SetDeviceCodeDecision on an unknown user code → ErrNotFound.
	if err := st.SetDeviceCodeDecision("no-code", "approved", u.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetDeviceCodeDecision unknown = %v", err)
	}

	// DeleteDeviceCode (denied cleanup / no-op on missing).
	d2 := &DeviceCode{DeviceCodeHash: HashToken("dc2"), UserCode: "AAAA-0000", AppID: app.ID,
		Scopes: "openid", Interval: 5, ExpiresAt: st.Now() + 600, CreatedAt: st.Now()}
	st.InsertDeviceCode(d2)
	if err := st.DeleteDeviceCode(HashToken("dc2")); err != nil {
		t.Fatalf("DeleteDeviceCode: %v", err)
	}
	if err := st.DeleteDeviceCode(HashToken("ghost")); err != nil {
		t.Fatalf("DeleteDeviceCode missing: %v", err)
	}
}

func TestConsumeApprovedDeviceCodeExpired(t *testing.T) {
	st := newTestStore(t)
	app := mustApp(t, st, "expdev")
	u := mustUser(t, st, "expdev@x")
	st.InsertDeviceCode(&DeviceCode{DeviceCodeHash: HashToken("exp"), UserCode: "EXP-0001", AppID: app.ID,
		Scopes: "openid", Status: "approved", Interval: 5, ExpiresAt: st.Now() + 10, CreatedAt: st.Now()})
	st.SetDeviceCodeDecision("EXP-0001", "approved", u.ID)
	// now beyond expiry → nil.
	res, err := st.ConsumeApprovedDeviceCode(HashToken("exp"), app.ID, st.Now()+100)
	if err != nil || res != nil {
		t.Fatalf("expired consume = %+v %v", res, err)
	}
}

// ---- WebAuthn ----

func TestWebAuthnCredentials(t *testing.T) {
	st := newTestStore(t)
	u := mustUser(t, st, "passkey@x")

	if ok, err := st.HasWebAuthnCredentials(u.ID); err != nil || ok {
		t.Fatalf("HasWebAuthnCredentials empty: %v %v", err, ok)
	}

	c := &WebAuthnCredential{ID: "cred-1", UserID: u.ID, PublicKey: []byte{1, 2, 3},
		SignCount: 0, AAGUID: []byte{9, 9}, Transports: "usb,nfc", Name: "YubiKey", CreatedAt: st.Now()}
	if err := st.AddWebAuthnCredential(c); err != nil {
		t.Fatalf("AddWebAuthnCredential: %v", err)
	}
	if err := st.AddWebAuthnCredential(c); !errors.Is(err, ErrConflict) {
		t.Fatalf("dup cred = %v", err)
	}
	// Credential with null aaguid/transports/name (COALESCE paths).
	c2 := &WebAuthnCredential{ID: "cred-2", UserID: u.ID, PublicKey: []byte{4, 5}, CreatedAt: st.Now()}
	if err := st.AddWebAuthnCredential(c2); err != nil {
		t.Fatalf("AddWebAuthnCredential minimal: %v", err)
	}

	if ok, err := st.HasWebAuthnCredentials(u.ID); err != nil || !ok {
		t.Fatalf("HasWebAuthnCredentials after add: %v %v", err, ok)
	}

	list, err := st.ListWebAuthnCredentials(u.ID)
	if err != nil || len(list) != 2 {
		t.Fatalf("ListWebAuthnCredentials: %v len=%d", err, len(list))
	}

	got, err := st.GetWebAuthnCredential("cred-1")
	if err != nil || got.Name != "YubiKey" || string(got.PublicKey) != string([]byte{1, 2, 3}) {
		t.Fatalf("GetWebAuthnCredential: %v %+v", err, got)
	}
	if _, err := st.GetWebAuthnCredential("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetWebAuthnCredential miss = %v", err)
	}

	if err := st.UpdateWebAuthnSignCount("cred-1", 42); err != nil {
		t.Fatalf("UpdateWebAuthnSignCount: %v", err)
	}
	got, _ = st.GetWebAuthnCredential("cred-1")
	if got.SignCount != 42 {
		t.Fatalf("sign count = %d", got.SignCount)
	}
	// Updating an unknown id is a no-op (no error).
	if err := st.UpdateWebAuthnSignCount("ghost", 1); err != nil {
		t.Fatalf("UpdateWebAuthnSignCount missing: %v", err)
	}

	if err := st.DeleteWebAuthnCredential(u.ID, "cred-1"); err != nil {
		t.Fatalf("DeleteWebAuthnCredential: %v", err)
	}
	if err := st.DeleteWebAuthnCredential(u.ID, "cred-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteWebAuthnCredential missing = %v", err)
	}
}

// ---- App key credentials ----

func TestAppKeyCredentials(t *testing.T) {
	st := newTestStore(t)
	app := mustApp(t, st, "keycredapp")

	c := &AppKeyCredential{ID: NewGUID(), AppID: app.ID, PublicKey: "-----PEM-----", DisplayName: "cert", CreatedAt: st.Now()}
	if err := st.AddAppKeyCredential(c); err != nil {
		t.Fatalf("AddAppKeyCredential: %v", err)
	}
	if err := st.AddAppKeyCredential(c); !errors.Is(err, ErrConflict) {
		t.Fatalf("dup keycred = %v", err)
	}
	// Null display name path.
	st.AddAppKeyCredential(&AppKeyCredential{ID: NewGUID(), AppID: app.ID, PublicKey: "-----PEM2-----", CreatedAt: st.Now()})

	list, err := st.ListAppKeyCredentials(app.ID)
	if err != nil || len(list) != 2 {
		t.Fatalf("ListAppKeyCredentials: %v len=%d", err, len(list))
	}

	if err := st.DeleteAppKeyCredential(app.ID, c.ID); err != nil {
		t.Fatalf("DeleteAppKeyCredential: %v", err)
	}
	if err := st.DeleteAppKeyCredential(app.ID, c.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteAppKeyCredential missing = %v", err)
	}
}

// ---- Workspace identities (fabric) ----

func TestWorkspaceIdentities(t *testing.T) {
	st := newTestStore(t)

	if ValidWorkspaceIdentityState("Active") != true || ValidWorkspaceIdentityState("Bogus") {
		t.Fatal("ValidWorkspaceIdentityState wrong")
	}

	appID := NewGUID()
	wi := &WorkspaceIdentity{ID: NewGUID(), TenantID: testTenantID, AppID: appID,
		WorkspaceID: "ws-1", WorkspaceName: "Analytics", State: "Active", CreatedAt: st.Now()}
	app := &App{ID: appID, TenantID: testTenantID, DisplayName: "Analytics", CreatedAt: st.Now()}
	if err := st.CreateWorkspaceIdentity(wi, app); err != nil {
		t.Fatalf("CreateWorkspaceIdentity: %v", err)
	}
	// Duplicate app id → conflict (mapConstraint inside tx).
	if err := st.CreateWorkspaceIdentity(wi, app); !errors.Is(err, ErrConflict) {
		t.Fatalf("dup workspace identity = %v", err)
	}
	// The SP app now exists.
	if _, err := st.GetApp(appID); err != nil {
		t.Fatalf("SP app missing: %v", err)
	}

	got, err := st.GetWorkspaceIdentity(wi.ID)
	if err != nil || got.WorkspaceName != "Analytics" {
		t.Fatalf("GetWorkspaceIdentity: %v %+v", err, got)
	}
	if _, err := st.GetWorkspaceIdentity("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetWorkspaceIdentity miss = %v", err)
	}

	list, err := st.ListWorkspaceIdentities()
	if err != nil || len(list) != 1 {
		t.Fatalf("ListWorkspaceIdentities: %v len=%d", err, len(list))
	}

	// Rename → SP display name follows.
	wi.WorkspaceName = "Analytics v2"
	wi.State = "Provisioning"
	if err := st.UpdateWorkspaceIdentity(wi); err != nil {
		t.Fatalf("UpdateWorkspaceIdentity: %v", err)
	}
	app2, _ := st.GetApp(appID)
	if app2.DisplayName != "Analytics v2" {
		t.Fatalf("SP display name not updated: %q", app2.DisplayName)
	}
	// Update missing identity → ErrNotFound.
	if err := st.UpdateWorkspaceIdentity(&WorkspaceIdentity{ID: "nope", AppID: appID}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateWorkspaceIdentity missing = %v", err)
	}

	// Delete removes SP app + cascades the identity row.
	if err := st.DeleteWorkspaceIdentity(wi.ID); err != nil {
		t.Fatalf("DeleteWorkspaceIdentity: %v", err)
	}
	if _, err := st.GetWorkspaceIdentity(wi.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("identity survived delete: %v", err)
	}
	if _, err := st.GetApp(appID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SP app survived delete: %v", err)
	}
	// Delete missing identity → ErrNotFound.
	if err := st.DeleteWorkspaceIdentity("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteWorkspaceIdentity missing = %v", err)
	}
}

// ---- Seed / Reset / Export / Import ----

func TestSeedAndIsSeeded(t *testing.T) {
	st := newTestStore(t)

	if seeded, err := st.IsSeeded(); err != nil || seeded {
		t.Fatalf("IsSeeded before seed: %v %v", err, seeded)
	}
	// First seed on an unseeded directory (no users yet) → wasNew=true.
	wasNew, err := st.Seed(testTenantID, testIssuer)
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if !wasNew {
		t.Fatalf("Seed wasNew should be true on an unseeded directory")
	}
	// Re-seeding an already-seeded directory → wasNew=false.
	if again, err := st.Seed(testTenantID, testIssuer); err != nil || again {
		t.Fatalf("re-seed wasNew: %v again=%v", err, again)
	}
	if seeded, _ := st.IsSeeded(); !seeded {
		t.Fatal("IsSeeded after seed should be true")
	}
	// Seed is idempotent.
	if _, err := st.Seed(testTenantID, testIssuer); err != nil {
		t.Fatalf("re-seed: %v", err)
	}
	// Seeded content is present.
	if _, err := st.GetUser(SeedUserAliceID); err != nil {
		t.Fatalf("seed alice missing: %v", err)
	}
	if _, err := st.GetApp(SeedAppDaemonID); err != nil {
		t.Fatalf("seed daemon missing: %v", err)
	}
	ok, _ := st.VerifyAppSecret(SeedAppDaemonID, SeedDaemonSecret)
	if !ok {
		t.Fatal("seeded daemon secret should verify")
	}
	u, _ := st.VerifyPassword("alice@entraemulator.dev", SeedPassword)
	if u == nil {
		t.Fatal("seeded alice password should verify")
	}
}

func TestSeedOnFreshDB(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "fresh.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	// No EnsureTenant: the tenant is absent, so Seed reports wasNew=true.
	wasNew, err := st.Seed(testTenantID, testIssuer)
	if err != nil {
		t.Fatalf("Seed: %v", err)
	}
	if !wasNew {
		t.Fatal("Seed wasNew should be true when tenant was absent")
	}
}

func TestReset(t *testing.T) {
	st := seededStore(t)
	st.InsertSigningKey(&SigningKey{Kid: "rk", TenantID: testTenantID, PublicJWK: "{}",
		PrivatePKCS8: "pem", IsActive: true, CreatedAt: st.Now()})

	// Reset without reseed, keeping keys.
	reseeded, err := st.Reset(testTenantID, testIssuer, false, false)
	if err != nil || reseeded {
		t.Fatalf("Reset no-reseed: %v reseeded=%v", err, reseeded)
	}
	if seeded, _ := st.IsSeeded(); seeded {
		t.Fatal("directory should be empty after reset")
	}
	if _, err := st.GetSigningKey("rk"); err != nil {
		t.Fatalf("signing key should be kept: %v", err)
	}

	// Reset with reseed and key wipe.
	reseeded, err = st.Reset(testTenantID, testIssuer, true, true)
	if err != nil || !reseeded {
		t.Fatalf("Reset reseed: %v reseeded=%v", err, reseeded)
	}
	if seeded, _ := st.IsSeeded(); !seeded {
		t.Fatal("directory should be reseeded")
	}
	if _, err := st.GetSigningKey("rk"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("signing key should be wiped: %v", err)
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	st := seededStore(t)
	// Add extra artifacts to exercise all export/import branches.
	app, _ := st.GetApp(SeedAppSPAID)
	st.AddRole(&AppRole{ID: NewGUID(), AppID: app.ID, Value: "Reader", DisplayName: "Reader", IsEnabled: true})

	snap, err := st.ExportDirectory()
	if err != nil {
		t.Fatalf("ExportDirectory: %v", err)
	}
	if snap.Version != 1 || len(snap.Users) < 2 || len(snap.Apps) < 2 || len(snap.GroupMembers) < 2 {
		t.Fatalf("snapshot incomplete: %+v", snap)
	}

	// Import into a fresh store.
	dst := newTestStore(t)
	if err := dst.ImportDirectory(snap, testTenantID); err != nil {
		t.Fatalf("ImportDirectory: %v", err)
	}
	if _, err := dst.GetUser(SeedUserAliceID); err != nil {
		t.Fatalf("imported alice missing: %v", err)
	}
	if _, err := dst.GetApp(SeedAppDaemonID); err != nil {
		t.Fatalf("imported daemon missing: %v", err)
	}
	members, _ := dst.ListGroupMembers(SeedGroupEngID)
	if len(members) != 2 {
		t.Fatalf("imported memberships = %d", len(members))
	}
	// Secret hashes survive → verify still works.
	if ok, _ := dst.VerifyAppSecret(SeedAppDaemonID, SeedDaemonSecret); !ok {
		t.Fatal("imported secret should verify")
	}
}

func TestImportDirectoryDefaults(t *testing.T) {
	st := newTestStore(t)
	// Snapshot with empty tenant ids and zero created_at → import fills defaults.
	snap := &DirectorySnapshot{
		Version: 1,
		Users: []*User{{ID: NewGUID(), UserPrincipalName: "imp@x", DisplayName: "Imp",
			AccountEnabled: true}},
		Groups: []*Group{{ID: NewGUID(), DisplayName: "ImpGroup"}},
		Apps: []AppExport{{
			App:          &App{ID: NewGUID(), DisplayName: "ImpApp"},
			RedirectURIs: []*RedirectURI{{URI: "https://imp/cb", Type: ""}},
			Secrets:      []*AppSecret{{ID: NewGUID(), SecretHash: "scrypt$x$y"}},
			Scopes:       []*AppScope{{ID: NewGUID(), Value: "imp.read", IsEnabled: true}},
			Roles:        []*AppRole{{ID: NewGUID(), Value: "ImpRole", AllowedMemberTypes: "", IsEnabled: true}},
		}},
	}
	snap.GroupMembers = []GroupMembership{{GroupID: snap.Groups[0].ID, UserID: snap.Users[0].ID}}
	if err := st.ImportDirectory(snap, testTenantID); err != nil {
		t.Fatalf("ImportDirectory defaults: %v", err)
	}
	u, err := st.GetUser(snap.Users[0].ID)
	if err != nil || u.TenantID != testTenantID || u.CreatedAt == 0 {
		t.Fatalf("import default fill: %v %+v", err, u)
	}
	a, _ := st.GetApp(snap.Apps[0].App.ID)
	if a.TenantID != testTenantID || a.CreatedAt == 0 {
		t.Fatalf("import app default fill: %+v", a)
	}
	roles, _ := st.ListRoles(a.ID)
	if len(roles) != 1 || roles[0].AllowedMemberTypes != "Application" {
		t.Fatalf("import role default member type: %+v", roles)
	}
}

// TestClosedStoreErrors drives every repository method against a closed
// database handle. Each underlying Query/Exec/Begin then fails, exercising the
// otherwise-unreachable `if err != nil { return ... }` DB-error guards in bulk.
func TestClosedStoreErrors(t *testing.T) {
	st := newTestStore(t)
	if err := st.db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	wantErr := func(name string, err error) {
		t.Helper()
		if err == nil {
			t.Errorf("%s: expected error on closed DB, got nil", name)
		}
	}

	// Tenants.
	_, err := st.GetTenant()
	wantErr("GetTenant", err)
	_, err = st.GetTenantByID("x")
	wantErr("GetTenantByID", err)
	_, err = st.ListTenants()
	wantErr("ListTenants", err)
	wantErr("CreateTenant", st.CreateTenant(&Tenant{ID: "x"}))
	wantErr("DeleteTenant", st.DeleteTenant("x"))
	wantErr("EnsureTenant", st.EnsureTenant("x", "y"))

	// Users.
	_, err = st.GetUser("x")
	wantErr("GetUser", err)
	_, err = st.GetUserByUPN("x")
	wantErr("GetUserByUPN", err)
	_, _, err = st.ListUsers(10, 0, "")
	wantErr("ListUsers", err)
	_, _, err = st.ListUsers(10, 0, "q")
	wantErr("ListUsers search", err)
	wantErr("CreateUser", st.CreateUser(&User{ID: "x"}))
	wantErr("UpdateUser", st.UpdateUser(&User{ID: "x"}))
	wantErr("DeleteUser", st.DeleteUser("x"))
	_, err = st.VerifyPassword("x", "y")
	wantErr("VerifyPassword", err)

	// Groups + membership.
	_, err = st.GetGroup("x")
	wantErr("GetGroup", err)
	_, _, err = st.ListGroups(10, 0, "")
	wantErr("ListGroups", err)
	wantErr("CreateGroup", st.CreateGroup(&Group{ID: "x"}))
	wantErr("UpdateGroup", st.UpdateGroup(&Group{ID: "x"}))
	wantErr("DeleteGroup", st.DeleteGroup("x"))
	wantErr("AddGroupMember", st.AddGroupMember("g", "u"))
	wantErr("RemoveGroupMember", st.RemoveGroupMember("g", "u"))
	_, err = st.ListGroupMembers("g")
	wantErr("ListGroupMembers", err)
	_, err = st.ListGroupsForUser("u")
	wantErr("ListGroupsForUser", err)
	_, err = st.CountGroupMembers("g")
	wantErr("CountGroupMembers", err)

	// Apps.
	_, err = st.GetApp("x")
	wantErr("GetApp", err)
	_, err = st.GetAppByIDURI("x")
	wantErr("GetAppByIDURI", err)
	_, _, err = st.ListApps(10, 0, "")
	wantErr("ListApps", err)
	wantErr("CreateApp", st.CreateApp(&App{ID: "x"}))
	wantErr("UpdateApp", st.UpdateApp(&App{ID: "x", AppIDURI: "api://x"}))
	wantErr("DeleteApp", st.DeleteApp("x"))

	// Redirect URIs.
	_, err = st.ListRedirectURIs("x")
	wantErr("ListRedirectURIs", err)
	_, err = st.AddRedirectURI("x", "u", "web")
	wantErr("AddRedirectURI", err)
	wantErr("DeleteRedirectURI", st.DeleteRedirectURI("x", 1))
	_, err = st.HasRedirectURI("x", "u")
	wantErr("HasRedirectURI", err)

	// Secrets.
	_, err = st.ListSecrets("x")
	wantErr("ListSecrets", err)
	wantErr("AddSecret", st.AddSecret(&AppSecret{ID: "x"}))
	wantErr("DeleteSecret", st.DeleteSecret("x", "y"))
	_, err = st.VerifyAppSecret("x", "y")
	wantErr("VerifyAppSecret", err)

	// Scopes.
	_, err = st.ListScopes("x")
	wantErr("ListScopes", err)
	wantErr("AddScope", st.AddScope(&AppScope{ID: "x"}))
	wantErr("UpdateScope", st.UpdateScope(&AppScope{ID: "x"}))
	wantErr("DeleteScope", st.DeleteScope("x", "y"))

	// Roles.
	_, err = st.ListRoles("x")
	wantErr("ListRoles", err)
	wantErr("AddRole", st.AddRole(&AppRole{ID: "x"}))
	wantErr("UpdateRole", st.UpdateRole(&AppRole{ID: "x"}))
	wantErr("DeleteRole", st.DeleteRole("x", "y"))

	// Signing keys.
	_, err = st.GetActiveSigningKey("x")
	wantErr("GetActiveSigningKey", err)
	_, err = st.GetSigningKey("x")
	wantErr("GetSigningKey", err)
	_, err = st.ListPublishableKeys("x", 0)
	wantErr("ListPublishableKeys", err)
	wantErr("DemoteActiveSigningKeys", st.DemoteActiveSigningKeys("x", 0))
	wantErr("InsertSigningKey", st.InsertSigningKey(&SigningKey{Kid: "x"}))

	// Auth codes.
	wantErr("InsertAuthCode", st.InsertAuthCode(&AuthCode{Code: "x"}))
	_, err = st.GetAuthCode("x")
	wantErr("GetAuthCode", err)
	_, err = st.ConsumeAuthCode("x")
	wantErr("ConsumeAuthCode", err)

	// Refresh tokens.
	_, err = st.GetRefreshTokenByHash("x")
	wantErr("GetRefreshTokenByHash", err)
	wantErr("InsertRefreshToken", st.InsertRefreshToken(&RefreshToken{TokenHash: "x"}))
	_, err = st.RotateRefreshToken("x", &RefreshToken{TokenHash: "y"})
	wantErr("RotateRefreshToken", err)
	wantErr("RevokeRefreshTokenFamily", st.RevokeRefreshTokenFamily("x"))

	// Sessions.
	wantErr("CreateSession", st.CreateSession(&Session{ID: "x"}))
	_, err = st.GetSession("x")
	wantErr("GetSession", err)
	wantErr("DeleteSession", st.DeleteSession("x"))

	// Device codes.
	wantErr("InsertDeviceCode", st.InsertDeviceCode(&DeviceCode{DeviceCodeHash: "x", UserCode: "u"}))
	_, err = st.GetDeviceCodeByHash("x")
	wantErr("GetDeviceCodeByHash", err)
	_, err = st.GetDeviceCodeByUserCode("x")
	wantErr("GetDeviceCodeByUserCode", err)
	wantErr("SetDeviceCodeDecision", st.SetDeviceCodeDecision("x", "approved", "u"))
	_, err = st.ConsumeApprovedDeviceCode("x", "a", 0)
	wantErr("ConsumeApprovedDeviceCode", err)
	wantErr("DeleteDeviceCode", st.DeleteDeviceCode("x"))
	_, err = st.UserCodeExists("x")
	wantErr("UserCodeExists", err)

	// WebAuthn.
	wantErr("AddWebAuthnCredential", st.AddWebAuthnCredential(&WebAuthnCredential{ID: "x"}))
	_, err = st.ListWebAuthnCredentials("x")
	wantErr("ListWebAuthnCredentials", err)
	_, err = st.GetWebAuthnCredential("x")
	wantErr("GetWebAuthnCredential", err)
	wantErr("UpdateWebAuthnSignCount", st.UpdateWebAuthnSignCount("x", 1))
	wantErr("DeleteWebAuthnCredential", st.DeleteWebAuthnCredential("u", "x"))
	_, err = st.HasWebAuthnCredentials("x")
	wantErr("HasWebAuthnCredentials", err)

	// App key credentials.
	wantErr("AddAppKeyCredential", st.AddAppKeyCredential(&AppKeyCredential{ID: "x"}))
	_, err = st.ListAppKeyCredentials("x")
	wantErr("ListAppKeyCredentials", err)
	wantErr("DeleteAppKeyCredential", st.DeleteAppKeyCredential("a", "x"))

	// Workspace identities.
	wantErr("CreateWorkspaceIdentity", st.CreateWorkspaceIdentity(
		&WorkspaceIdentity{ID: "x"}, &App{ID: "a"}))
	_, err = st.GetWorkspaceIdentity("x")
	wantErr("GetWorkspaceIdentity", err)
	_, err = st.ListWorkspaceIdentities()
	wantErr("ListWorkspaceIdentities", err)
	wantErr("UpdateWorkspaceIdentity", st.UpdateWorkspaceIdentity(&WorkspaceIdentity{ID: "x"}))
	wantErr("DeleteWorkspaceIdentity", st.DeleteWorkspaceIdentity("x"))

	// Seed / reset / export / import.
	_, err = st.IsSeeded()
	wantErr("IsSeeded", err)
	_, err = st.Seed(testTenantID, testIssuer)
	wantErr("Seed", err)
	_, err = st.Reset(testTenantID, testIssuer, false, false)
	wantErr("Reset", err)
	_, err = st.ExportDirectory()
	wantErr("ExportDirectory", err)
	wantErr("ImportDirectory", st.ImportDirectory(&DirectorySnapshot{
		Users:  []*User{{ID: "u"}},
		Groups: []*Group{{ID: "g"}},
		Apps:   []AppExport{{App: &App{ID: "a"}}},
	}, testTenantID))
}

// TestImportDirectoryInsertErrors exercises each inner INSERT-failure branch of
// ImportDirectory by feeding snapshots that violate a constraint mid-transaction.
func TestImportDirectoryInsertErrors(t *testing.T) {
	dupUser := &User{ID: "dup", UserPrincipalName: "a@x", DisplayName: "A", AccountEnabled: true}
	dupUser2 := &User{ID: "dup", UserPrincipalName: "b@x", DisplayName: "B", AccountEnabled: true}
	dupGroup := &Group{ID: "g", DisplayName: "G"}
	appOf := func(sub AppExport) *DirectorySnapshot {
		return &DirectorySnapshot{Apps: []AppExport{sub}}
	}
	cases := []struct {
		name string
		snap *DirectorySnapshot
	}{
		{"users", &DirectorySnapshot{Users: []*User{dupUser, dupUser2}}},
		{"groups", &DirectorySnapshot{Groups: []*Group{dupGroup, {ID: "g", DisplayName: "G2"}}}},
		{"apps", &DirectorySnapshot{Apps: []AppExport{
			{App: &App{ID: "a", DisplayName: "A"}},
			{App: &App{ID: "a", DisplayName: "A2"}},
		}}},
		{"redirects", appOf(AppExport{App: &App{ID: "ra", DisplayName: "RA"},
			RedirectURIs: []*RedirectURI{{URI: "u", Type: "web"}, {URI: "u", Type: "web"}}})},
		{"secrets", appOf(AppExport{App: &App{ID: "sa", DisplayName: "SA"},
			Secrets: []*AppSecret{{ID: "s", SecretHash: "h"}, {ID: "s", SecretHash: "h"}}})},
		{"scopes", appOf(AppExport{App: &App{ID: "ca", DisplayName: "CA"},
			Scopes: []*AppScope{{ID: "sc1", Value: "v", IsEnabled: true}, {ID: "sc2", Value: "v", IsEnabled: true}}})},
		{"roles", appOf(AppExport{App: &App{ID: "roa", DisplayName: "ROA"},
			Roles: []*AppRole{{ID: "r1", Value: "v", IsEnabled: true}, {ID: "r2", Value: "v", IsEnabled: true}}})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := newTestStore(t)
			if err := st.ImportDirectory(tc.snap, testTenantID); err == nil {
				t.Fatalf("%s: expected import to fail on constraint violation", tc.name)
			}
		})
	}
}

// TestSeedInsertConflictIsIgnored confirms Seed's INSERT OR IGNORE tolerates a
// pre-existing conflicting group-member row (idempotent re-seed path).
func TestSeedReseedOverExisting(t *testing.T) {
	st := seededStore(t)
	// Mutate a seeded user, then re-seed: INSERT OR IGNORE must not overwrite.
	u, _ := st.GetUser(SeedUserAliceID)
	u.DisplayName = "Changed"
	st.UpdateUser(u)
	if _, err := st.Seed(testTenantID, testIssuer); err != nil {
		t.Fatalf("re-seed: %v", err)
	}
	again, _ := st.GetUser(SeedUserAliceID)
	if again.DisplayName != "Changed" {
		t.Fatalf("re-seed overwrote existing row: %q", again.DisplayName)
	}
}

// ---- hashing helpers ----

func TestHashingHelpers(t *testing.T) {
	enc, err := HashSecret("pw")
	if err != nil {
		t.Fatalf("HashSecret: %v", err)
	}
	if !VerifySecret("pw", enc) {
		t.Fatal("VerifySecret should accept correct plaintext")
	}
	if VerifySecret("nope", enc) {
		t.Fatal("VerifySecret should reject wrong plaintext")
	}
	// Malformed encodings.
	if VerifySecret("pw", "not-scrypt") {
		t.Fatal("wrong format should be false")
	}
	if VerifySecret("pw", "bcrypt$a$b") {
		t.Fatal("wrong algo prefix should be false")
	}
	if VerifySecret("pw", "scrypt$!!!$"+"zzz") {
		t.Fatal("bad salt b64 should be false")
	}
	if VerifySecret("pw", "scrypt$AAAA$!!!") {
		t.Fatal("bad hash b64 should be false")
	}
	// HashToken is deterministic.
	if HashToken("x") != HashToken("x") || HashToken("x") == HashToken("y") {
		t.Fatal("HashToken not deterministic/distinct")
	}
}

// ---- util helpers ----

func TestGUIDAndTokenHelpers(t *testing.T) {
	g := NewGUID()
	if len(g) != 36 || g[14] != '4' {
		t.Fatalf("NewGUID malformed: %q", g)
	}
	if NewGUID() == NewGUID() {
		t.Fatal("NewGUID should be unique")
	}
	tok := NewOpaqueToken(32)
	if tok == "" || NewOpaqueToken(32) == tok {
		t.Fatalf("NewOpaqueToken not random: %q", tok)
	}
}

func TestNullableHelpers(t *testing.T) {
	if nullable("") != nil {
		t.Fatal("nullable empty should be nil")
	}
	if nullable("x") != "x" {
		t.Fatal("nullable non-empty passthrough")
	}
	if nullableInt(0) != nil || nullableInt(5) != 5 {
		t.Fatal("nullableInt")
	}
	if nullableInt64(0) != nil {
		t.Fatal("nullableInt64 zero should be nil")
	}
	if v, ok := nullableInt64(7).(int64); !ok || v != 7 {
		t.Fatal("nullableInt64 non-zero passthrough")
	}
	if coalesceStr("", "def") != "def" || coalesceStr("v", "def") != "v" {
		t.Fatal("coalesceStr")
	}
	if orNow(0, 99) != 99 || orNow(5, 99) != 5 {
		t.Fatal("orNow")
	}
	if secretHint("ab") != "a…" {
		t.Fatalf("secretHint short = %q", secretHint("ab"))
	}
	if secretHint("abcdefgh") != "abc…gh" {
		t.Fatalf("secretHint long = %q", secretHint("abcdefgh"))
	}
}
