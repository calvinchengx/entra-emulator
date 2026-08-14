package identity

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/config"
	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

const (
	testTasksAppID      = "55556666-7777-8888-9999-000011112222"
	testTasksAppIDURI   = "api://tasks-api"
	testTasksWSFedReply = "https://rp.example.test/signin-wsfed"
)

func newTestIdentity(t *testing.T) (*Identity, *config.Config, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	getenv := func(k string) string {
		switch k {
		case "DB_PATH":
			return filepath.Join(dir, "test.db")
		case "TLS_ENABLED":
			return "false"
		case "ORIGIN_MODE":
			return "compat"
		case "PORT":
			return "8443"
		}
		return ""
	}
	cfg, err := config.Load(getenv)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.Seed(cfg.TenantID, cfg.Issuer); err != nil {
		t.Fatal(err)
	}
	signer, err := tokens.EnsureActiveKey(st, cfg.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Origins.Login = "https://login.test"
	id := New(cfg, st, &tokens.Service{Store: st, Signer: signer, Cfg: cfg}, nil, nil)
	return id, cfg, st
}

func registerTasksAPI(t *testing.T, st *store.Store, tenantID string) {
	t.Helper()
	app := &store.App{
		ID: testTasksAppID, TenantID: tenantID,
		DisplayName: "Tasks API", AppIDURI: testTasksAppIDURI,
	}
	if err := st.CreateApp(app); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AddRedirectURI(app.ID, testTasksWSFedReply, "wsfed-reply"); err != nil {
		t.Fatal(err)
	}
}

func alice(t *testing.T, st *store.Store) *store.User {
	t.Helper()
	u, err := st.GetUser(store.SeedUserAliceID)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func tasksState(tenant string) wsfedState {
	return wsfedState{
		Kind: "wsfed", Tenant: tenant,
		Wtrealm: testTasksAppIDURI, Wreply: testTasksWSFedReply,
	}
}

func wsfedRequest(method, tenant, rawQuery, body string) *http.Request {
	target := "/" + tenant + "/wsfed"
	if rawQuery != "" {
		target += "?" + rawQuery
	}
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	r.SetPathValue("tenant", tenant)
	return r
}

// These branches never happen on a healthy walking-skeleton path: the HTTP
// challenge refuses an unknown wtrealm before minting, and a live tenant
// always has a signing key. They still have to render an error rather than
// posting a broken wresult.

func TestDeliverWSFedResponseRefusesATenantWithNoSigningKey(t *testing.T) {
	id, cfg, st := newTestIdentity(t)
	registerTasksAPI(t, st, cfg.TenantID)
	rec := httptest.NewRecorder()
	id.deliverWSFedResponse(rec, wsfedRequest(http.MethodGet, "not-a-tenant", "", ""),
		tasksState("not-a-tenant"), alice(t, st))
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "No signing key") {
		t.Fatalf("want 500 signing-key refusal, got %d\n%s", rec.Code, rec.Body.String())
	}
}

func TestDeliverWSFedResponseRefusesAnAssertionItCannotMint(t *testing.T) {
	id, cfg, st := newTestIdentity(t)
	registerTasksAPI(t, st, cfg.TenantID)
	broken := tasksState(cfg.TenantID)
	broken.Wtrealm = ""
	rec := httptest.NewRecorder()
	id.deliverWSFedResponse(rec, wsfedRequest(http.MethodGet, cfg.TenantID, "", ""),
		broken, alice(t, st))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 when the assertion cannot be built, got %d\n%s", rec.Code, rec.Body.String())
	}
}

func TestIssueWSFedRSTRRefusesASignerWithNoCertificate(t *testing.T) {
	id, cfg, st := newTestIdentity(t)
	_, err := id.issueWSFedRSTR(nil, tasksState(cfg.TenantID), alice(t, st))
	if err == nil || !strings.Contains(err.Error(), "No signing certificate") {
		t.Fatalf("want certificate refusal, got %v", err)
	}
}

func TestIssueWSFedRSTRRefusesAnAssertionMissingAudience(t *testing.T) {
	id, cfg, st := newTestIdentity(t)
	signer, err := tokens.EnsureActiveKey(st, cfg.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	broken := tasksState(cfg.TenantID)
	broken.Wtrealm = ""
	if _, err := id.issueWSFedRSTR(signer, broken, alice(t, st)); err == nil {
		t.Fatal("want a refusal when wtrealm is empty")
	}
}

func TestRenderWSFedSignInSurfacesADirectoryReadFailure(t *testing.T) {
	id, cfg, st := newTestIdentity(t)
	st.Close()
	rec := httptest.NewRecorder()
	id.renderWSFedSignIn(rec, tasksState(cfg.TenantID), "")
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "Could not list accounts") {
		t.Fatalf("want 500 listing refusal, got %d\n%s", rec.Code, rec.Body.String())
	}
}

func TestResolveWSFedRelyingPartySurfacesAReplyURLReadFailure(t *testing.T) {
	id, cfg, st := newTestIdentity(t)
	registerTasksAPI(t, st, cfg.TenantID)
	orig := checkWSFedReply
	checkWSFedReply = func(*store.Store, string, string) (bool, error) {
		return false, errors.New("disk is on fire")
	}
	t.Cleanup(func() { checkWSFedReply = orig })

	_, err := id.resolveWSFedRelyingParty(testTasksAppIDURI, testTasksWSFedReply)
	if err == nil || !strings.Contains(err.Error(), "cannot read reply URLs") {
		t.Fatalf("want a wrapped read failure, got %v", err)
	}
}

func TestHandleWSFedUnknownTenantIsNotFound(t *testing.T) {
	id, _, _ := newTestIdentity(t)
	rec := httptest.NewRecorder()
	id.handleWSFed(rec, wsfedRequest(http.MethodGet, "00000000-0000-0000-0000-000000000000", "", ""))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown tenant: want 404, got %d\n%s", rec.Code, rec.Body.String())
	}
}

func TestWSFedSignInRefusesAForeignKind(t *testing.T) {
	id, cfg, st := newTestIdentity(t)
	registerTasksAPI(t, st, cfg.TenantID)
	signed := id.signState(wsfedState{Kind: "authorize", Tenant: cfg.TenantID,
		Wtrealm: testTasksAppIDURI, Wreply: testTasksWSFedReply})
	body := url.Values{fieldState: {signed}, fieldUser: {store.SeedUserAliceID}}.Encode()
	rec := httptest.NewRecorder()
	id.handleWSFed(rec, wsfedRequest(http.MethodPost, cfg.TenantID, "", body))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid or expired") {
		t.Fatalf("foreign Kind: want invalid-state page, got %d\n%s", rec.Code, rec.Body.String())
	}
}

func TestWSFedSignInRefusesGarbageState(t *testing.T) {
	id, cfg, st := newTestIdentity(t)
	registerTasksAPI(t, st, cfg.TenantID)
	body := url.Values{fieldState: {"not-a-mac"}, fieldUser: {store.SeedUserAliceID}}.Encode()
	rec := httptest.NewRecorder()
	id.handleWSFed(rec, wsfedRequest(http.MethodPost, cfg.TenantID, "", body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("garbage state: want 400, got %d\n%s", rec.Code, rec.Body.String())
	}
}
