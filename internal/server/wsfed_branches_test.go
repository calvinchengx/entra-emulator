package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// Branches the walking skeleton never takes: an unknown tenant, a session
// already in the cookie jar, a picker POST that can no longer resolve the
// app, and the password/account refusals. Each must stay on the emulator
// (no Location to an unowned URL) rather than minting a wresult.

func TestWSFedUnknownTenantIsNotFound(t *testing.T) {
	hts, _, st := newTestServer(t)
	registerTasksAPI(t, st, tenant)
	resp, err := http.Get(hts.URL + "/00000000-0000-0000-0000-000000000000/wsfed?" + url.Values{
		"wa": {"wsignin1.0"}, "wtrealm": {testTasksAppIDURI}, "wreply": {testTasksWSFedReply},
	}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown tenant: want 404, got %d\n%s", resp.StatusCode, body)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Fatalf("unknown tenant redirected to %s", loc)
	}
}

func TestExistingSessionSkipsTheWSFedPicker(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPI(t, st, cfg.TenantID)
	c := samlClient(t)

	authURL := hts.URL + "/" + cfg.TenantID + "/oauth2/v2.0/authorize?" + url.Values{
		"client_id": {spaID}, "response_type": {"code"}, "redirect_uri": {redirect},
		"scope": {"openid"}, "state": {"s"},
		"code_challenge": {pkceChallenge(verifierPK)}, "code_challenge_method": {"S256"},
	}.Encode()
	page, err := c.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, page)
	post, err := c.PostForm(hts.URL+"/"+cfg.TenantID+"/oauth2/v2.0/authorize", url.Values{
		"__ee_state": {firstMatch(t, stateFieldRe, body, "signed state")},
		"__ee_user":  {aliceID},
	})
	if err != nil {
		t.Fatal(err)
	}
	readAll(t, post)

	resp, err := c.Get(wsfedChallengeURL(hts.URL, cfg.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	out := readAll(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("existing session: want 200 wresult, got %d\n%s", resp.StatusCode, out)
	}
	if strings.Contains(out, "Pick an account") {
		t.Fatal("existing session still showed Pick an account")
	}
	if !strings.Contains(out, `name="wresult"`) {
		t.Fatalf("existing session did not skip the picker:\n%s", out)
	}
}

func TestWSFedSignInRefusesAnAppDeletedAfterThePicker(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPI(t, st, cfg.TenantID)
	c := samlClient(t)
	resp, err := c.Get(wsfedChallengeURL(hts.URL, cfg.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, resp)
	if err := st.DeleteApp(testTasksAppID); err != nil {
		t.Fatal(err)
	}
	post, err := c.PostForm(hts.URL+"/"+cfg.TenantID+"/wsfed", url.Values{
		"__ee_state": {firstMatch(t, stateFieldRe, page, "signed state")},
		"__ee_user":  {firstMatch(t, userFieldRe, page, "an account to pick")},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := readAll(t, post)
	if post.StatusCode != http.StatusBadRequest {
		t.Fatalf("deleted app: want 400, got %d\n%s", post.StatusCode, out)
	}
	if strings.Contains(out, "wresult") {
		t.Fatal("deleted app still minted a wresult")
	}
	if loc := post.Header.Get("Location"); loc != "" {
		t.Fatalf("deleted app redirected to %s", loc)
	}
}

func TestWSFedSignInRefusesTheWrongPassword(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPI(t, st, cfg.TenantID)
	cfg.RequirePassword = true
	t.Cleanup(func() { cfg.RequirePassword = false })

	c := samlClient(t)
	resp, err := c.Get(wsfedChallengeURL(hts.URL, cfg.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, resp)
	post, err := c.PostForm(hts.URL+"/"+cfg.TenantID+"/wsfed", url.Values{
		"__ee_state":    {firstMatch(t, stateFieldRe, page, "signed state")},
		"__ee_username": {"alice@entraemulator.dev"},
		"__ee_password": {"wrong"},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := readAll(t, post)
	if post.StatusCode != http.StatusOK || !strings.Contains(strings.ToLower(out), "incorrect") {
		t.Fatalf("wrong password: want re-rendered form, got %d\n%s", post.StatusCode, out)
	}
	if strings.Contains(out, "wresult") {
		t.Fatal("wrong password minted a wresult")
	}
}

func TestWSFedSignInRefusesAnUnknownAccount(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPI(t, st, cfg.TenantID)
	c := samlClient(t)
	resp, err := c.Get(wsfedChallengeURL(hts.URL, cfg.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, resp)
	post, err := c.PostForm(hts.URL+"/"+cfg.TenantID+"/wsfed", url.Values{
		"__ee_state": {firstMatch(t, stateFieldRe, page, "signed state")},
		"__ee_user":  {"f73eb7b3-0790-40a3-b964-db34fd88e1c4"},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := readAll(t, post)
	if post.StatusCode != http.StatusOK || strings.Contains(out, "wresult") {
		t.Fatalf("unknown account: want picker re-render, got %d\n%s", post.StatusCode, out)
	}
}

func TestWSFedSignInRefusesADisabledAccountPostedDirectly(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPI(t, st, cfg.TenantID)
	c := samlClient(t)
	resp, err := c.Get(wsfedChallengeURL(hts.URL, cfg.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, resp)
	user, err := st.GetUser(store.SeedUserAliceID)
	if err != nil {
		t.Fatal(err)
	}
	user.AccountEnabled = false
	if err := st.UpdateUser(user); err != nil {
		t.Fatal(err)
	}
	post, err := c.PostForm(hts.URL+"/"+cfg.TenantID+"/wsfed", url.Values{
		"__ee_state": {firstMatch(t, stateFieldRe, page, "signed state")},
		"__ee_user":  {store.SeedUserAliceID},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := readAll(t, post)
	if strings.Contains(out, "wresult") {
		t.Fatalf("disabled account minted a wresult:\n%s", out)
	}
}

func TestWSFedSignInRefusesAnOIDCState(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	registerTasksAPI(t, st, cfg.TenantID)
	c := samlClient(t)
	authURL := hts.URL + "/" + cfg.TenantID + "/oauth2/v2.0/authorize?" + url.Values{
		"client_id": {spaID}, "response_type": {"code"}, "redirect_uri": {redirect},
		"scope": {"openid"}, "state": {"s"},
		"code_challenge": {pkceChallenge(verifierPK)}, "code_challenge_method": {"S256"},
	}.Encode()
	page, err := c.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, page)
	post, err := c.PostForm(hts.URL+"/"+cfg.TenantID+"/wsfed", url.Values{
		"__ee_state": {firstMatch(t, stateFieldRe, body, "signed state")},
		"__ee_user":  {aliceID},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := readAll(t, post)
	if post.StatusCode != http.StatusBadRequest || strings.Contains(out, "wresult") {
		t.Fatalf("OIDC state on /wsfed: want 400, got %d\n%s", post.StatusCode, out)
	}
}
