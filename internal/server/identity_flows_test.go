package server

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// postFormHTML posts a form and returns the status and HTML body.
func postFormHTML(t *testing.T, client *http.Client, u string, form url.Values) (int, string) {
	t.Helper()
	resp, err := client.PostForm(u, form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

// TestDeviceCodeBrowserApproval drives the human verification UI end-to-end:
// code entry → account pick → consent approve → device poll succeeds. This
// exercises the device-code HTML state machine the token-grant test skips.
func TestDeviceCodeBrowserApproval(t *testing.T) {
	hts, _, _ := newTestServer(t)
	base := hts.URL + "/" + tenant + "/oauth2/v2.0"

	_, da := postForm(t, http.DefaultClient, base+"/devicecode", url.Values{
		"client_id": {spaID}, "scope": {"openid profile offline_access"},
	})
	userCode := da["user_code"].(string)
	deviceCode := da["device_code"].(string)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// Code-entry page renders (GET).
	if resp, err := client.Get(base + "/devicecode?user_code=" + userCode); err != nil || resp.StatusCode != 200 {
		t.Fatalf("code entry page: %v %v", err, resp)
	}

	// lookup step (no session) → account picker with a signed state.
	verify := base + "/devicecode/verify"
	code, html := postFormHTML(t, client, verify, url.Values{"__ee_step": {"lookup"}, "user_code": {userCode}})
	if code != 200 {
		t.Fatalf("lookup step: %d", code)
	}
	m := stateRe.FindStringSubmatch(html)
	if m == nil {
		t.Fatalf("no signed state after lookup: %s", html[:min(300, len(html))])
	}

	// signin step → creates a session, renders the consent screen with a new state.
	code, html = postFormHTML(t, client, verify, url.Values{
		"__ee_step": {"signin"}, "__ee_state": {m[1]}, "__ee_user": {aliceID},
	})
	if code != 200 || !strings.Contains(html, "Approve sign-in") {
		t.Fatalf("signin step did not reach consent: %d", code)
	}
	m = stateRe.FindStringSubmatch(html)
	if m == nil {
		t.Fatalf("no signed state on consent page")
	}

	// decide step → approve.
	code, html = postFormHTML(t, client, verify, url.Values{
		"__ee_step": {"decide"}, "__ee_state": {m[1]}, "__ee_decision": {"approve"},
	})
	if code != 200 || !strings.Contains(html, "all set") {
		t.Fatalf("approve step: %d %q", code, html[:min(200, len(html))])
	}

	// Device poll now succeeds and carries Alice.
	resp, body := postForm(t, http.DefaultClient, base+"/token", url.Values{
		"grant_type": {"device_code"}, "device_code": {deviceCode}, "client_id": {spaID},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("approved device poll: %d %v", resp.StatusCode, body)
	}
	if idc := decodeJWTPayload(t, body["id_token"].(string)); idc["oid"] != aliceID {
		t.Fatalf("device token oid = %v, want alice", idc["oid"])
	}
}

// TestDeviceCodeBrowserDeny covers the deny branch of the consent screen.
func TestDeviceCodeBrowserDeny(t *testing.T) {
	hts, _, _ := newTestServer(t)
	base := hts.URL + "/" + tenant + "/oauth2/v2.0"

	_, da := postForm(t, http.DefaultClient, base+"/devicecode", url.Values{
		"client_id": {spaID}, "scope": {"openid"},
	})
	userCode := da["user_code"].(string)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	verify := base + "/devicecode/verify"

	_, html := postFormHTML(t, client, verify, url.Values{"__ee_step": {"lookup"}, "user_code": {userCode}})
	m := stateRe.FindStringSubmatch(html)
	_, html = postFormHTML(t, client, verify, url.Values{
		"__ee_step": {"signin"}, "__ee_state": {m[1]}, "__ee_user": {aliceID},
	})
	m = stateRe.FindStringSubmatch(html)
	if code, _ := postFormHTML(t, client, verify, url.Values{
		"__ee_step": {"decide"}, "__ee_state": {m[1]}, "__ee_decision": {"deny"},
	}); code != 200 {
		t.Fatalf("deny step: %d", code)
	}

	resp, body := postForm(t, http.DefaultClient, base+"/token", url.Values{
		"grant_type": {"device_code"}, "device_code": {da["device_code"].(string)}, "client_id": {spaID},
	})
	if resp.StatusCode != 400 || body["error"] != "authorization_declined" {
		t.Fatalf("denied poll: want authorization_declined, got %d %v", resp.StatusCode, body)
	}
}

// TestLogout covers the end_session endpoint's three outcomes.
func TestLogout(t *testing.T) {
	hts, _, _ := newTestServer(t)
	base := hts.URL + "/" + tenant + "/oauth2/v2.0/logout"
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// Validated post_logout_redirect_uri (seeded SPA redirect) → 302 with state.
	resp, err := client.Get(base + "?" + url.Values{
		"client_id":                {spaID},
		"post_logout_redirect_uri": {redirect},
		"state":                    {"bye"},
	}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 || !strings.Contains(resp.Header.Get("Location"), "state=bye") {
		t.Fatalf("logout redirect: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// No redirect param → signed-out page (200).
	if resp, _ = client.Get(base); resp.StatusCode != 200 {
		t.Fatalf("signed-out page: %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Unvalidated redirect URI → signed-out page, never a redirect.
	resp, _ = client.Get(base + "?" + url.Values{
		"client_id": {spaID}, "post_logout_redirect_uri": {"https://evil.example/steal"},
	}.Encode())
	if resp.StatusCode != 200 {
		t.Fatalf("unvalidated redirect must not 302: got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// TestGroupsClaimEmission covers token-configuration group claims: with
// groupMembershipClaims=SecurityGroup, a delegated token carries the user's
// group object ids in the groups claim (exercises applyTokenConfig).
func TestGroupsClaimEmission(t *testing.T) {
	hts, _, _ := newTestServer(t)

	// Turn on group claims for the seeded SPA.
	if code, _ := patchJSON(t, hts.URL+"/admin/api/apps/"+spaID, map[string]any{
		"groupMembershipClaims": "SecurityGroup",
	}); code != 200 {
		t.Fatalf("enable group claims: %d", code)
	}

	body := driveAuthCode(t, hts, "verifier-groups-claim-0123456789abcd")
	claims := decodeJWTPayload(t, body["access_token"].(string))
	groups, ok := claims["groups"].([]any)
	if !ok || len(groups) == 0 {
		t.Fatalf("no groups claim emitted: %v", claims["groups"])
	}
	found := false
	for _, g := range groups {
		if g == store.SeedGroupEngID {
			found = true
		}
	}
	if !found {
		t.Fatalf("Engineering group id missing from groups claim: %v", groups)
	}
}
