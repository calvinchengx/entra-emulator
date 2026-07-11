package server

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
)

// driveToConsent runs authorize + sign-in and returns the consent page's
// signed state (the client's jar holds the session cookie).
func driveToConsent(t *testing.T, origin string, client *http.Client) string {
	t.Helper()
	authURL := origin + "/" + tenant + "/oauth2/v2.0/authorize?" + url.Values{
		"client_id": {spaID}, "response_type": {"code"}, "redirect_uri": {redirect},
		"scope": {"openid profile User.Read"}, "state": {"cst"},
		"code_challenge": {pkceChallenge(verifierPK)}, "code_challenge_method": {"S256"},
	}.Encode()
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := stateRe.FindStringSubmatch(string(raw))
	if m == nil {
		t.Fatalf("no state in picker: %.200s", raw)
	}
	// Select Alice; with consent on this returns the consent page, not a 302.
	resp, err = client.PostForm(origin+"/"+tenant+"/oauth2/v2.0/authorize", url.Values{
		"__ee_state": {m[1]}, "__ee_user": {aliceID},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(raw), "Permissions requested") {
		t.Fatalf("expected consent page, got %d %.200s", resp.StatusCode, raw)
	}
	cm := stateRe.FindStringSubmatch(string(raw))
	if cm == nil {
		t.Fatalf("no state on consent page")
	}
	return cm[1]
}

func TestConsentApprove(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	cfg.RequireConsent = true // handlers read cfg live

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	consentState := driveToConsent(t, hts.URL, client)

	resp, err := client.PostForm(hts.URL+"/"+tenant+"/oauth2/v2.0/authorize", url.Values{
		"__ee_consent": {"1"}, "__ee_state": {consentState}, "__ee_decision": {"approve"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 {
		t.Fatalf("approve should 302 with a code, got %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Query().Get("code") == "" {
		t.Fatalf("no code after consent approve: %s", loc)
	}

	resp2, body := postForm(t, http.DefaultClient, hts.URL+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")},
		"redirect_uri": {redirect}, "client_id": {spaID}, "code_verifier": {verifierPK},
	})
	if resp2.StatusCode != 200 {
		t.Fatalf("token exchange after consent: %d %v", resp2.StatusCode, body)
	}
}

func TestConsentDeny(t *testing.T) {
	hts, cfg, _ := newTestServer(t)
	cfg.RequireConsent = true

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	consentState := driveToConsent(t, hts.URL, client)

	resp, err := client.PostForm(hts.URL+"/"+tenant+"/oauth2/v2.0/authorize", url.Values{
		"__ee_consent": {"1"}, "__ee_state": {consentState}, "__ee_decision": {"deny"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 {
		t.Fatalf("deny should redirect, got %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Query().Get("error") != "access_denied" {
		t.Fatalf("deny should redirect with error=access_denied, got %s", loc)
	}
}
