// Authorization code + PKCE with a CUSTOM API scope, driven by MSAL Go.
//
// The existing Go suite covers client credentials and device code, both of
// which take different paths through scope handling. This one exercises the
// interactive path with a resource-qualified scope — the combination that a
// line-of-business app calling its own API actually uses, and the one where
// MSAL's scope bookkeeping is strictest.
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"

	"github.com/calvinchengx/entra-emulator/emulator"
)

var stateField = regexp.MustCompile(`name="__ee_state" value="([^"]+)"`)

// pkcePair returns a verifier and its S256 challenge.
func pkcePair(t *testing.T) (verifier, challenge string) {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// signInForCode drives the emulator's real sign-in page and returns the
// authorization code from the redirect. This is the part a browser would do;
// everything after it is MSAL's.
func signInForCode(t *testing.T, emu *emulator.Emulator, authURL, redirectURI string) string {
	t.Helper()
	hc := emu.HTTPClient()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	hc.Jar = jar
	// Stop at the redirect so the code can be read off the Location header.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := hc.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatal(err)
	}
	m := stateField.FindStringSubmatch(buf.String())
	if m == nil {
		t.Fatalf("no sign-in form at the authorize endpoint (status %d): %s",
			resp.StatusCode, truncate(buf.String()))
	}

	// The account picker: choose alice.
	post, err := hc.PostForm(authURL, url.Values{
		"__ee_state": {m[1]}, "__ee_user": {emulator.AliceOID},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer post.Body.Close()
	loc := post.Header.Get("Location")
	if loc == "" {
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(post.Body)
		t.Fatalf("no redirect after sign-in (status %d): %s", post.StatusCode, truncate(body.String()))
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	if e := u.Query().Get("error"); e != "" {
		t.Fatalf("authorize returned %s: %s", e, u.Query().Get("error_description"))
	}
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect %q", loc)
	}
	return code
}

func truncate(s string) string {
	if len(s) > 400 {
		return s[:400] + "…"
	}
	return s
}

func TestMSALGoAuthCodeWithCustomAPIScope(t *testing.T) {
	emu := emulator.StartT(t, emulator.WithTLS())
	exposeScope(t, emu, emulator.DaemonClientID, "access_as_user")

	const redirectURI = "http://localhost:3000/callback"
	registerRedirectURI(t, emu, emulator.SPAClientID, redirectURI)

	pca, err := public.New(emulator.SPAClientID,
		public.WithAuthority(emu.Authority()),
		public.WithHTTPClient(emu.HTTPClient()),
		public.WithInstanceDiscovery(false))
	if err != nil {
		t.Fatal(err)
	}

	// The fully-qualified custom API scope alongside the OIDC scopes, as a real
	// line-of-business app requests them.
	scopes := []string{"openid", "profile", middleTierScope}
	verifier, challenge := pkcePair(t)

	authURL, err := pca.AuthCodeURL(context.Background(), emulator.SPAClientID, redirectURI, scopes)
	if err != nil {
		t.Fatal(err)
	}
	// MSAL Go's AuthCodeURL has no PKCE option — the caller appends the
	// challenge, which is the documented usage. The verifier goes back in on
	// redemption below.
	authURL += "&code_challenge=" + url.QueryEscape(challenge) + "&code_challenge_method=S256"
	code := signInForCode(t, emu, authURL, redirectURI)

	result, err := pca.AcquireTokenByAuthCode(context.Background(), code, redirectURI, scopes,
		public.WithChallenge(verifier))
	if err != nil {
		t.Fatalf("MSAL Go could not redeem the code for a custom API scope: %v", err)
	}

	claims := oboClaims(t, result.AccessToken)
	if got := claims["aud"]; got != "api://"+emulator.DaemonClientID {
		t.Errorf("aud = %v, want the custom API", got)
	}
	if claims["oid"] != emulator.AliceOID {
		t.Errorf("oid = %v, want alice", claims["oid"])
	}
	// The scp CLAIM carries short names — that is Entra's shape and is not
	// what the response `scope` reports.
	if scp, _ := claims["scp"].(string); !strings.Contains(scp, "access_as_user") {
		t.Errorf("scp = %q, want the short scope name", scp)
	}
	// MSAL only reports a scope as granted when the response echoed it back;
	// anything else it treats as declined and fails the acquisition above.
	if len(result.GrantedScopes) == 0 {
		t.Error("MSAL reports no granted scopes")
	}
}

// registerRedirectURI adds a redirect URI to an app through the admin API.
func registerRedirectURI(t *testing.T, emu *emulator.Emulator, appID, uri string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"uri": uri, "type": "web"})
	resp, err := emu.HTTPClient().Post(
		emu.Origin+"/admin/api/apps/"+appID+"/redirectUris", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusConflict {
		t.Fatalf("register redirect uri: %d", resp.StatusCode)
	}
}
