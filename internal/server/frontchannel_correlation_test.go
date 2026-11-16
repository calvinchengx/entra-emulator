package server

import (
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

func TestCreateAppFrontchannelLogoutURI(t *testing.T) {
	hts, _, _ := newTestServer(t)
	want := "https://localhost:3000/signout"
	status, app := postJSON(t, hts.URL+"/admin/api/apps", map[string]any{
		"displayName": "Logout registration", "frontchannelLogoutUri": want,
	})
	if status != http.StatusCreated {
		t.Fatalf("create: %d %v", status, app)
	}
	_, persisted := getJSON(t, hts.URL+"/admin/api/apps/"+app["id"].(string))
	if persisted["frontchannelLogoutUri"] != want {
		t.Fatalf("logout URI not persisted on creation: %v", persisted)
	}
}

// Exercise the actual authorize, code exchange, refresh and logout endpoints.
// A logout iframe is useful only if the RP learned the same sid in a signed
// ID token. Never expose the provider's bearer session cookie as that sid.
func TestFrontchannelSessionCorrelation(t *testing.T) {
	for _, scenario := range []struct {
		name              string
		consent, password bool
	}{
		{"picker", false, false}, {"consent", true, false}, {"password", false, true}, {"password-consent", true, true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			consent := scenario.consent
			hts, cfg, _ := newTestServer(t)
			cfg.RequireConsent = consent
			cfg.RequirePassword = scenario.password
			status, _ := patchJSON(t, hts.URL+"/admin/api/apps/"+spaID, map[string]any{
				"frontchannelLogoutUri": "https://localhost:3000/signout?keep=yes",
			})
			if status != http.StatusOK {
				t.Fatal(status)
			}
			client := noRedirectJar()
			authorize := hts.URL + "/" + tenant + "/oauth2/v2.0/authorize"
			var sessionCookieValue string
			var sid string
			for n, responseType := range []string{"code", "id_token", "code id_token"} {
				q := url.Values{
					"client_id": {spaID}, "response_type": {responseType}, "redirect_uri": {redirect},
					"scope": {"openid profile offline_access"}, "nonce": {"logout-nonce"},
					"code_challenge": {pkceChallenge(verifierPK)}, "code_challenge_method": {"S256"},
				}
				if n > 0 {
					q.Set("prompt", "none")
				}
				resp, err := client.Get(authorize + "?" + q.Encode())
				if err != nil {
					t.Fatal(err)
				}
				if n == 0 {
					body, _ := io.ReadAll(resp.Body)
					resp.Body.Close()
					state := stateRe.FindStringSubmatch(string(body))
					if state == nil {
						t.Fatalf("no picker state: %s", body)
					}
					form := url.Values{"__ee_state": {html.UnescapeString(state[1])}, "__ee_user": {aliceID}}
					if scenario.password {
						form.Set("__ee_username", "alice@entraemulator.dev")
						form.Set("__ee_password", "Password1!")
					}
					resp, err = client.PostForm(authorize, form)
					if err != nil {
						t.Fatal(err)
					}
					if consent {
						body, _ = io.ReadAll(resp.Body)
						resp.Body.Close()
						state = stateRe.FindStringSubmatch(string(body))
						if state == nil {
							t.Fatalf("no consent state: %s", body)
						}
						resp, err = client.PostForm(authorize, url.Values{"__ee_state": {html.UnescapeString(state[1])}, "__ee_consent": {"1"}, "__ee_decision": {"approve"}})
						if err != nil {
							t.Fatal(err)
						}
					}
					origin, _ := url.Parse(hts.URL)
					for _, c := range client.Jar.Cookies(origin) {
						if c.Name == "ee_session" {
							sessionCookieValue = c.Value
						}
					}
					if sessionCookieValue == "" {
						t.Fatal("sign-in did not establish a provider session")
					}
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusFound {
					t.Fatalf("authorize %s: %d", responseType, resp.StatusCode)
				}
				loc, err := url.Parse(resp.Header.Get("Location"))
				if err != nil {
					t.Fatal(err)
				}
				values := loc.Query()
				if loc.Fragment != "" {
					values, err = url.ParseQuery(loc.Fragment)
					if err != nil {
						t.Fatal(err)
					}
				}
				assertSID := func(token string) {
					t.Helper()
					claims := decodeJWTPayload(t, token)
					got, _ := claims["sid"].(string)
					if got == "" || got == sessionCookieValue {
						t.Fatalf("sid must be nonempty and distinct from the bearer cookie: %v", claims)
					}
					if sid == "" {
						sid = got
					} else if got != sid {
						t.Fatalf("sid changed within one session: %s != %s", got, sid)
					}
				}
				if responseType != "code" {
					assertSID(values.Get("id_token"))
				}
				if code := values.Get("code"); code != "" {
					response, tokens := postForm(t, client, hts.URL+"/"+tenant+"/oauth2/v2.0/token", url.Values{
						"grant_type": {"authorization_code"}, "client_id": {spaID}, "code": {code}, "redirect_uri": {redirect}, "code_verifier": {verifierPK},
					})
					if response.StatusCode != http.StatusOK {
						t.Fatalf("exchange: %v", tokens)
					}
					assertSID(tokens["id_token"].(string))
					for range 2 {
						response, tokens = postForm(t, client, hts.URL+"/"+tenant+"/oauth2/v2.0/token", url.Values{
							"grant_type": {"refresh_token"}, "client_id": {spaID}, "refresh_token": {tokens["refresh_token"].(string)},
						})
						if response.StatusCode != http.StatusOK {
							t.Fatalf("refresh: %v", tokens)
						}
						assertSID(tokens["id_token"].(string))
					}
				}
			}
			cfg.RequireConsent = false // the helper drives the picker, not consent
			cfg.RequirePassword = false
			other := driveAuthCode(t, hts, verifierPK)
			cfg.RequireConsent = consent
			cfg.RequirePassword = scenario.password
			otherSID, _ := decodeJWTPayload(t, other["id_token"].(string))["sid"].(string)
			if otherSID == "" || otherSID == sid {
				t.Fatal("independent browser sessions need distinct logout identifiers")
			}
			resp, err := client.Get(hts.URL + "/" + tenant + "/oauth2/v2.0/logout")
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			frame := regexp.MustCompile(`<iframe src="([^"]+)"`).FindStringSubmatch(string(body))
			if frame == nil {
				t.Fatalf("no logout iframe: %s", body)
			}
			logoutURL, err := url.Parse(html.UnescapeString(frame[1]))
			if err != nil {
				t.Fatal(err)
			}
			if logoutURL.Query().Get("sid") != sid || logoutURL.Query().Get("iss") != cfg.Issuer || logoutURL.Query().Get("keep") != "yes" {
				t.Fatalf("iframe must preserve query and match signed token: %s", logoutURL)
			}
			if strings.Contains(string(body), sessionCookieValue) {
				t.Fatal("logout page leaks bearer session cookie")
			}
		})
	}
}

func TestLogoutStateWithAndWithoutFrontchannel(t *testing.T) {
	for _, frontchannel := range []bool{false, true} {
		t.Run(map[bool]string{false: "redirect", true: "frontchannel"}[frontchannel], func(t *testing.T) {
			hts, _, st := newTestServer(t)
			client := noRedirectJar()
			// Use a real signed-in session even when there is no RP notification.
			authorize := hts.URL + "/" + tenant + "/oauth2/v2.0/authorize"
			state := authPickerState(t, client, authorize+"?"+url.Values{"client_id": {spaID}, "response_type": {"code"}, "redirect_uri": {redirect}, "scope": {"openid"}, "code_challenge": {pkceChallenge(verifierPK)}, "code_challenge_method": {"S256"}}.Encode())
			resp, err := client.PostForm(authorize, url.Values{"__ee_state": {state}, "__ee_user": {aliceID}})
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if frontchannel {
				if err := st.SetFrontchannelLogoutURI(spaID, "https://localhost:3000/signout"); err != nil {
					t.Fatal(err)
				}
			}
			target := "https://localhost:3000/after?z=2&keep=1&flag"
			if _, err := st.AddRedirectURI(spaID, target, "web"); err != nil {
				t.Fatal(err)
			}
			q := url.Values{"client_id": {spaID}, "post_logout_redirect_uri": {target}, "state": {"round trip + & < > \""}}
			resp, err = client.Get(hts.URL + "/" + tenant + "/oauth2/v2.0/logout?" + q.Encode())
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			location := resp.Header.Get("Location")
			if frontchannel {
				m := regexp.MustCompile(`content="1;url=([^"]+)"`).FindStringSubmatch(string(body))
				if m == nil {
					t.Fatalf("no post-logout continuation: %s", body)
				}
				location = html.UnescapeString(m[1])
			}
			u, err := url.Parse(location)
			if err != nil {
				t.Fatal(err)
			}
			if u.Query().Get("state") != q.Get("state") || !strings.HasPrefix(u.RawQuery, "z=2&keep=1&flag&state=") {
				t.Fatalf("lost state or registered URI components: %s", location)
			}
		})
	}
}
