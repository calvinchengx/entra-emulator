package server

import (
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/store"
	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

func TestFrontchannelLogoutQueryParameters(t *testing.T) {
	hts, cfg, st := newTestServer(t)
	for _, suffix := range []string{"?", "?keep=a%20b&iss=stale&sid=stale", "?flag&keep=a%20b&%69ss=stale", "?a=1;b=2&sid=stale"} {
		t.Run(suffix, func(t *testing.T) {
			if err := st.SetFrontchannelLogoutURI(spaID, "https://localhost:3000/logout"+suffix); err != nil {
				t.Fatal(err)
			}
			session := &store.Session{ID: store.NewOpaqueToken(24), UserID: aliceID, CreatedAt: st.Now(), ExpiresAt: st.Now() + 3600}
			if err := st.CreateSession(session); err != nil {
				t.Fatal(err)
			}
			if err := st.RecordSessionApp(session.ID, spaID); err != nil {
				t.Fatal(err)
			}
			client := noRedirectJar()
			origin, _ := url.Parse(hts.URL)
			client.Jar.SetCookies(origin, []*http.Cookie{{Name: "ee_session", Value: session.ID, Path: "/"}})
			resp, err := client.Get(hts.URL + "/" + tenant + "/oauth2/v2.0/logout")
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			frame := regexp.MustCompile(`<iframe src="([^"]+)"`).FindStringSubmatch(string(body))
			if frame == nil {
				t.Fatalf("no iframe: %s", body)
			}
			u, err := url.Parse(html.UnescapeString(frame[1]))
			if err != nil {
				t.Fatal(err)
			}
			q := u.Query()
			if q.Get("iss") != cfg.Issuer || q.Get("sid") != tokens.FrontchannelSID(session.ID) || len(q["iss"]) != 1 || len(q["sid"]) != 1 {
				t.Fatalf("wrong notification query: %s", u)
			}
			if strings.Contains(suffix, "keep=") && q.Get("keep") != "a b" {
				t.Fatalf("lost existing query: %s", u)
			}
			if strings.HasPrefix(suffix, "?flag&") && !strings.HasPrefix(u.RawQuery, "flag&keep=a%20b&") {
				t.Fatalf("re-encoded application query: %s", u)
			}
			if strings.HasPrefix(suffix, "?a=1;b=2") && !strings.HasPrefix(u.RawQuery, "a=1;b=2&") {
				t.Fatalf("discarded application query: %s", u)
			}
		})
	}
}

func TestFrontchannelLogoutRegistrationRejectsUnsafeURLs(t *testing.T) {
	hts, _, st := newTestServer(t)
	const safe = "https://localhost:3000/logout"
	for _, unsafe := range []string{
		"javascript:alert(document.domain)", "data:text/html,<script>alert(1)</script>",
		"//attacker.example/logout", "/logout", "https://user:password@localhost:3000/logout",
		"https://localhost:3000/logout#fragment", "https://localhost:3000/logout#", "https://localhost:bad/logout",
	} {
		t.Run(unsafe, func(t *testing.T) {
			_, before := getJSON(t, hts.URL+"/admin/api/apps")
			status, _ := postJSON(t, hts.URL+"/admin/api/apps", map[string]any{"displayName": "Unsafe", "frontchannelLogoutUri": unsafe})
			_, after := getJSON(t, hts.URL+"/admin/api/apps")
			beforeCount, beforeOK := before["count"].(float64)
			afterCount, afterOK := after["count"].(float64)
			if status != http.StatusBadRequest || !beforeOK || !afterOK || beforeCount != afterCount {
				t.Fatal("unsafe create must fail before writing")
			}
			if err := st.SetFrontchannelLogoutURI(spaID, safe); err != nil {
				t.Fatal(err)
			}
			status, _ = patchJSON(t, hts.URL+"/admin/api/apps/"+spaID, map[string]any{"displayName": "Must not apply", "frontchannelLogoutUri": unsafe})
			got, err := st.FrontchannelLogoutURI(spaID)
			if err != nil || status != http.StatusBadRequest || got != safe {
				t.Fatal("unsafe patch must preserve existing registration")
			}
			app, err := st.GetApp(spaID)
			if err != nil || app.DisplayName == "Must not apply" {
				t.Fatal("unsafe patch must not apply other fields")
			}
		})
	}
	status, _ := patchJSON(t, hts.URL+"/admin/api/apps/"+spaID, map[string]any{"frontchannelLogoutUri": ""})
	_, app := getJSON(t, hts.URL+"/admin/api/apps/"+spaID)
	if status != http.StatusOK || app["frontchannelLogoutUri"] != nil {
		t.Fatal("empty URL must clear registration")
	}
}

func TestFrontchannelLogoutDoesNotRenderLegacyUnsafeURL(t *testing.T) {
	hts, _, st := newTestServer(t)
	if err := st.SetFrontchannelLogoutURI(spaID, "javascript:alert(document.domain)"); err != nil {
		t.Fatal(err)
	}
	session := &store.Session{ID: store.NewOpaqueToken(24), UserID: aliceID, CreatedAt: st.Now(), ExpiresAt: st.Now() + 3600}
	if err := st.CreateSession(session); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordSessionApp(session.ID, spaID); err != nil {
		t.Fatal(err)
	}
	client := noRedirectJar()
	origin, _ := url.Parse(hts.URL)
	client.Jar.SetCookies(origin, []*http.Cookie{{Name: "ee_session", Value: session.ID, Path: "/"}})
	resp, err := client.Get(hts.URL + "/" + tenant + "/oauth2/v2.0/logout")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || strings.Contains(string(body), "<iframe") || strings.Contains(string(body), "javascript:") {
		t.Fatalf("unsafe persisted URL rendered: %s", body)
	}
	if _, err := st.GetSession(session.ID); err != store.ErrNotFound {
		t.Fatal("provider session must still be cleared")
	}
}
