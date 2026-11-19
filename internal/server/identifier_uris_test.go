package server

import (
	"net/http"
	"net/url"
	"slices"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// TestMultipleIdentifierURIs proves an app with several identifierUris is a
// resource under each of them: delegated scopes and client-credentials
// `.default` resolve through any URI, and the token's aud is the URI asked for.
func TestMultipleIdentifierURIs(t *testing.T) {
	hts, _, st := newTestServer(t)
	gtok := appGraphToken(t, hts.URL)
	uris := []string{"api://multi", "https://multi.example.com"}

	code, created := graphSend(t, "POST", hts.URL, "/graph/v1.0/applications", gtok, map[string]any{
		"displayName": "Multi API", "identifierUris": uris,
	})
	if code != 201 {
		t.Fatalf("create application: %d %v", code, created)
	}
	appID := created["appId"].(string)
	if err := st.AddScope(&store.AppScope{ID: store.NewGUID(), AppID: appID, Value: "Data.Read", IsEnabled: true}); err != nil {
		t.Fatalf("add scope: %v", err)
	}
	if err := st.AddRole(&store.AppRole{ID: store.NewGUID(), AppID: appID, Value: "Data.Read.All",
		AllowedMemberTypes: "Application", IsEnabled: true}); err != nil {
		t.Fatalf("add role: %v", err)
	}

	// Graph reports every URI, in order, on the application and its SP.
	_, appShape := graphGet(t, hts.URL, "/graph/v1.0/applications/"+appID, gtok)
	if got := strs(appShape["identifierUris"]); !slices.Equal(got, uris) {
		t.Fatalf("identifierUris: want %v, got %v", uris, got)
	}
	_, spShape := graphGet(t, hts.URL, "/graph/v1.0/servicePrincipals/"+appID, gtok)
	if got := strs(spShape["servicePrincipalNames"]); !slices.Equal(got, append([]string{appID}, uris...)) {
		t.Fatalf("servicePrincipalNames: got %v", got)
	}

	for _, uri := range uris {
		// Delegated: the scope resolves through this URI; aud is the URI.
		claims := decodeJWTPayload(t, ropcAccessToken(t, hts.URL, spaID, uri+"/Data.Read"))
		if claims["aud"] != uri || claims["scp"] != "Data.Read" {
			t.Fatalf("delegated via %s: aud %v scp %v", uri, claims["aud"], claims["scp"])
		}
		// Client credentials: .default through this URI; aud is the URI.
		claims = appTokenForResource(t, hts.URL, uri)
		if claims["aud"] != uri || !slices.Contains(rolesOf(claims), "Data.Read.All") {
			t.Fatalf("app-only via %s: aud %v roles %v", uri, claims["aud"], claims["roles"])
		}
	}

	// A URI another app already holds is refused, even in a later position.
	code, body := graphSend(t, "POST", hts.URL, "/graph/v1.0/applications", gtok, map[string]any{
		"displayName": "Clash", "identifierUris": []string{"api://clash", uris[1]},
	})
	if code == 201 {
		t.Fatalf("duplicate identifier URI accepted: %v", body)
	}

	// PATCH replaces the set: the dropped URI no longer resolves.
	if code, body := graphSend(t, "PATCH", hts.URL, "/graph/v1.0/applications/"+appID, gtok, map[string]any{
		"identifierUris": []string{uris[1]},
	}); code != 204 {
		t.Fatalf("patch identifierUris: %d %v", code, body)
	}
	_, resp := postForm(t, http.DefaultClient, hts.URL+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type": {"password"}, "client_id": {spaID},
		"username": {"alice@entraemulator.dev"}, "password": {store.SeedPassword},
		"scope": {uris[0] + "/Data.Read"},
	})
	if resp["access_token"] != nil {
		t.Fatalf("dropped URI still grants a token: %v", resp)
	}
	claims := decodeJWTPayload(t, ropcAccessToken(t, hts.URL, spaID, uris[1]+"/Data.Read"))
	if claims["aud"] != uris[1] {
		t.Fatalf("remaining URI: aud %v", claims["aud"])
	}
}

func strs(v any) []string {
	raw, _ := v.([]any)
	out := make([]string, 0, len(raw))
	for _, x := range raw {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
