package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// authorizeAs drives the account picker and returns the final response for the
// given authorize query — the front-channel result implicit/hybrid deliver.
func authorizeAs(t *testing.T, hts string, q url.Values) *http.Response {
	t.Helper()
	authorize := hts + "/" + tenant + "/oauth2/v2.0/authorize"
	client := noRedirectJar()
	state := authPickerState(t, client, authorize+"?"+q.Encode())
	resp, err := client.PostForm(authorize, url.Values{
		"__ee_state": {state}, "__ee_user": {aliceID},
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func baseAuthorizeQuery(responseType string) url.Values {
	return url.Values{
		"client_id": {spaID}, "response_type": {responseType},
		"redirect_uri": {redirect}, "scope": {"openid profile"},
		"state": {"s1"}, "nonce": {"n1"},
	}
}

// TestImplicitAndHybridFlows covers response_type=id_token and
// code id_token — real Entra advertises both. The id_token must be a genuine
// signed token, delivered through the front channel under OIDC's rules: never
// on the query string, and only with a nonce.
func TestImplicitAndHybridFlows(t *testing.T) {
	hts, _, _ := newTestServer(t)

	t.Run("implicit returns a real id_token in the fragment", func(t *testing.T) {
		resp := authorizeAs(t, hts.URL, baseAuthorizeQuery("id_token"))
		defer resp.Body.Close()
		loc := resp.Header.Get("Location")
		if !strings.Contains(loc, "#") {
			t.Fatalf("implicit must deliver via fragment, got %q", loc)
		}
		frag := loc[strings.Index(loc, "#")+1:]
		vals, err := url.ParseQuery(frag)
		if err != nil {
			t.Fatal(err)
		}
		if vals.Get("code") != "" {
			t.Errorf("response_type=id_token must not return a code")
		}
		idToken := vals.Get("id_token")
		if idToken == "" {
			t.Fatalf("no id_token in fragment: %q", frag)
		}
		claims := decodeJWTPayload(t, idToken)
		if claims["nonce"] != "n1" {
			t.Errorf("nonce must be echoed into the id_token, got %v", claims["nonce"])
		}
		if claims["oid"] != aliceID || claims["aud"] != spaID {
			t.Errorf("id_token not issued for the signed-in user/app: %v", claims)
		}
		if vals.Get("state") != "s1" {
			t.Errorf("state must round-trip, got %q", vals.Get("state"))
		}
	})

	t.Run("hybrid returns both a code and an id_token", func(t *testing.T) {
		q := baseAuthorizeQuery("code id_token")
		q.Set("code_challenge", pkceChallenge("verifier-hybrid-0123456789abcdefghij"))
		q.Set("code_challenge_method", "S256")
		resp := authorizeAs(t, hts.URL, q)
		defer resp.Body.Close()
		loc := resp.Header.Get("Location")
		vals, _ := url.ParseQuery(loc[strings.Index(loc, "#")+1:])
		if vals.Get("code") == "" || vals.Get("id_token") == "" {
			t.Fatalf("hybrid must return code AND id_token, got %q", loc)
		}
	})

	// Both of these are rejected at the GET, before any sign-in page renders —
	// the request is malformed regardless of who the user turns out to be.
	authorizeGET := func(t *testing.T, q url.Values) string {
		t.Helper()
		resp, err := noRedirectJar().Get(hts.URL + "/" + tenant + "/oauth2/v2.0/authorize?" + q.Encode())
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.Header.Get("Location")
	}

	t.Run("an id_token is never delivered on the query string", func(t *testing.T) {
		q := baseAuthorizeQuery("id_token")
		q.Set("response_mode", "query")
		if loc := authorizeGET(t, q); !strings.Contains(loc, "error=invalid_request") {
			t.Fatalf("response_mode=query with an id_token must be refused, got %q", loc)
		}
	})

	t.Run("a nonce is required", func(t *testing.T) {
		q := baseAuthorizeQuery("id_token")
		q.Del("nonce")
		if loc := authorizeGET(t, q); !strings.Contains(loc, "error=invalid_request") {
			t.Fatalf("a missing nonce must be refused, got %q", loc)
		}
	})

	t.Run("discovery advertises exactly what is implemented", func(t *testing.T) {
		_, doc := getJSON(t, hts.URL+"/"+tenant+"/v2.0/.well-known/openid-configuration")
		got := map[string]bool{}
		for _, v := range asStrings(doc["response_types_supported"]) {
			got[v] = true
		}
		for _, want := range []string{"code", "id_token", "code id_token"} {
			if !got[want] {
				t.Errorf("discovery should advertise %q", want)
			}
		}
		// Not implemented, so it must not be advertised.
		if got["id_token token"] {
			t.Errorf("id_token token is not implemented and must not be advertised")
		}
	})
}
