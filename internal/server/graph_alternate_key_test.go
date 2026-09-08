package server

import (
	"net/http"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// Graph lets a caller address a service principal by its appId rather than its
// object id: `servicePrincipals(appId='...')`. SDKs reach for it because it
// saves a $filter round trip. This emulator answered 404 with a NON-Graph body
// ("No such API route."), which a recorded Graph read caught: both the routing
// and the envelope were wrong, and neither was visible to our own tests because
// no test asked for the alternate-key form.
func TestGraphServicePrincipalByAlternateKey(t *testing.T) {
	hts, _, _ := newTestServer(t)
	tok := appGraphToken(t, hts.URL)

	t.Run("resolves to the same object as the canonical path", func(t *testing.T) {
		code, alt := graphGet(t, hts.URL, "/graph/v1.0/servicePrincipals(appId='"+daemonID+"')", tok)
		if code != http.StatusOK {
			t.Fatalf("alternate key: %d %v", code, alt)
		}
		codeCanon, canon := graphGet(t, hts.URL, "/graph/v1.0/servicePrincipals/"+daemonID, tok)
		if codeCanon != http.StatusOK {
			t.Fatalf("canonical: %d %v", codeCanon, canon)
		}
		if alt["id"] != canon["id"] || alt["id"] == nil {
			t.Errorf("alternate key resolved a different object: alt id=%v canonical id=%v", alt["id"], canon["id"])
		}
		if alt["appId"] != canon["appId"] {
			t.Errorf("appId differs: %v vs %v", alt["appId"], canon["appId"])
		}
	})

	t.Run("an appId belonging to nobody is a Graph 404", func(t *testing.T) {
		code, body := graphGet(t, hts.URL,
			"/graph/v1.0/servicePrincipals(appId='"+store.NewGUID()+"')", tok)
		if code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404: %v", code, body)
		}
		assertGraphErrorEnvelope(t, body, "Request_ResourceNotFound")
	})

	t.Run("$select applies through the alternate key too", func(t *testing.T) {
		code, body := graphGet(t, hts.URL,
			"/graph/v1.0/servicePrincipals(appId='"+daemonID+"')?$select=appId", tok)
		if code != http.StatusOK {
			t.Fatalf("status = %d: %v", code, body)
		}
		if _, ok := body["appId"]; !ok {
			t.Errorf("selected field missing: %v", body)
		}
		if _, ok := body["id"]; ok {
			t.Errorf("id must not be re-added when not selected: %v", body)
		}
	})
}

// An unknown resource under /v1.0/ must answer in GRAPH's envelope, not the
// router's. An SDK parsing the error should not have to special-case us: before
// this it got {"error":{"code":"not_found","message":"No such API route."}},
// which is neither Graph's code vocabulary nor Graph's shape.
func TestGraphUnknownResourceUsesGraphEnvelope(t *testing.T) {
	hts, _, _ := newTestServer(t)
	tok := appGraphToken(t, hts.URL)

	code, body := graphGet(t, hts.URL, "/graph/v1.0/noSuchResource", tok)
	if code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %v", code, body)
	}
	assertGraphErrorEnvelope(t, body, "Request_ResourceNotFound")
	if msg, _ := errField(body, "message").(string); msg == "No such API route." {
		t.Error("still the router's message rather than Graph's")
	}
}

// Every Graph error carries innerError over the wire, not just in the unit test
// for the writer: this asserts it survives the real handler stack.
func TestGraphErrorsCarryInnerErrorOverTheWire(t *testing.T) {
	hts, _, _ := newTestServer(t)
	tok := appGraphToken(t, hts.URL)

	cases := []struct {
		name, path string
		bearer     string
		want       int
	}{
		{"missing object", "/graph/v1.0/users/" + store.NewGUID(), tok, http.StatusNotFound},
		{"malformed id", "/graph/v1.0/users/not-a-valid-object-id", tok, http.StatusNotFound},
		{"unknown resource", "/graph/v1.0/noSuchResource", tok, http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := graphGet(t, hts.URL, tc.path, tc.bearer)
			if code != tc.want {
				t.Fatalf("status = %d, want %d: %v", code, tc.want, body)
			}
			assertInnerError(t, body)
		})
	}

	t.Run("unauthenticated", func(t *testing.T) {
		// No Authorization header at all, which Entra distinguishes from an
		// empty or malformed one.
		code, body := getJSON(t, hts.URL+"/graph/v1.0/users/"+aliceID)
		if code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401: %v", code, body)
		}
		assertInnerError(t, body)
		if msg, _ := errField(body, "message").(string); msg != "Access token is empty." {
			t.Errorf("message = %q, want Entra's exact wording for an absent token", msg)
		}
	})
}

func errField(body map[string]any, key string) any {
	e, _ := body["error"].(map[string]any)
	if e == nil {
		return nil
	}
	return e[key]
}

func assertGraphErrorEnvelope(t *testing.T, body map[string]any, wantCode string) {
	t.Helper()
	if got, _ := errField(body, "code").(string); got != wantCode {
		t.Errorf("error.code = %q, want %q (body %v)", got, wantCode, body)
	}
	assertInnerError(t, body)
}

func assertInnerError(t *testing.T, body map[string]any) {
	t.Helper()
	inner, _ := errField(body, "innerError").(map[string]any)
	if inner == nil {
		t.Fatalf("innerError missing: %v", body)
	}
	for _, k := range []string{"date", "request-id", "client-request-id"} {
		if s, _ := inner[k].(string); s == "" {
			t.Errorf("innerError.%s empty: %v", k, inner)
		}
	}
}
