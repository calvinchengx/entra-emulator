package server

import (
	"net/http"
	"net/url"
	"testing"
)

// TestDeviceVerifyErrorBranches covers deviceLookup/deviceSignIn/deviceDecide
// rejection branches through the verification endpoint.
func TestDeviceVerifyErrorBranches(t *testing.T) {
	hts, _, _ := newTestServer(t)
	verify := hts.URL + "/" + tenant + "/oauth2/v2.0/devicecode/verify"
	status := func(form url.Values) int {
		resp, _ := postForm(t, http.DefaultClient, verify, form)
		return resp.StatusCode
	}

	// lookup with an empty user_code → re-renders the code-entry page (200).
	if s := status(url.Values{"__ee_step": {"lookup"}, "user_code": {""}}); s != 200 {
		t.Fatalf("empty-code lookup: want 200, got %d", s)
	}
	// signin step with an invalid state → error page, not a redirect.
	if s := status(url.Values{"__ee_step": {"signin"}, "__ee_state": {"garbage"}}); s == 302 {
		t.Fatalf("bad signin state should not redirect (got %d)", s)
	}
	// decide step with an invalid state → error page.
	if s := status(url.Values{"__ee_step": {"decide"}, "__ee_state": {"garbage"}, "__ee_decision": {"approve"}}); s == 302 {
		t.Fatalf("bad decide state should not redirect (got %d)", s)
	}
	// Unknown user code at lookup → not-found page.
	if s := status(url.Values{"__ee_step": {"lookup"}, "user_code": {"ZZZZ-ZZZZ"}}); s == 302 {
		t.Fatalf("unknown code lookup should not redirect (got %d)", s)
	}
}
