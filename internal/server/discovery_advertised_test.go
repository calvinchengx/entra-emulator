package server

import (
	"net/http"
	"testing"
)

// TestAdvertisedAuthMethodsAreUsable closes the gap where a capability is
// implemented but invisible: discovery must advertise every client
// authentication method the token endpoint actually accepts, because a
// spec-driven client only attempts what discovery lists. private_key_jwt was
// implemented and unadvertised, so no conforming client ever used it.
func TestAdvertisedAuthMethodsAreUsable(t *testing.T) {
	hts, _, _ := newTestServer(t)
	code, doc := getJSON(t, hts.URL+"/"+tenant+"/v2.0/.well-known/openid-configuration")
	if code != http.StatusOK {
		t.Fatalf("discovery: %d", code)
	}
	advertised := map[string]bool{}
	for _, m := range asStrings(doc["token_endpoint_auth_methods_supported"]) {
		advertised[m] = true
	}
	for _, want := range []string{"client_secret_post", "client_secret_basic", "private_key_jwt"} {
		if !advertised[want] {
			t.Errorf("discovery does not advertise %q, so conforming clients will never try it", want)
		}
	}
	// The advertised private_key_jwt is genuinely accepted end-to-end —
	// TestClientAssertionHappyPath drives a real assertion through the token
	// endpoint; this asserts the two agree, so the advertisement is not a claim
	// without an implementation behind it.
}

// TestLogoutAdvertisement pins the honest split: RP-initiated logout really
// works (so http_logout_supported is advertised), but the emulator does not
// call each RP's frontchannel_logout_uri, so frontchannel_logout_supported must
// stay unadvertised rather than promise a notification that never arrives.
func TestLogoutAdvertisement(t *testing.T) {
	hts, _, _ := newTestServer(t)
	code, doc := getJSON(t, hts.URL+"/"+tenant+"/v2.0/.well-known/openid-configuration")
	if code != http.StatusOK {
		t.Fatalf("discovery: %d", code)
	}
	if doc["http_logout_supported"] != true {
		t.Errorf("http_logout_supported should be advertised: RP-initiated logout works")
	}
	if _, present := doc["frontchannel_logout_supported"]; present {
		t.Errorf("frontchannel_logout_supported must NOT be advertised — the emulator " +
			"does not call RPs' frontchannel_logout_uri")
	}
	if doc["end_session_endpoint"] == nil {
		t.Errorf("end_session_endpoint must be advertised alongside http_logout_supported")
	}

	// And the advertised endpoint actually responds.
	resp, err := http.Get(hts.URL + "/" + tenant + "/oauth2/v2.0/logout")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("end_session_endpoint: want 200, got %d", resp.StatusCode)
	}
}
