package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/calvinchengx/entra-emulator/internal/tokens"
)

// OIDC `max_age` and the `auth_time` claim (OIDC Core 3.1.2.1).
//
// Two behaviours, and they are separable: max_age decides whether an existing
// session may be REUSED, and auth_time reports when the authentication behind
// the issued token happened. Every elapsed-time judgement below runs on the
// emulator's controllable clock rather than a sleep, which is what makes a
// one-second max_age testable at all.

// maxAgeFlow drives the interactive authorize flow on `client`, passing the
// extra authorize parameters in `extra`. It returns the sign-in page's signed
// state when the emulator asked for credentials, or the redirect Location when
// it answered straight away from an existing session.
type flowStep struct {
	signInState string // non-empty: the emulator demanded authentication
	location    *url.URL
	status      int
}

func authorizeStep(t *testing.T, client *http.Client, hts string, extra url.Values) flowStep {
	t.Helper()
	q := url.Values{
		"client_id": {spaID}, "response_type": {"code"}, "redirect_uri": {redirect},
		"scope": {"openid offline_access"}, "state": {"st"}, "nonce": {"n"},
		"code_challenge": {pkceChallenge(verifierMA)}, "code_challenge_method": {"S256"},
	}
	for k, vs := range extra {
		q[k] = vs
	}
	resp, err := client.Get(hts + "/" + tenant + "/oauth2/v2.0/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	step := flowStep{status: resp.StatusCode}
	if loc := resp.Header.Get("Location"); loc != "" {
		step.location, _ = url.Parse(loc)
	}
	if m := stateRe.FindStringSubmatch(string(raw)); m != nil {
		step.signInState = m[1]
	}
	return step
}

// signIn completes the interactive POST and returns the redirect it produced.
func signIn(t *testing.T, client *http.Client, hts, state string) *url.URL {
	t.Helper()
	resp, err := client.PostForm(hts+"/"+tenant+"/oauth2/v2.0/authorize",
		url.Values{"__ee_state": {state}, "__ee_user": {aliceID}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("sign-in: want 302, got %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	return loc
}

// idTokenClaims redeems a code and returns the ID token's claims.
func idTokenClaims(t *testing.T, client *http.Client, hts, code string) map[string]any {
	t.Helper()
	resp, body := postForm(t, client, hts+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {redirect}, "client_id": {spaID}, "code_verifier": {verifierMA},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token exchange: %d %v", resp.StatusCode, body)
	}
	idt, _ := body["id_token"].(string)
	if idt == "" {
		t.Fatalf("no id_token in %v", body)
	}
	return decodeJWTPayload(t, idt)
}

const verifierMA = "verifier-max-age-0123456789abcdefghijklmn"

// TestMaxAgeReusesSessionYoungerThanTheLimit is the OIDCCMaxAge10000 shape: a
// generous max_age must NOT disturb a usable session. Getting this wrong in the
// safe-looking direction — re-authenticating whenever max_age appears — would
// pass a naive "does max_age force sign-in" test and break SSO for every client
// that sends one.
func TestMaxAgeReusesSessionYoungerThanTheLimit(t *testing.T) {
	hts, _, _ := newTestServer(t)
	client := noRedirectJar()

	first := authorizeStep(t, client, hts.URL, nil)
	if first.signInState == "" {
		t.Fatal("first authorize should ask for credentials")
	}
	loc := signIn(t, client, hts.URL, first.signInState)
	firstClaims := idTokenClaims(t, client, hts.URL, loc.Query().Get("code"))

	// Age the session by an interval that is real but well inside the ceiling.
	// Without this gap iat and auth_time coincide and the assertion below
	// cannot tell the authentication instant from the issuance instant — which
	// is the whole claim being made.
	const aged = 300
	setClock(t, hts.URL, map[string]any{"advanceSeconds": aged})

	// A 10000-second ceiling: the session is 300s old, so it is reused and no
	// sign-in page appears.
	second := authorizeStep(t, client, hts.URL, url.Values{"max_age": {"10000"}})
	if second.signInState != "" {
		t.Fatal("max_age=10000 re-authenticated a session well inside the limit")
	}
	if second.status != http.StatusFound || second.location == nil {
		t.Fatalf("want a redirect carrying a code, got %d", second.status)
	}
	claims := idTokenClaims(t, client, hts.URL, second.location.Query().Get("code"))

	authTime, ok := claims["auth_time"].(float64)
	if !ok {
		t.Fatalf("max_age was requested, so auth_time is REQUIRED: %v", claims)
	}
	// auth_time is the ORIGINAL authentication, not the moment this token was
	// issued. Reporting issuance passes every "is auth_time present" check
	// while making a session look permanently fresh, so max_age could never
	// expire anything — hence the exact-interval assertion rather than an
	// ordering one.
	iat, _ := claims["iat"].(float64)
	if elapsed := iat - authTime; elapsed < aged {
		t.Fatalf("auth_time %v is only %vs before iat %v; the session was aged %ds, "+
			"so auth_time is tracking issuance rather than authentication",
			authTime, elapsed, iat, aged)
	}
	// The first token carried no max_age, so it carries no auth_time — and the
	// two exchanges must still describe the same authentication.
	if _, present := firstClaims["auth_time"]; present {
		t.Error("auth_time emitted without max_age or an optionalClaims opt-in")
	}
}

// TestMaxAgeForcesReauthenticationWhenSessionIsStale is the OIDCCMaxAge1 shape.
// The clock ages the session instead of a sleep.
func TestMaxAgeForcesReauthenticationWhenSessionIsStale(t *testing.T) {
	hts, _, _ := newTestServer(t)
	client := noRedirectJar()

	first := authorizeStep(t, client, hts.URL, nil)
	loc := signIn(t, client, hts.URL, first.signInState)
	if loc.Query().Get("code") == "" {
		t.Fatalf("no code from the first sign-in: %s", loc)
	}

	// Without max_age the session is reused: the control that proves the next
	// assertion is about max_age and not about the session having lapsed.
	if reuse := authorizeStep(t, client, hts.URL, nil); reuse.signInState != "" {
		t.Fatal("session should be reusable before the clock moves")
	}

	setClock(t, hts.URL, map[string]any{"advanceSeconds": 60})

	stale := authorizeStep(t, client, hts.URL, url.Values{"max_age": {"1"}})
	if stale.signInState == "" {
		t.Fatalf("max_age=1 against a 60s-old session must re-authenticate, got %d", stale.status)
	}
	loc = signIn(t, client, hts.URL, stale.signInState)
	claims := idTokenClaims(t, client, hts.URL, loc.Query().Get("code"))
	authTime, ok := claims["auth_time"].(float64)
	if !ok {
		t.Fatalf("auth_time missing after a max_age re-authentication: %v", claims)
	}
	// The fresh authentication is what auth_time reports: it must now be inside
	// the window the client asked for, judged on the same clock.
	if iat, _ := claims["iat"].(float64); iat-authTime > 1 {
		t.Fatalf("auth_time %v is not the re-authentication (iat %v)", authTime, iat)
	}
}

// TestMaxAgeZeroRejectsASessionThatHasAged pins the comparison's boundary.
// OIDC says re-authenticate when the elapsed time is GREATER THAN max_age, so
// max_age=0 rejects a session the moment any time has passed — and a session
// authenticated within the same second is, literally, not older than zero
// seconds. The clock moves by one second here so the test names which side of
// that boundary it is asserting rather than depending on how fast it ran.
func TestMaxAgeZeroRejectsASessionThatHasAged(t *testing.T) {
	hts, _, _ := newTestServer(t)
	client := noRedirectJar()
	first := authorizeStep(t, client, hts.URL, nil)
	signIn(t, client, hts.URL, first.signInState)

	setClock(t, hts.URL, map[string]any{"advanceSeconds": 1})
	if step := authorizeStep(t, client, hts.URL, url.Values{"max_age": {"0"}}); step.signInState == "" {
		t.Fatalf("max_age=0 must re-authenticate, got %d", step.status)
	}
}

// TestMaxAgeWithPromptNoneFailsRatherThanReusingAStaleSession. prompt=none
// forbids the interaction max_age demands, so the only conforming answer is
// login_required — silently reusing the stale session would tell the client its
// freshness requirement was met when it was not.
func TestMaxAgeWithPromptNoneFailsRatherThanReusingAStaleSession(t *testing.T) {
	hts, _, _ := newTestServer(t)
	client := noRedirectJar()
	first := authorizeStep(t, client, hts.URL, nil)
	signIn(t, client, hts.URL, first.signInState)

	// Control: prompt=none alone is satisfied by the session.
	ok := authorizeStep(t, client, hts.URL, url.Values{"prompt": {"none"}})
	if ok.location == nil || ok.location.Query().Get("code") == "" {
		t.Fatalf("prompt=none with a fresh session should issue a code, got %d %v", ok.status, ok.location)
	}

	setClock(t, hts.URL, map[string]any{"advanceSeconds": 60})
	stale := authorizeStep(t, client, hts.URL, url.Values{"prompt": {"none"}, "max_age": {"1"}})
	if stale.location == nil {
		t.Fatalf("want an error redirect, got %d", stale.status)
	}
	if got := stale.location.Query().Get("error"); got != "login_required" {
		t.Fatalf("want login_required, got %q", got)
	}
}

// TestMalformedMaxAgeIsRefused. Ignoring an unparseable max_age is the
// dangerous reading: the client believes it forced a fresh credential check and
// receives a cached session instead.
func TestMalformedMaxAgeIsRefused(t *testing.T) {
	hts, _, _ := newTestServer(t)
	for _, bad := range []string{"soon", "-1", "3.5", ""} {
		if bad == "" {
			continue
		}
		step := authorizeStep(t, noRedirectJar(), hts.URL, url.Values{"max_age": {bad}})
		if step.location == nil {
			t.Fatalf("max_age=%q: want an error redirect, got %d", bad, step.status)
		}
		if got := step.location.Query().Get("error"); got != "invalid_request" {
			t.Errorf("max_age=%q: want invalid_request, got %q", bad, got)
		}
	}
}

// TestAuthTimeIsAnOptionalClaimWithoutMaxAge pins the emission rule. Real Entra
// lists auth_time in the OPTIONAL claim set, so it is absent by default and
// present when the app asks — matching Entra rather than emitting it always.
func TestAuthTimeIsAnOptionalClaimWithoutMaxAge(t *testing.T) {
	hts, _, _ := newTestServer(t)

	// Default: no max_age, no opt-in, no auth_time.
	client := noRedirectJar()
	first := authorizeStep(t, client, hts.URL, nil)
	loc := signIn(t, client, hts.URL, first.signInState)
	if claims := idTokenClaims(t, client, hts.URL, loc.Query().Get("code")); claims["auth_time"] != nil {
		t.Fatalf("auth_time should be absent by default, got %v", claims["auth_time"])
	}

	// Opt in through optionalClaims, exactly as an app manifest would.
	code, body := patchJSON(t, hts.URL+"/admin/api/apps/"+spaID, map[string]any{
		"optionalClaims": map[string]any{
			"idToken": []map[string]any{{"name": "auth_time"}},
		},
	})
	if code != http.StatusOK {
		t.Fatalf("patch optionalClaims: %d %v", code, body)
	}

	client2 := noRedirectJar()
	step := authorizeStep(t, client2, hts.URL, nil)
	loc = signIn(t, client2, hts.URL, step.signInState)
	claims := idTokenClaims(t, client2, hts.URL, loc.Query().Get("code"))
	if _, ok := claims["auth_time"].(float64); !ok {
		t.Fatalf("optionalClaims asked for auth_time and it is missing: %v", claims)
	}
}

// TestDiscoveryAdvertisesAuthTime. Real Entra names auth_time in
// claims_supported; a client that reads the document before deciding whether to
// send max_age needs to see it here.
func TestDiscoveryAdvertisesAuthTime(t *testing.T) {
	hts, _, _ := newTestServer(t)
	code, doc := getJSON(t, hts.URL+"/"+tenant+"/v2.0/.well-known/openid-configuration")
	if code != http.StatusOK {
		t.Fatalf("discovery: %d", code)
	}
	if !strings.Contains(strings.Join(asStrings(doc["claims_supported"]), " "), "auth_time") {
		t.Errorf("claims_supported does not advertise auth_time: %v", doc["claims_supported"])
	}
}

// TestMaxAgeInsideASignedRequestObject. A JAR request object carries max_age as
// a JSON NUMBER where the query carries a string, so the overlay needs its own
// conversion — without it the parameter is dropped and the signed request
// silently loses the freshness requirement it was signed to carry.
func TestMaxAgeInsideASignedRequestObject(t *testing.T) {
	hts, _, _ := newTestServer(t)
	key := registerAppKey(t, hts.URL, spaID)

	var maxAge any = float64(1)
	object := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		obj, err := tokens.SignRS256(key, "jar-key", map[string]any{
			"iss": spaID, "response_type": "code", "scope": "openid",
			"redirect_uri": redirect, "state": "from-object", "nonce": "n",
			"code_challenge": pkceChallenge(verifierMA), "code_challenge_method": "S256",
			"max_age": maxAge,
		})
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = w.Write([]byte(obj))
	}))
	defer object.Close()
	// Trust the origin the object is served from (the SSRF guard allows only
	// origins already registered as this app's redirect URIs).
	if code, body := postJSON(t, hts.URL+"/admin/api/apps/"+spaID+"/redirectUris",
		map[string]any{"uri": object.URL + "/cb", "type": "web"}); code != http.StatusCreated {
		t.Fatalf("register redirect uri: %d %v", code, body)
	}

	client := noRedirectJar()
	jarRequest := url.Values{"client_id": {spaID}, "request_uri": {object.URL + "/obj"}}

	// Authenticate once through the object's own parameters.
	first := authorizeStep(t, client, hts.URL, jarRequest)
	if first.signInState == "" {
		t.Fatalf("first JAR request should ask for credentials, got %d", first.status)
	}
	loc := signIn(t, client, hts.URL, first.signInState)
	claims := idTokenClaims(t, client, hts.URL, loc.Query().Get("code"))
	if _, ok := claims["auth_time"].(float64); !ok {
		t.Fatalf("max_age came from the signed object, so auth_time is REQUIRED: %v", claims)
	}

	// Age the session past the object's one-second ceiling: the signed max_age
	// must still force re-authentication.
	setClock(t, hts.URL, map[string]any{"advanceSeconds": 60})
	if stale := authorizeStep(t, client, hts.URL, jarRequest); stale.signInState == "" {
		t.Fatalf("max_age from the request object did not age the session, got %d", stale.status)
	}

	// Control: with max_age absent from the object, the same aged session IS
	// reused — so the assertion above is about max_age and not about the
	// session having lapsed on its own.
	maxAge = nil
	if reuse := authorizeStep(t, client, hts.URL, jarRequest); reuse.signInState != "" {
		t.Fatal("without max_age the aged session should still be reusable")
	}
}

// TestMaxAgeOnTheImplicitFlow. The implicit and hybrid flows mint the ID token
// at the authorize endpoint instead of the token endpoint, so auth_time reaches
// it by a different route than the code exchange's — and a claim that is
// REQUIRED is required on both.
func TestMaxAgeOnTheImplicitFlow(t *testing.T) {
	hts, _, _ := newTestServer(t)
	client := noRedirectJar()

	// Authenticate first, so the implicit request is answered from the session.
	first := authorizeStep(t, client, hts.URL, nil)
	signIn(t, client, hts.URL, first.signInState)
	setClock(t, hts.URL, map[string]any{"advanceSeconds": 120})

	step := authorizeStep(t, client, hts.URL, url.Values{
		"response_type": {"id_token"}, "response_mode": {"fragment"}, "max_age": {"10000"},
	})
	if step.location == nil {
		t.Fatalf("want a fragment redirect, got %d", step.status)
	}
	frag := step.location.Fragment
	if frag == "" {
		t.Fatalf("no fragment in %s", step.location)
	}
	vals, err := url.ParseQuery(frag)
	if err != nil {
		t.Fatal(err)
	}
	claims := decodeJWTPayload(t, vals.Get("id_token"))
	authTime, ok := claims["auth_time"].(float64)
	if !ok {
		t.Fatalf("max_age was requested, so the implicit id_token needs auth_time: %v", claims)
	}
	if iat, _ := claims["iat"].(float64); iat-authTime < 120 {
		t.Fatalf("auth_time %v should be the original authentication, 120s before iat %v", authTime, iat)
	}
}
