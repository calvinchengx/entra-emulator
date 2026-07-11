package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	vwa "github.com/descope/virtualwebauthn"
)

// passkeyHarness drives the WebAuthn ceremonies with a virtual authenticator
// (no browser) against the emulator's per-request relying party.
type passkeyHarness struct {
	t      *testing.T
	origin string
	client *http.Client
	rp     vwa.RelyingParty
	auth   vwa.Authenticator
	cred   vwa.Credential
}

const verifierPK = "passkey-verifier-0123456789abcdefghijklmnopqrstuv"

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func newHarness(t *testing.T, origin string) *passkeyHarness {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	host := strings.TrimPrefix(origin, "http://")
	host = strings.TrimPrefix(host, "https://")
	rpID := host
	if i := strings.LastIndex(host, ":"); i > 0 {
		rpID = host[:i]
	}
	return &passkeyHarness{
		t:      t,
		origin: origin,
		client: &http.Client{Jar: jar},
		rp:     vwa.RelyingParty{Name: "Entra Emulator", ID: rpID, Origin: origin},
		auth:   vwa.NewAuthenticator(),
		cred:   vwa.NewCredential(vwa.KeyTypeEC2),
	}
}

func (h *passkeyHarness) post(path string, body any) (int, string) {
	h.t.Helper()
	var reader io.Reader
	switch b := body.(type) {
	case string:
		reader = strings.NewReader(b)
	default:
		raw, _ := json.Marshal(b)
		reader = strings.NewReader(string(raw))
	}
	req, _ := http.NewRequest("POST", h.origin+path, reader)
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

func (h *passkeyHarness) register(upn string) {
	h.t.Helper()
	base := "/" + tenant + "/webauthn"
	code, optionsJSON := h.post(base+"/register/begin", map[string]string{"upn": upn})
	if code != 200 {
		h.t.Fatalf("register/begin: %d %s", code, optionsJSON)
	}
	attOpts, err := vwa.ParseAttestationOptions(optionsJSON)
	if err != nil {
		h.t.Fatalf("parse attestation options: %v", err)
	}
	attResp := vwa.CreateAttestationResponse(h.rp, h.auth, h.cred, *attOpts)
	code, out := h.post(base+"/register/finish", attResp)
	if code != 200 {
		h.t.Fatalf("register/finish: %d %s", code, out)
	}
	h.auth.AddCredential(h.cred)
}

// assert performs a passkey sign-in; on success the client's jar holds the
// ee_session cookie tagged fido.
func (h *passkeyHarness) assert(upn string) (int, string) {
	h.t.Helper()
	base := "/" + tenant + "/webauthn"
	code, optionsJSON := h.post(base+"/assert/begin", map[string]string{"upn": upn})
	if code != 200 {
		return code, optionsJSON
	}
	asrtOpts, err := vwa.ParseAssertionOptions(optionsJSON)
	if err != nil {
		h.t.Fatalf("parse assertion options: %v", err)
	}
	asrtResp := vwa.CreateAssertionResponse(h.rp, h.auth, h.cred, *asrtOpts)
	return h.post(base+"/assert/finish", asrtResp)
}

func TestPasskeyRegisterAssertAndAMR(t *testing.T) {
	hts, _, _ := newTestServer(t)
	h := newHarness(t, hts.URL)

	// Register a passkey for Alice, then sign in with it.
	h.register("alice@entraemulator.dev")
	code, out := h.assert("alice@entraemulator.dev")
	if code != 200 {
		t.Fatalf("assert/finish: %d %s", code, out)
	}
	var assertResp map[string]any
	_ = json.Unmarshal([]byte(out), &assertResp)
	if assertResp["amr"] != "fido" || assertResp["userId"] != aliceID {
		t.Fatalf("unexpected assert result: %s", out)
	}

	// The passkey session (in h.client's jar) drives an SSO /authorize with no
	// picker, and the resulting ID token carries amr:["fido"].
	h.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	authURL := hts.URL + "/" + tenant + "/oauth2/v2.0/authorize?" + url.Values{
		"client_id": {spaID}, "response_type": {"code"}, "redirect_uri": {redirect},
		"scope": {"openid profile"}, "state": {"pk"},
		// public client needs PKCE; reuse a fixed verifier/challenge
		"code_challenge": {pkceChallenge(verifierPK)}, "code_challenge_method": {"S256"},
	}.Encode()
	resp, err := h.client.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 {
		t.Fatalf("passkey SSO authorize: want 302, got %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	acode := loc.Query().Get("code")
	if acode == "" {
		t.Fatalf("no code from SSO authorize: %s", loc)
	}
	resp2, body := postForm(t, http.DefaultClient, hts.URL+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {acode},
		"redirect_uri": {redirect}, "client_id": {spaID}, "code_verifier": {verifierPK},
	})
	if resp2.StatusCode != 200 {
		t.Fatalf("token exchange: %d %v", resp2.StatusCode, body)
	}
	idc := decodeJWTPayload(t, body["id_token"].(string))
	amr, _ := json.Marshal(idc["amr"])
	if string(amr) != `["fido"]` {
		t.Fatalf("id token should carry amr:[fido], got %s", amr)
	}
}

func TestPasskeyAssertWithoutCredentialFails(t *testing.T) {
	hts, _, _ := newTestServer(t)
	h := newHarness(t, hts.URL)
	// No registration → assert/begin should refuse (no passkeys).
	code, _ := h.post("/"+tenant+"/webauthn/assert/begin", map[string]string{"upn": "bob@entraemulator.dev"})
	if code != 400 {
		t.Fatalf("assert/begin with no passkey: want 400, got %d", code)
	}
}

func TestPasskeyAdminManagement(t *testing.T) {
	hts, _, _ := newTestServer(t)
	h := newHarness(t, hts.URL)
	h.register("alice@entraemulator.dev")

	code, body := getJSON(t, hts.URL+"/admin/api/users/"+aliceID+"/passkeys")
	if code != 200 {
		t.Fatalf("list passkeys: %d %v", code, body)
	}
	list, _ := body["value"].([]any)
	if len(list) != 1 {
		t.Fatalf("expected 1 passkey, got %d", len(list))
	}
	credID := list[0].(map[string]any)["id"].(string)

	// Delete it; assert then fails (no passkeys).
	req, _ := http.NewRequest("DELETE", hts.URL+"/admin/api/users/"+aliceID+"/passkeys/"+credID, nil)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("delete passkey: want 204, got %d", resp.StatusCode)
	}
	code, _ = h.post("/"+tenant+"/webauthn/assert/begin", map[string]string{"upn": "alice@entraemulator.dev"})
	if code != 400 {
		t.Fatalf("assert after delete: want 400, got %d", code)
	}
}
