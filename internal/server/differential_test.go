package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// Differential harness: compare the emulator's response with one RECORDED FROM
// REAL ENTRA, rather than with our own expectation.
//
// Every other test in this package asserts the emulator does what we believe
// Entra does. These assert it does what Entra was OBSERVED to do. That is a
// different and stronger claim, and it is the only evidence tier in this
// emulator family that does not ultimately rest on our own reading of the docs.
//
// The fixtures come from e2e/differential/capture.sh, run by hand against the
// capture tenant. This harness is deliberately OFFLINE: it needs no Azure, no
// credentials and no network, so it can sit in the ordinary `go test` gate.
// Capture is the privileged step; checking is not.
//
// See e2e/differential/README.md for what a passing diff does and does not mean.
// It does NOT mean parity with Azure. It means: for these interactions, at the
// capture date, the normalised responses matched.

const (
	differentialDir = "differential"
	// Fixtures older than the manifest's maxAgeDays are reported STALE rather
	// than passing. An old recording that still passes is the failure mode this
	// whole system exists to prevent: it certifies behaviour nobody rechecked.
	staleIsFailure = true
)

type fixtureManifest struct {
	SchemaVersion  string   `json:"schemaVersion"`
	CapturedAt     *string  `json:"capturedAt"`
	MaxAgeDays     int      `json:"maxAgeDays"`
	Normalizations []string `json:"normalizations"`
	Scenarios      []struct {
		ID            string `json:"id"`
		Status        string `json:"status"`
		Fixture       string `json:"fixture"`
		AzureRequired bool   `json:"azureRequired"`
		What          string `json:"what"`
	} `json:"scenarios"`
}

type capturedResponse struct {
	Scenario   string `json:"scenario"`
	CapturedAt string `json:"capturedAt"`
	Response   struct {
		Status int            `json:"status"`
		Body   map[string]any `json:"body"`
	} `json:"response"`
}

func differentialPath(parts ...string) string {
	return filepath.Join(append([]string{"..", "..", "e2e", differentialDir}, parts...)...)
}

func loadManifest(t *testing.T) fixtureManifest {
	t.Helper()
	raw, err := os.ReadFile(differentialPath("testdata", "fixture-manifest.json"))
	if err != nil {
		t.Fatalf("read fixture manifest: %v", err)
	}
	var m fixtureManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse fixture manifest: %v", err)
	}
	return m
}

// --- the normaliser -------------------------------------------------------
//
// This mirrors capture.sh's `normalise`, and the two MUST agree: capture folds
// these values to placeholders on the way in, and this folds the emulator's
// live response the same way on the way out. A rule present on one side only
// shows up as a permanent, unfixable diff (harmless, visible) or as a
// permanently ignored real difference (invisible, which is the dangerous one).
//
// Deliberately NOT a generic "ignore anything that differs". Each rule names a
// value that is genuinely not part of the contract. Everything else is compared.

var (
	guidRe      = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	timestampRe = regexp.MustCompile(`\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}Z?`)
)

// normaliseValue folds volatile substrings. tenantID and appID are substituted
// before the generic GUID rule so they stay recognisable instead of collapsing
// into {guid} — same ordering constraint capture.sh documents.
func normaliseValue(v any, tenantID, appID string) any {
	switch x := v.(type) {
	case string:
		s := x
		if tenantID != "" {
			s = replaceAll(s, tenantID, "{tenant-id}")
		}
		if appID != "" {
			s = replaceAll(s, appID, "{daemon-app-id}")
		}
		s = guidRe.ReplaceAllString(s, "{guid}")
		s = timestampRe.ReplaceAllString(s, "{timestamp}")
		return s
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			switch k {
			case "expires_in", "ext_expires_in":
				out[k] = "{seconds}"
			case "access_token":
				out[k] = "{redacted-jwt}"
			default:
				out[k] = normaliseValue(val, tenantID, appID)
			}
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = normaliseValue(e, tenantID, appID)
		}
		return out
	default:
		return v
	}
}

func replaceAll(s, old, new string) string {
	if old == "" {
		return s
	}
	return regexp.MustCompile(regexp.QuoteMeta(old)).ReplaceAllString(s, new)
}

// diffKeys reports structural differences: which keys only one side has, and
// which shared keys hold different values. Key presence is reported separately
// from value mismatch because they are different defects — a missing
// error_codes array is an omission, a wrong AADSTS number is a bug.
func diffKeys(want, got map[string]any, path string) []string {
	var diffs []string
	keys := map[string]bool{}
	for k := range want {
		keys[k] = true
	}
	for k := range got {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	for _, k := range sorted {
		w, inWant := want[k]
		g, inGot := got[k]
		at := path + k
		switch {
		case inWant && !inGot:
			diffs = append(diffs, fmt.Sprintf("missing from emulator: %s (Entra sent %v)", at, w))
		case !inWant && inGot:
			diffs = append(diffs, fmt.Sprintf("emulator sent extra: %s = %v (Entra sent no such field)", at, g))
		default:
			wm, wOK := w.(map[string]any)
			gm, gOK := g.(map[string]any)
			if wOK && gOK {
				diffs = append(diffs, diffKeys(wm, gm, at+".")...)
				continue
			}
			if !reflect.DeepEqual(w, g) {
				diffs = append(diffs, fmt.Sprintf("%s: Entra %#v, emulator %#v", at, w, g))
			}
		}
	}
	return diffs
}

// --- the tests ------------------------------------------------------------

// TestDifferentialManifestIsHonest checks the ledger of scenarios before any
// comparison runs. A manifest claiming a fixture that is absent would make the
// harness skip silently and read as "nothing to do".
func TestDifferentialManifestIsHonest(t *testing.T) {
	m := loadManifest(t)
	if m.SchemaVersion == "" {
		t.Error("manifest has no schemaVersion")
	}
	if m.MaxAgeDays <= 0 {
		t.Error("manifest must set a positive maxAgeDays, or fixtures never go stale")
	}
	if len(m.Normalizations) == 0 {
		t.Error("manifest declares no normalizations; capture.sh applies several")
	}
	seen := map[string]bool{}
	captured := 0
	for _, s := range m.Scenarios {
		if s.ID == "" {
			t.Error("scenario with empty id")
		}
		if seen[s.ID] {
			t.Errorf("duplicate scenario id %q", s.ID)
		}
		seen[s.ID] = true
		switch s.Status {
		case "planned":
			if s.Fixture != "" {
				t.Errorf("%s is planned but names fixture %q", s.ID, s.Fixture)
			}
		case "captured":
			captured++
			if s.Fixture == "" {
				t.Errorf("%s is captured but names no fixture", s.ID)
				continue
			}
			if _, err := os.Stat(differentialPath("testdata", "fixtures", s.Fixture)); err != nil {
				t.Errorf("%s claims fixture %s which does not exist: %v", s.ID, s.Fixture, err)
			}
		default:
			t.Errorf("%s has unknown status %q (want planned|captured)", s.ID, s.Status)
		}
	}
	t.Logf("differential scenarios: %d captured, %d planned (of %d)",
		captured, len(m.Scenarios)-captured, len(m.Scenarios))
	if captured == 0 {
		t.Log("NO DIFFERENTIAL EVIDENCE YET: every scenario is planned. " +
			"Run e2e/differential/capture.sh against the capture tenant. " +
			"No parity row may cite an azure: witness until this is non-zero.")
	}
}

// TestDifferentialFixturesAreFresh fails on stale recordings instead of letting
// them pass. Age is measured per fixture, not from the manifest, because a
// partial recapture leaves the manifest looking current while some fixtures
// were not re-recorded.
func TestDifferentialFixturesAreFresh(t *testing.T) {
	m := loadManifest(t)
	maxAge := time.Duration(m.MaxAgeDays) * 24 * time.Hour
	checked := 0
	for _, s := range m.Scenarios {
		if s.Status != "captured" {
			continue
		}
		fx := loadFixture(t, s.Fixture)
		at, err := time.Parse(time.RFC3339, fx.CapturedAt)
		if err != nil {
			t.Errorf("%s: unparseable capturedAt %q: %v", s.ID, fx.CapturedAt, err)
			continue
		}
		checked++
		if age := time.Since(at); age > maxAge {
			t.Errorf("STALE: %s captured %s ago, max %d days. Re-run capture.sh; "+
				"a stale fixture certifies behaviour nobody rechecked.",
				s.ID, age.Round(24*time.Hour), m.MaxAgeDays)
		}
	}
	if checked == 0 {
		t.Skip("no captured fixtures to age-check yet")
	}
}

func loadFixture(t *testing.T, name string) capturedResponse {
	t.Helper()
	raw, err := os.ReadFile(differentialPath("testdata", "fixtures", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var fx capturedResponse
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parse fixture %s: %v", name, err)
	}
	return fx
}

// TestDifferentialNormaliserDoesNotHideDifferences is the mutation check the
// README demands, and it is the most important test in this file.
//
// The normaliser is the instrument. If it over-normalises, every comparison
// passes and no green run anywhere would reveal it — the harness would report
// perfect agreement with Azure while checking nothing. So: feed it a response
// that differs from the reference in each way that MATTERS, and require the
// diff to catch every one. Then feed it differences that do NOT matter and
// require it to stay quiet.
func TestDifferentialNormaliserDoesNotHideDifferences(t *testing.T) {
	const tid = "2882b6f0-a973-4098-bb7b-7da81a4d4ae1"
	const aid = "11111111-2222-3333-4444-555555555555"
	// trace and correlation ids are per-request and unrelated to the tenant or
	// the app. Reusing tid/aid for them here made an earlier version of this
	// test fail for the wrong reason: the reference folded to {daemon-app-id}
	// while the mutant folded to {guid}, so a difference the normaliser is meant
	// to absorb looked real. Synthetic data has to be shaped like the real thing
	// or it tests the shape of the mistake instead.
	const traceID = "7c9f1e42-0b3d-4a18-9f52-2c6d8e1a4b70"
	const corrID = "e4b21a90-5d77-4c36-8ab1-9f0e3d5c7a24"

	// Stand-in for a recorded Entra error envelope. Synthetic on purpose: this
	// tests the instrument, so it must not be confused with captured evidence.
	reference := map[string]any{
		"error":             "invalid_client",
		"error_description": "AADSTS7000215: Invalid client secret provided for app " + aid + ". Trace ID: " + traceID + " Correlation ID: " + corrID + " Timestamp: 2026-08-11 06:00:00Z",
		"error_codes":       []any{float64(7000215)},
		"timestamp":         "2026-08-11 06:00:00Z",
		"trace_id":          traceID,
		"correlation_id":    corrID,
	}

	mustCatch := []struct {
		name string
		body map[string]any
	}{
		{"a missing field", withoutKey(reference, "error_codes")},
		{"an extra field", withKey(reference, "unexpected", "surprise")},
		{"a wrong error code", withKey(reference, "error", "invalid_request")},
		{"a wrong AADSTS number", withKey(reference, "error_codes", []any{float64(50000)})},
	}
	for _, tc := range mustCatch {
		t.Run("catches "+tc.name, func(t *testing.T) {
			want := normaliseValue(reference, tid, aid).(map[string]any)
			got := normaliseValue(tc.body, tid, aid).(map[string]any)
			if d := diffKeys(want, got, ""); len(d) == 0 {
				t.Fatalf("normaliser HID a real difference (%s) — it is over-normalising, "+
					"which makes every differential comparison a false pass", tc.name)
			}
		})
	}

	mustIgnore := []struct {
		name string
		body map[string]any
	}{
		{"a different trace id", withKey(reference, "trace_id", "99999999-8888-7777-6666-555555555555")},
		{"a different timestamp", withKey(reference, "timestamp", "2027-01-02 03:04:05Z")},
	}
	for _, tc := range mustIgnore {
		t.Run("ignores "+tc.name, func(t *testing.T) {
			want := normaliseValue(reference, tid, aid).(map[string]any)
			got := normaliseValue(tc.body, tid, aid).(map[string]any)
			if d := diffKeys(want, got, ""); len(d) != 0 {
				t.Fatalf("normaliser reported a difference it should absorb (%s): %v", tc.name, d)
			}
		})
	}
}

func withoutKey(m map[string]any, k string) map[string]any {
	out := map[string]any{}
	for kk, vv := range m {
		if kk != k {
			out[kk] = vv
		}
	}
	return out
}

func withKey(m map[string]any, k string, v any) map[string]any {
	out := map[string]any{}
	for kk, vv := range m {
		out[kk] = vv
	}
	out[k] = v
	return out
}

// TestDifferentialTokenScenarios replays each captured token scenario against
// the emulator and diffs. Skips cleanly while nothing is captured, so the file
// is committable before the first capture run — but TestDifferentialManifest-
// IsHonest logs loudly that no evidence exists, so "skipped" cannot be mistaken
// for "passed".
func TestDifferentialTokenScenarios(t *testing.T) {
	m := loadManifest(t)
	replays := map[string]url.Values{
		"token-client-credentials": {
			"grant_type": {"client_credentials"}, "client_id": {daemonID},
			"client_secret": {store.SeedDaemonSecret}, "scope": {"api://" + daemonID + "/.default"},
		},
		"token-error-invalid-client": {
			"grant_type": {"client_credentials"}, "client_id": {daemonID},
			"client_secret": {"deliberately-wrong"}, "scope": {"https://graph.microsoft.com/.default"},
		},
		"token-error-invalid-scope": {
			"grant_type": {"client_credentials"}, "client_id": {daemonID},
			"client_secret": {store.SeedDaemonSecret}, "scope": {"api://not-a-registered-resource/.default"},
		},
		"token-error-unsupported-grant-type": {
			"grant_type": {"no_such_grant"}, "client_id": {daemonID},
			"client_secret": {store.SeedDaemonSecret}, "scope": {"https://graph.microsoft.com/.default"},
		},
		"token-error-unknown-client": {
			"grant_type": {"client_credentials"}, "client_id": {"00000000-0000-0000-0000-000000000000"},
			"client_secret": {store.SeedDaemonSecret}, "scope": {"https://graph.microsoft.com/.default"},
		},
	}

	ran := 0
	for _, s := range m.Scenarios {
		if s.Status != "captured" {
			continue
		}
		form, ok := replays[s.ID]
		if !ok {
			continue // claims: TestDifferentialTokenClaims, not an HTTP envelope
		}
		s := s
		t.Run(s.ID, func(t *testing.T) {
			ran++
			fx := loadFixture(t, s.Fixture)
			hts, _, _ := newTestServer(t)
			resp, body := postForm(t, http.DefaultClient, hts.URL+"/"+tenant+"/oauth2/v2.0/token", form)

			if resp.StatusCode != fx.Response.Status {
				t.Errorf("HTTP status: Entra %d, emulator %d", fx.Response.Status, resp.StatusCode)
			}
			want := normaliseValue(fx.Response.Body, "", "").(map[string]any)
			got := normaliseValue(body, tenant, daemonID).(map[string]any)
			for _, d := range diffKeys(want, got, "") {
				t.Errorf("%s: %s", s.ID, d)
			}
		})
	}
	if ran == 0 {
		t.Skip("no captured token fixtures yet — run e2e/differential/capture.sh")
	}
}

// capturedClaims is the shape capture.sh writes for token-claims-*. The token
// itself is never stored; only header fields, claim NAMES, and a handful of
// structural values.
type capturedClaims struct {
	Scenario   string         `json:"scenario"`
	CapturedAt string         `json:"capturedAt"`
	Header     map[string]any `json:"header"`
	ClaimNames []string       `json:"claimNames"`
	Structural map[string]any `json:"structural"`
}

func loadClaimsFixture(t *testing.T, name string) capturedClaims {
	t.Helper()
	raw, err := os.ReadFile(differentialPath("testdata", "fixtures", name))
	if err != nil {
		t.Fatalf("read claims fixture %s: %v", name, err)
	}
	var fx capturedClaims
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parse claims fixture %s: %v", name, err)
	}
	return fx
}

func decodeJWTHeader(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", jwt)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var hdr map[string]any
	if err := json.Unmarshal(raw, &hdr); err != nil {
		t.Fatal(err)
	}
	return hdr
}

// entraTelemetryClaims are request-scoped or Microsoft-internal fields Entra
// puts on an access token. Requiring them would make the emulator copy
// telemetry, not the protocol. azpacr is the client-auth method (secret vs
// cert); present on Entra, not claimed here yet.
var entraTelemetryClaims = map[string]bool{
	"aio": true, "rh": true, "uti": true, "xms_ftd": true, "azpacr": true,
}

// entraAppOnlyOmissions are Entra claims this emulator deliberately does not
// emit on client-credentials tokens. oid is the service principal's object
// id; TestClientCredentials asserts app-only tokens are userless. Do not
// promote these to required without changing that contract.
var entraAppOnlyOmissions = map[string]bool{
	"oid": true,
}

// TestDifferentialTokenClaims compares the emulator's app-only JWT against
// the captured Entra claims fixture. It is NOT an exact match:
//
//   - header alg/typ must equal Entra; kid must be present (value is per-key)
//   - ver, tid, azp must equal (tid/azp after normalisation)
//   - iss must end in /{tenant-id}/v2.0; the host is local, not login.microsoftonline.com
//   - every Entra protocol claim name must be present; telemetry and the
//     documented omissions above may be absent; extra emulator claims (appid,
//     roles) are allowed
//   - aud VALUE is not compared: Entra returned the app GUID for
//     api://{appId}/.default, the emulator returns the App ID URI. That is a
//     recorded divergence, not a silent skip of the claim's presence.
//
// An exact claimNames / iss / aud equality would fail on origin and telemetry
// and read as "no Azure evidence" while hiding the protocol agreement.
func TestDifferentialTokenClaims(t *testing.T) {
	m := loadManifest(t)
	var fixture string
	for _, s := range m.Scenarios {
		if s.ID == "token-claims-client-credentials" && s.Status == "captured" {
			fixture = s.Fixture
			break
		}
	}
	if fixture == "" {
		t.Skip("token-claims-client-credentials is not captured — run e2e/differential/capture.sh")
	}

	fx := loadClaimsFixture(t, fixture)
	hts, _, _ := newTestServer(t)
	resp, body := postForm(t, http.DefaultClient, hts.URL+"/"+tenant+"/oauth2/v2.0/token", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {daemonID},
		"client_secret": {store.SeedDaemonSecret},
		"scope":         {"api://" + daemonID + "/.default"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("emulator token mint: %d %v", resp.StatusCode, body)
	}
	jwt, _ := body["access_token"].(string)
	if jwt == "" {
		t.Fatalf("emulator returned no access_token: %v", body)
	}

	hdr := decodeJWTHeader(t, jwt)
	if hdr["alg"] != fx.Header["alg"] {
		t.Errorf("header.alg: Entra %#v, emulator %#v", fx.Header["alg"], hdr["alg"])
	}
	if hdr["typ"] != fx.Header["typ"] {
		t.Errorf("header.typ: Entra %#v, emulator %#v", fx.Header["typ"], hdr["typ"])
	}
	if kid, _ := hdr["kid"].(string); kid == "" {
		t.Error("header.kid: emulator token has no kid")
	}

	claims := decodeJWTPayload(t, jwt)
	got := normaliseValue(claims, tenant, daemonID).(map[string]any)

	if got["ver"] != fx.Structural["ver"] {
		t.Errorf("ver: Entra %#v, emulator %#v", fx.Structural["ver"], got["ver"])
	}
	if got["tid"] != "{tenant-id}" {
		t.Errorf("tid: want {tenant-id} after normalisation, got %#v", got["tid"])
	}
	if got["azp"] != "{daemon-app-id}" {
		t.Errorf("azp: want {daemon-app-id} after normalisation, got %#v", got["azp"])
	}
	iss, _ := got["iss"].(string)
	if !strings.HasSuffix(iss, "/{tenant-id}/v2.0") {
		t.Errorf("iss: want suffix /{tenant-id}/v2.0 (host is local), got %#v", iss)
	}

	for _, name := range fx.ClaimNames {
		if entraTelemetryClaims[name] || entraAppOnlyOmissions[name] {
			continue
		}
		if _, ok := got[name]; !ok {
			t.Errorf("missing protocol claim %q (Entra sent it; not telemetry)", name)
		}
	}
}
