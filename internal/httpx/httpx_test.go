package httpx

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidTenant(t *testing.T) {
	tid := "6f89cf12-978b-4d23-ac18-9ef0c127cf87"
	cases := []struct {
		segment string
		want    bool
	}{
		{tid, true},
		{"common", true},
		{"organizations", true},
		{"consumers", true},
		{"nope", false},
		{"", false},
	}
	for _, c := range cases {
		if got := ValidTenant(c.segment, tid); got != c.want {
			t.Errorf("ValidTenant(%q) = %v, want %v", c.segment, got, c.want)
		}
	}
}

func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteJSON(rec, http.StatusCreated, map[string]string{"hello": "world"})

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusCreated)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type = %q", ct)
	}
	var out map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if out["hello"] != "world" {
		t.Fatalf("body = %v", out)
	}
}

func TestOAuthStatus(t *testing.T) {
	cases := []struct {
		code string
		want int
	}{
		{"invalid_client", http.StatusUnauthorized},
		{"temporarily_unavailable", http.StatusServiceUnavailable},
		{"server_error", http.StatusInternalServerError},
		{"invalid_grant", http.StatusBadRequest},
		{"anything_else", http.StatusBadRequest},
	}
	for _, c := range cases {
		if got := oauthStatus(c.code); got != c.want {
			t.Errorf("oauthStatus(%q) = %d, want %d", c.code, got, c.want)
		}
	}
}

func TestWriteOAuthError_KnownCode(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteOAuthError(rec, "invalid_client", "bad secret")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q", cc)
	}
	if p := rec.Header().Get("Pragma"); p != "no-cache" {
		t.Fatalf("Pragma = %q", p)
	}
	var e OAuthError
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if e.Error != "invalid_client" || !strings.HasPrefix(e.ErrorDescription, "bad secret Trace ID:") {
		t.Fatalf("body = %+v", e)
	}
	if !strings.Contains(e.ErrorDescription, "Correlation ID:") || !strings.Contains(e.ErrorDescription, "Timestamp:") {
		t.Fatalf("description missing Entra suffix: %q", e.ErrorDescription)
	}
	if e.ErrorURI != "https://login.microsoftonline.com/error?code=7000215" {
		t.Fatalf("error_uri = %q", e.ErrorURI)
	}
	if len(e.ErrorCodes) != 1 || e.ErrorCodes[0] != 7000215 {
		t.Fatalf("error_codes = %v, want [7000215]", e.ErrorCodes)
	}
	if e.Timestamp == "" || e.TraceID == "" || e.CorrelationID == "" {
		t.Fatalf("missing generated fields: %+v", e)
	}
}

func TestWriteOAuthError_UnknownCodeOmitsErrorCodes(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteOAuthError(rec, "some_injected_code", "desc")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	// error_codes has omitempty and no known AADSTS number, so it must be absent.
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if _, present := raw["error_codes"]; present {
		t.Fatalf("error_codes should be omitted for unknown code, body = %v", raw)
	}
}

func TestNoStore(t *testing.T) {
	rec := httptest.NewRecorder()
	NoStore(rec)
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q", cc)
	}
	if p := rec.Header().Get("Pragma"); p != "no-cache" {
		t.Fatalf("Pragma = %q", p)
	}
}

func TestWriteAdminError(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteAdminError(rec, http.StatusBadRequest, "invalidRequest", "bad input",
		AdminDetail{Field: "endpoint", Message: "required"})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	var raw struct {
		Error AdminError `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if raw.Error.Code != "invalidRequest" || raw.Error.Message != "bad input" {
		t.Fatalf("body = %+v", raw.Error)
	}
	if len(raw.Error.Details) != 1 || raw.Error.Details[0].Field != "endpoint" ||
		raw.Error.Details[0].Message != "required" {
		t.Fatalf("details = %+v", raw.Error.Details)
	}
}

func TestWriteAdminError_NoDetails(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteAdminError(rec, http.StatusNotFound, "notFound", "missing")

	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	errObj, ok := raw["error"].(map[string]any)
	if !ok {
		t.Fatalf("error not an object: %v", raw)
	}
	if _, present := errObj["details"]; present {
		t.Fatalf("details should be omitted when empty, got %v", errObj)
	}
}

func TestWriteGraphError_Unauthorized(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteGraphError(rec, http.StatusUnauthorized, "InvalidAuthenticationToken", "token expired")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	wa := rec.Header().Get("WWW-Authenticate")
	if wa != `Bearer error="invalid_token", error_description="token expired"` {
		t.Fatalf("WWW-Authenticate = %q", wa)
	}
	// map[string]any, not map[string]string: the envelope carries innerError,
	// which is an object. A string-typed map silently stopped parsing when
	// innerError was added, which is what this comment is here to prevent
	// someone "fixing" by dropping the field again.
	var raw struct {
		Error map[string]any `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if raw.Error["code"] != "InvalidAuthenticationToken" || raw.Error["message"] != "token expired" {
		t.Fatalf("body = %+v", raw.Error)
	}
}

// TestWriteGraphErrorCarriesInnerError pins the field real Entra sends on EVERY
// error and this emulator omitted entirely until a recorded diff found it.
// request-id is what Microsoft support and SDK logging middleware correlate on,
// so an envelope without it is not merely terser, it is unusable for the thing
// the field exists for.
func TestWriteGraphErrorCarriesInnerError(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		code   string
	}{
		{"not found", http.StatusNotFound, "Request_ResourceNotFound"},
		{"unauthorized", http.StatusUnauthorized, "InvalidAuthenticationToken"},
		{"forbidden", http.StatusForbidden, "Authorization_RequestDenied"},
		{"bad request", http.StatusBadRequest, "BadRequest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			WriteGraphError(rec, tc.status, tc.code, "boom")
			var raw struct {
				Error struct {
					Code       string            `json:"code"`
					Message    string            `json:"message"`
					InnerError map[string]string `json:"innerError"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
				t.Fatalf("body not JSON: %v", err)
			}
			if raw.Error.InnerError == nil {
				t.Fatalf("innerError missing entirely from %s: %s", tc.code, rec.Body)
			}
			for _, k := range []string{"date", "request-id", "client-request-id"} {
				if raw.Error.InnerError[k] == "" {
					t.Errorf("innerError.%s empty: %v", k, raw.Error.InnerError)
				}
			}
		})
	}
}

// TestGraphRequestIDsEchoesClientRequestID: the caller supplies
// client-request-id to correlate its own logs with the service's. Generating a
// fresh one instead would look correct in isolation and break exactly the
// correlation the header exists for.
func TestGraphRequestIDsEchoes(t *testing.T) {
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/graph/v1.0/users", nil)
	r.Header.Set("client-request-id", "caller-supplied-id")
	GraphRequestIDs(rec, r)
	if got := rec.Header().Get("client-request-id"); got != "caller-supplied-id" {
		t.Errorf("client-request-id = %q, want the caller's", got)
	}
	if rec.Header().Get("request-id") == "" {
		t.Error("request-id not stamped")
	}

	// And the envelope agrees with the headers, rather than inventing its own.
	WriteGraphError(rec, http.StatusNotFound, "Request_ResourceNotFound", "nope")
	var raw struct {
		Error struct {
			InnerError map[string]string `json:"innerError"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if raw.Error.InnerError["client-request-id"] != "caller-supplied-id" {
		t.Errorf("innerError disagrees with the header: %v", raw.Error.InnerError)
	}
	if raw.Error.InnerError["request-id"] != rec.Header().Get("request-id") {
		t.Errorf("innerError request-id disagrees with the header")
	}
}

// TestGraphResourceNotFoundWording pins Entra's exact string. Callers match on
// it, and the trailing clause is not padding: it is what Entra returns.
func TestGraphResourceNotFoundWording(t *testing.T) {
	got := GraphResourceNotFound("abc")
	want := "Resource 'abc' does not exist or one of its queried reference-property objects are not present."
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestWriteGraphError_NonUnauthorizedHasNoChallenge(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteGraphError(rec, http.StatusForbidden, "Authorization_RequestDenied", "no access")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if wa := rec.Header().Get("WWW-Authenticate"); wa != "" {
		t.Fatalf("WWW-Authenticate should be absent for non-401, got %q", wa)
	}
}
