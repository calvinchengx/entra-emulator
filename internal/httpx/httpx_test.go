package httpx

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidTenant(t *testing.T) {
	tid := "11111111-1111-1111-1111-111111111111"
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
	if e.Error != "invalid_client" || e.ErrorDescription != "bad secret" {
		t.Fatalf("body = %+v", e)
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
	var raw struct {
		Error map[string]string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if raw.Error["code"] != "InvalidAuthenticationToken" || raw.Error["message"] != "token expired" {
		t.Fatalf("body = %+v", raw.Error)
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
