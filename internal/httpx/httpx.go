// Package httpx holds shared HTTP plumbing: tenant validation and the
// canonical error envelopes (docs/05, docs/06, docs/07).
package httpx

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/calvinchengx/entra-emulator/internal/store"
)

// ValidTenant reports whether the path segment is the configured tenant GUID
// or one of the aliases; all resolve to the single tenant.
func ValidTenant(segment, tenantID string) bool {
	switch segment {
	case tenantID, "common", "organizations", "consumers":
		return true
	}
	return false
}

// WriteJSON writes v with the given status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// OAuthError is the canonical AADSTS-style token error body.
type OAuthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorCodes       []int  `json:"error_codes,omitempty"`
	Timestamp        string `json:"timestamp"`
	TraceID          string `json:"trace_id"`
	CorrelationID    string `json:"correlation_id"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// aadstsCodes maps OAuth error codes to best-effort AADSTS numerics.
// Numbers that came off a captured Entra envelope are marked; the rest are
// from the docs and have not been differentially confirmed.
var aadstsCodes = map[string]int{
	"invalid_request":        900144,
	"invalid_client":         7000215, // captured 2026-08-14
	"invalid_grant":          70008,
	"invalid_scope":          70011,
	"invalid_resource":       500011, // captured 2026-08-14
	"unauthorized_client":    700038, // captured 2026-08-14
	"unsupported_grant_type": 70003,  // captured 2026-08-14
	"authorization_pending":  70016,
	"access_denied":          65004,
	"expired_token":          70020,
	"authorization_declined": 70018, // device-code: user denied (entra-docs name)
	"bad_verification_code":  70019, // device-code: unknown device_code (entra-docs name)
}

// errorURICodes are the AADSTS numbers Entra attached error_uri to in the
// 2026-08-14 token capture. 70003 and 700038 were captured without it, so
// this is an observed set, not "every AADSTS number".
var errorURICodes = map[int]bool{
	7000215: true,
	500011:  true,
}

// oauthStatus maps error codes to HTTP status.
func oauthStatus(code string) int {
	switch code {
	case "invalid_client":
		return http.StatusUnauthorized
	case "temporarily_unavailable":
		return http.StatusServiceUnavailable
	case "server_error":
		return http.StatusInternalServerError
	default:
		return http.StatusBadRequest
	}
}

// entraTimestamp is the layout Entra puts in both the timestamp field and
// the "Timestamp: …" suffix of error_description (space, not RFC3339's T).
const entraTimestamp = "2006-01-02 15:04:05Z"

// WriteOAuthError emits the canonical OAuth error JSON with no-store headers.
func WriteOAuthError(w http.ResponseWriter, code, description string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	// Omit error_codes for codes without a known AADSTS number (e.g. injected
	// or standard OAuth codes) rather than emitting a bogus [0].
	var codes []int
	if n := aadstsCodes[code]; n != 0 {
		codes = []int{n}
	}
	traceID := store.NewGUID()
	corrID := store.NewGUID()
	ts := time.Now().UTC().Format(entraTimestamp)
	if len(codes) > 0 {
		description = fmt.Sprintf("%s Trace ID: %s Correlation ID: %s Timestamp: %s",
			description, traceID, corrID, ts)
	}
	var uri string
	if len(codes) > 0 && errorURICodes[codes[0]] {
		uri = fmt.Sprintf("https://login.microsoftonline.com/error?code=%d", codes[0])
	}
	WriteJSON(w, oauthStatus(code), OAuthError{
		Error:            code,
		ErrorDescription: description,
		ErrorCodes:       codes,
		Timestamp:        ts,
		TraceID:          traceID,
		CorrelationID:    corrID,
		ErrorURI:         uri,
	})
}

// NoStore stamps token/no-cache headers on a success response.
func NoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

// AdminError is the admin API error envelope.
type AdminError struct {
	Code    string        `json:"code"`
	Message string        `json:"message"`
	Target  string        `json:"target,omitempty"`
	Details []AdminDetail `json:"details,omitempty"`
}

type AdminDetail struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func WriteAdminError(w http.ResponseWriter, status int, code, message string, details ...AdminDetail) {
	WriteJSON(w, status, map[string]any{"error": AdminError{Code: code, Message: message, Details: details}})
}

// WriteGraphError emits the Graph-shaped error body.
func WriteGraphError(w http.ResponseWriter, status int, code, message string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="`+message+`"`)
	}
	WriteJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}
