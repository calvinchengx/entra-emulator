// Package httpx holds shared HTTP plumbing: tenant validation and the
// canonical error envelopes (docs/05, docs/06, docs/07).
package httpx

import (
	"encoding/json"
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
	ErrorCodes       []int  `json:"error_codes"`
	Timestamp        string `json:"timestamp"`
	TraceID          string `json:"trace_id"`
	CorrelationID    string `json:"correlation_id"`
}

// aadstsCodes maps OAuth error codes to best-effort AADSTS numerics.
var aadstsCodes = map[string]int{
	"invalid_request":         900144,
	"invalid_client":          7000215,
	"invalid_grant":           70008,
	"invalid_scope":           70011,
	"unsupported_grant_type":  70003,
	"authorization_pending":   70016,
	"access_denied":           65004,
	"expired_token":           70020,
}

// oauthStatus maps error codes to HTTP status.
func oauthStatus(code string) int {
	if code == "invalid_client" {
		return http.StatusUnauthorized
	}
	return http.StatusBadRequest
}

// WriteOAuthError emits the canonical OAuth error JSON with no-store headers.
func WriteOAuthError(w http.ResponseWriter, code, description string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	WriteJSON(w, oauthStatus(code), OAuthError{
		Error:            code,
		ErrorDescription: description,
		ErrorCodes:       []int{aadstsCodes[code]},
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		TraceID:          store.NewGUID(),
		CorrelationID:    store.NewGUID(),
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
