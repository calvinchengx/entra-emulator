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
// GraphRequestIDs stamps the correlation headers Graph returns on every
// response, echoing the caller's client-request-id when it supplies one.
// WriteGraphError reads them back out to build innerError, so a handler that
// runs behind this gets a correlated error envelope for free.
func GraphRequestIDs(w http.ResponseWriter, r *http.Request) {
	if w.Header().Get("request-id") == "" {
		w.Header().Set("request-id", store.NewGUID())
	}
	if w.Header().Get("client-request-id") == "" {
		if c := r.Header.Get("client-request-id"); c != "" {
			w.Header().Set("client-request-id", c)
		} else {
			w.Header().Set("client-request-id", store.NewGUID())
		}
	}
}

// GraphResourceNotFound is Entra's exact wording for a missing directory
// object. The trailing clause about reference-property objects is not padding:
// it is what Entra returns, recorded in e2e/differential, and callers match on
// these strings. Kept in one place so the emulator cannot drift per handler.
func GraphResourceNotFound(id string) string {
	return "Resource '" + id + "' does not exist or one of its queried reference-property objects are not present."
}

// WriteGraphError writes Graph's error envelope.
//
// innerError is NOT optional decoration. Real Entra sends it on every error,
// carrying date, request-id and client-request-id, and those ids are what
// Microsoft support and SDK logging middleware correlate on. Omitting it was a
// divergence found by diffing four recorded Graph errors against this emulator
// (e2e/differential): all four matched on code and status and differed only
// here, which is precisely the kind of gap our own tests cannot report.
//
// The ids are taken from the response headers when GraphRequestIDs has run, so
// the envelope and the headers agree. A direct call still produces a complete
// envelope rather than a half-populated one.
func WriteGraphError(w http.ResponseWriter, status int, code, message string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="`+message+`"`)
	}
	reqID := w.Header().Get("request-id")
	if reqID == "" {
		reqID = store.NewGUID()
	}
	clientReqID := w.Header().Get("client-request-id")
	if clientReqID == "" {
		clientReqID = store.NewGUID()
	}
	WriteJSON(w, status, map[string]any{"error": map[string]any{
		"code":    code,
		"message": message,
		"innerError": map[string]any{
			// Entra's own format here is a local timestamp with no zone offset.
			"date":              time.Now().UTC().Format("2006-01-02T15:04:05"),
			"request-id":        reqID,
			"client-request-id": clientReqID,
		},
	}})
}
