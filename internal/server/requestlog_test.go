package server

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The point of this middleware is that SILENCE MEANS SOMETHING. So both halves
// are asserted: a request produces a line, and with the flag off it produces
// none. Testing only the first would leave "logs nothing when enabled" and
// "logs everything when disabled" equally green.
func TestRequestLogRecordsMethodPathAndStatus(t *testing.T) {
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(old) })

	h := logRequests(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	req := httptest.NewRequest(http.MethodPost, "http://login.example/oauth2/v2.0/token?x=1", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	got := buf.String()
	for _, want := range []string{"POST", "login.example", "/oauth2/v2.0/token?x=1", "418"} {
		if !strings.Contains(got, want) {
			t.Errorf("request line %q is missing %q", strings.TrimSpace(got), want)
		}
	}
}

// A handler that never calls WriteHeader still answers 200, and the line must
// say so rather than reporting a zero.
func TestRequestLogDefaultsToTwoHundred(t *testing.T) {
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(old) })

	h := logRequests(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/health", nil))

	if !strings.Contains(buf.String(), "200") {
		t.Errorf("an unset status should log 200, got %q", strings.TrimSpace(buf.String()))
	}
}

// THE HALF THAT MAKES SILENCE READABLE. Without the flag the handler is not
// wrapped at all, so a served request leaves no line -- which is what lets an
// empty log during the iOS e2e mean "nothing arrived" rather than "nothing is
// recorded".
func TestWithoutTheFlagNothingIsLogged(t *testing.T) {
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(old) })

	plain := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	plain.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/health", nil))

	if buf.Len() != 0 {
		t.Errorf("an unwrapped handler logged %q", strings.TrimSpace(buf.String()))
	}
}

// The status is recorded once. A handler that calls WriteHeader twice (Go warns
// but continues) must not have the second call rewrite what was reported.
func TestTheFirstStatusWins(t *testing.T) {
	rec := &statusRecorder{ResponseWriter: httptest.NewRecorder(), status: http.StatusOK}
	rec.WriteHeader(http.StatusNotFound)
	rec.WriteHeader(http.StatusInternalServerError)
	if rec.status != http.StatusNotFound {
		t.Errorf("status = %d, want the first one (404)", rec.status)
	}
}
