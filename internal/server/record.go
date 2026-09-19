package server

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

// Response recording, so the traffic the e2e suites already generate can be
// held to Microsoft's published Graph OpenAPI (scripts/check_graph_conformance.py).
//
// WHY IT LIVES IN THE EMULATOR RATHER THAN IN A PROXY. A proxy would have to be
// spliced into every suite, and every suite that forgot would silently
// contribute nothing. Recording here is opt-in by one environment variable and
// covers whatever traffic a suite already produces, so a new suite is measured
// the day it is written. fabric-emulator arrived at the same design for the same
// reason; this is a port of internal/server/record.go there.
//
// WHY THIS IS A DIFFERENT KIND OF EVIDENCE. The `ci:` witnesses in
// docs/witnesses.json are clients: an SDK drives a surface and its own model
// rejects a wrong shape. That is strong and narrow, because a typed client
// asserts on the fields it uses and ignores the rest. The `diff:` witnesses are
// stronger still (the oracle is the service itself) and there are seventeen of
// them. A recording validated against the Graph OpenAPI is neither: it is
// machine-readable, Microsoft's, and covers every route a suite happens to
// touch. Shape, never semantics: it says an answer was SHAPED right, not that it
// was TRUE.
//
// WHAT IS RECORDED, and deliberately no more: method, path, query, status and
// the response body. No request bodies and NO HEADERS. The Authorization header
// carries a bearer token, and a recording written to a file that CI uploads as
// an artifact is exactly where a token must never be. The bodies are the
// emulator's own seeded fixtures, not a tenant's data.

// recorded is one response, in the shape scripts/check_graph_conformance.py
// reads. One JSON object per line: a suite killed mid-run still leaves a
// readable file up to the last complete line, where a JSON array would leave an
// unparseable one.
type recorded struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Query  string          `json:"query,omitempty"`
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body,omitempty"`
}

// recorder appends responses to a file. Nil when recording is off, which is
// every run except the conformance job.
type recorder struct {
	mu   sync.Mutex
	file *os.File
}

// newRecorder returns nil unless path is set.
//
// A FAILURE TO OPEN IT IS NOT FATAL, and it is LOUD. Recording is diagnostic: an
// emulator that refused to start because a recording path was unwritable would
// turn a typo into a broken stack. But staying silent cost fabric a full CI
// round trip: the open failed, the suite passed having recorded nothing, and the
// aggregate job noticed seven missing routes several steps away from the cause.
func newRecorder(path string) *recorder {
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Printf("RECORD_RESPONSES=%s could not be opened, so nothing will be recorded: %v", path, err)
		return nil
	}
	return &recorder{file: f}
}

// Close releases the file. Windows cannot delete an open file, so a test that
// records into t.TempDir() and leaves the handle open fails in cleanup there
// while passing everywhere else.
func (rec *recorder) Close() error {
	if rec == nil {
		return nil
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.file == nil {
		return nil
	}
	err := rec.file.Close()
	rec.file = nil
	return err
}

func (rec *recorder) write(entry recorded) {
	line, err := json.Marshal(entry)
	if err != nil {
		return
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.file == nil {
		return // closed; a late write is dropped rather than panicking
	}
	_, _ = rec.file.Write(append(line, '\n'))
}

// capture keeps the status and a bounded copy of the body.
//
// BOUNDED ON PURPOSE: past the cap the body is dropped and the status is still
// recorded, which is enough for the status-against-spec check.
type capture struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
	over   bool
}

const captureLimit = 1 << 20 // 1 MiB

func (c *capture) WriteHeader(status int) {
	c.status = status
	c.ResponseWriter.WriteHeader(status)
}

func (c *capture) Write(p []byte) (int, error) {
	if !c.over {
		if c.body.Len()+len(p) > captureLimit {
			c.over = true
			c.body.Reset()
		} else {
			c.body.Write(p)
		}
	}
	return c.ResponseWriter.Write(p)
}

// Flush and Unwrap keep streaming and upgrading surfaces working through the
// wrapper; dropping them would break the handler chain only when recording is on.
func (c *capture) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (c *capture) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// graphPath returns the path as Microsoft's OpenAPI spells it, and whether the
// request is a Graph request at all.
//
// ONE API, TWO SPELLINGS. On its own origin the emulator serves Graph at the
// root (`/v1.0/users`); under ORIGIN_MODE=compat everything shares one origin and
// Graph lives under `/graph` (`/graph/v1.0/users`). The spec knows only the
// first, so recording the second verbatim would make every compat-mode request
// look like a route that is not documented, which is a finding nobody could act
// on and the quietest way for a surface to go unchecked.
//
// Only /v1.0 is recorded. It is the only version the vendored spec describes, and
// `beta` is not served.
func graphPath(path string) (string, bool) {
	path = strings.TrimPrefix(path, "/graph")
	if !strings.HasPrefix(path, "/v1.0/") {
		return "", false
	}
	return path, true
}

// record wraps a handler so every Graph response is appended. It returns next
// untouched when recording is off, so the common path pays nothing.
func record(rec *recorder, next http.Handler) http.Handler {
	if rec == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, ok := graphPath(r.URL.Path)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		c := &capture{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(c, r)

		entry := recorded{Method: r.Method, Path: path, Query: r.URL.RawQuery, Status: c.status}
		if body := c.body.Bytes(); len(body) > 0 && json.Valid(body) {
			entry.Body = append(json.RawMessage(nil), body...)
		}
		rec.write(entry)
	})
}
