// Package audit records every authorize/token exchange with its concrete
// accept/reject reason (roadmap #8), turning "why won't MSAL sign in" into
// reading a log. In-memory ring buffer, admin-readable.
package audit

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Event is one recorded flow exchange.
type Event struct {
	// ID is assigned once when the event is recorded, so a log consumer can
	// correlate and de-duplicate across polls.
	EventID   string `json:"id"`
	Time      int64  `json:"time"`
	TimeISO   string `json:"timeISO"`
	Flow      string `json:"flow"`                // "token" | "authorize"
	GrantType string `json:"grantType,omitempty"` // for token exchanges
	ClientID  string `json:"clientId,omitempty"`
	// The signing-in user, when the exchange resolved one. Empty for app-only
	// flows (client_credentials), which genuinely have no user — that emptiness
	// is meaningful, not missing data.
	UserID            string `json:"userId,omitempty"`
	UserPrincipalName string `json:"userPrincipalName,omitempty"`
	Status            int    `json:"status"`
	OK                bool   `json:"ok"`
	Error             string `json:"error,omitempty"`  // OAuth error code, if any
	Reason            string `json:"reason,omitempty"` // error_description / concrete reason
}

// Recorder is a thread-safe fixed-capacity ring buffer of events.
type Recorder struct {
	mu   sync.Mutex
	buf  []Event
	next int
	full bool
	cap  int
}

// New returns a recorder holding the most recent capacity events.
func New(capacity int) *Recorder {
	if capacity <= 0 {
		capacity = 500
	}
	return &Recorder{buf: make([]Event, capacity), cap: capacity}
}

// Record stores an event, stamping ISO time from its epoch.
// ID returns the event's stable identifier.
func (e Event) ID() string { return e.EventID }

func (r *Recorder) Record(e Event) {
	if e.EventID == "" {
		var b [16]byte
		if _, err := rand.Read(b[:]); err == nil {
			e.EventID = hex.EncodeToString(b[:])
		}
	}
	e.TimeISO = time.Unix(e.Time, 0).UTC().Format(time.RFC3339)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[r.next] = e
	r.next = (r.next + 1) % r.cap
	if r.next == 0 {
		r.full = true
	}
}

// List returns up to limit events, newest first (all if limit <= 0).
func (r *Recorder) List(limit int) []Event {
	r.mu.Lock()
	defer r.mu.Unlock()

	n := r.next
	if r.full {
		n = r.cap
	}
	out := make([]Event, 0, n)
	// Walk backwards from the most recent write.
	for i := 0; i < n; i++ {
		idx := (r.next - 1 - i + r.cap) % r.cap
		out = append(out, r.buf[idx])
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// Clear empties the buffer.
func (r *Recorder) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = make([]Event, r.cap)
	r.next = 0
	r.full = false
}
