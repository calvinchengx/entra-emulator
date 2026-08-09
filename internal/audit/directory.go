package audit

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Directory audits are the counterpart to sign-in logs: sign-ins record who
// authenticated, these record what CHANGED in the directory and who changed it.
// Graph exposes them as auditLogs/directoryAudits.
//
// Scope, stated plainly: mutations made through the Graph write surface — the
// real Entra API a client would use — are journaled. The emulator's own admin
// API is a control surface that has no Entra equivalent, so its mutations are
// not, and the parity row says so.

// DirectoryEvent is one recorded directory change.
type DirectoryEvent struct {
	EventID  string `json:"id"`
	Time     int64  `json:"time"`
	TimeISO  string `json:"timeISO"`
	Activity string `json:"activity"` // "Add user", "Update group", …
	Category string `json:"category"` // UserManagement | GroupManagement | ApplicationManagement | RoleManagement
	Result   string `json:"result"`   // success | failure

	// Who did it, from the caller's token. An app-only caller has no user,
	// which is meaningful rather than missing.
	InitiatedByAppID string `json:"initiatedByAppId,omitempty"`
	InitiatedByUser  string `json:"initiatedByUserId,omitempty"`
	InitiatedByUPN   string `json:"initiatedByUpn,omitempty"`

	TargetType        string `json:"targetType"` // User | Group | Application | …
	TargetID          string `json:"targetId"`
	TargetDisplayName string `json:"targetDisplayName,omitempty"`
}

// DirectoryRecorder is a thread-safe fixed-capacity ring of directory changes,
// mirroring the sign-in Recorder so both logs behave the same under load.
type DirectoryRecorder struct {
	mu   sync.Mutex
	buf  []DirectoryEvent
	next int
	full bool
	cap  int
}

func NewDirectoryRecorder(capacity int) *DirectoryRecorder {
	if capacity <= 0 {
		capacity = 500
	}
	return &DirectoryRecorder{buf: make([]DirectoryEvent, capacity), cap: capacity}
}

// Record stores one change, stamping an id and timestamps if absent.
func (r *DirectoryRecorder) Record(e DirectoryEvent) {
	if r == nil {
		return
	}
	if e.EventID == "" {
		var b [16]byte
		if _, err := rand.Read(b[:]); err == nil {
			e.EventID = hex.EncodeToString(b[:])
		}
	}
	if e.Time == 0 {
		e.Time = time.Now().Unix()
	}
	if e.TimeISO == "" {
		e.TimeISO = time.Unix(e.Time, 0).UTC().Format(time.RFC3339)
	}
	if e.Result == "" {
		e.Result = "success"
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf[r.next] = e
	r.next = (r.next + 1) % r.cap
	if r.next == 0 {
		r.full = true
	}
}

// List returns up to limit events, newest first.
func (r *DirectoryRecorder) List(limit int) []DirectoryEvent {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.next
	if r.full {
		n = r.cap
	}
	if limit <= 0 || limit > n {
		limit = n
	}
	// Allocate from the ring's own size, never from the caller's limit: `limit`
	// originates in a request's $top, and sizing an allocation on request data
	// is how a large-$top request turns into a large allocation. n is bounded by
	// the fixed capacity, so this is bounded no matter what is asked for.
	out := make([]DirectoryEvent, 0, n)
	for i := 0; i < limit; i++ {
		idx := (r.next - 1 - i + r.cap*2) % r.cap
		out = append(out, r.buf[idx])
	}
	return out
}

func (r *DirectoryRecorder) Clear() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = make([]DirectoryEvent, r.cap)
	r.next, r.full = 0, false
}
