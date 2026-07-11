// Package clock provides the emulator's controllable time source (roadmap
// #6). Every timestamp the emulator stamps — token iat/nbf/exp, refresh and
// device-code expiry, sessions — flows through Store.Now, which delegates
// here, so advancing or freezing this clock makes expiry testable without
// real sleeps.
package clock

import (
	"sync"
	"time"
)

// Clock is a concurrency-safe, offsettable, freezable wall clock.
type Clock struct {
	mu       sync.RWMutex
	offset   int64 // seconds added to real time when not frozen
	frozen   bool
	frozenAt int64 // absolute epoch returned while frozen
	realNow  func() int64
}

// New returns a clock tracking real time.
func New() *Clock {
	return &Clock{realNow: func() int64 { return time.Now().Unix() }}
}

// Now returns the current controlled time (epoch seconds).
func (c *Clock) Now() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.frozen {
		return c.frozenAt
	}
	return c.realNow() + c.offset
}

// SetOffset sets an absolute offset from real time and unfreezes.
func (c *Clock) SetOffset(seconds int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.offset = seconds
	c.frozen = false
}

// Advance moves the controlled time forward (or back) by delta seconds,
// honoring the frozen state.
func (c *Clock) Advance(seconds int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.frozen {
		c.frozenAt += seconds
		return
	}
	c.offset += seconds
}

// Freeze pins time at the current controlled value.
func (c *Clock) Freeze() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.frozen {
		c.frozenAt = c.realNow() + c.offset
		c.frozen = true
	}
}

// Unfreeze resumes real time from wherever the frozen value was, keeping
// continuity (no jump).
func (c *Clock) Unfreeze() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.frozen {
		c.offset = c.frozenAt - c.realNow()
		c.frozen = false
	}
}

// Reset returns to real time (offset 0, unfrozen).
func (c *Clock) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.offset = 0
	c.frozen = false
	c.frozenAt = 0
}

// State is the observable clock state.
type State struct {
	OffsetSeconds int64  `json:"offsetSeconds"`
	Frozen        bool   `json:"frozen"`
	Now           int64  `json:"now"`
	NowISO        string `json:"nowISO"`
}

// State returns the current clock state.
func (c *Clock) State() State {
	c.mu.RLock()
	defer c.mu.RUnlock()
	now := c.realNow() + c.offset
	if c.frozen {
		now = c.frozenAt
	}
	return State{
		OffsetSeconds: c.offset,
		Frozen:        c.frozen,
		Now:           now,
		NowISO:        time.Unix(now, 0).UTC().Format(time.RFC3339),
	}
}
