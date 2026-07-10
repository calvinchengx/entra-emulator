// Package faults holds runtime, admin-controllable fault-injection state so
// apps can test failure handling the real Entra can't reproduce on demand
// (roadmap #5). State is in-memory (not persisted) and reset-clearable.
package faults

import (
	"math/rand"
	"sync"
)

// Config describes the active faults. The zero value injects nothing.
type Config struct {
	// TokenError, when non-empty, forces the /token endpoint to return this
	// OAuth error code (e.g. "temporarily_unavailable", "invalid_grant")
	// instead of issuing a token.
	TokenError string `json:"tokenError"`
	// TokenErrorDescription is the error_description sent with TokenError.
	TokenErrorDescription string `json:"tokenErrorDescription"`
	// TokenLatencyMs delays every /token response by this many milliseconds.
	TokenLatencyMs int `json:"tokenLatencyMs"`
	// Probability (0..1] is the chance a set fault actually fires; <=0 is
	// treated as 1 (always). Lets tests exercise intermittent failures.
	Probability float64 `json:"probability"`
}

// Store is a concurrency-safe holder for the active Config.
type Store struct {
	mu  sync.RWMutex
	cfg Config
}

// New returns an empty (no-fault) store.
func New() *Store { return &Store{} }

// Get returns the current config.
func (s *Store) Get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// Set replaces the config.
func (s *Store) Set(c Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = c
}

// Clear resets to no faults.
func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = Config{}
}

// TokenFault reports the latency to apply and, if the token endpoint should
// fail this call, the error code + description. fire is false when no error
// fault is configured or the probability roll misses.
func (s *Store) TokenFault() (latencyMs int, code, desc string, fire bool) {
	c := s.Get()
	latencyMs = c.TokenLatencyMs
	if c.TokenError == "" {
		return latencyMs, "", "", false
	}
	p := c.Probability
	if p <= 0 || p >= 1 {
		return latencyMs, c.TokenError, c.TokenErrorDescription, true
	}
	return latencyMs, c.TokenError, c.TokenErrorDescription, rand.Float64() < p
}
