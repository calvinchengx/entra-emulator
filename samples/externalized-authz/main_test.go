package main

import (
	"os"
	"testing"
)

// TestEnv covers the env() helper (both the fallback and set branches). It
// lives in package main because env is the runner's own helper; the reusable
// library and its tests live in the authz package.
func TestEnv(t *testing.T) {
	const k = "EXTAUTHZ_TEST_ENV"
	os.Unsetenv(k)
	if got := env(k, "fallback"); got != "fallback" {
		t.Fatalf("unset env: want fallback, got %q", got)
	}
	t.Setenv(k, "explicit")
	if got := env(k, "fallback"); got != "explicit" {
		t.Fatalf("set env: want explicit, got %q", got)
	}
}
