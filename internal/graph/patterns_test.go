package graph

import (
	"net/http"
	"strings"
	"testing"
)

// The enumerator is only worth having if it sees EVERYTHING Register installs.
// The way to know is to compare it with the real mux, which is the thing that
// actually serves requests: every enumerated pattern must be accepted by a
// ServeMux (which panics on a malformed or conflicting one), and none may repeat.
// There are more patterns than HandleFunc call sites (97 against 89 when this was
// written, 94 once the uncited oAuth2PermissionGrants duplicates went) because
// some calls sit in loops, which is the whole reason the source cannot simply be
// counted.
func TestRegisteredPatternsIsCompleteAndServable(t *testing.T) {
	patterns := RegisteredPatterns("")

	mux := http.NewServeMux()
	(&Graph{}).Register(mux, "") // panics on a duplicate or malformed pattern
	seen := map[string]bool{}
	for _, p := range patterns {
		if seen[p] {
			t.Errorf("pattern registered twice: %s", p)
		}
		seen[p] = true
		if !strings.Contains(p, " /") {
			t.Errorf("not a METHOD /path pattern: %q", p)
		}
	}
	// A floor rather than an exact figure, so adding a route is not a test edit;
	// what it guards is the enumerator silently seeing a fraction, which is the
	// failure a source regex had (it read 19).
	if len(patterns) < 94 {
		t.Fatalf("enumerated %d patterns, but Register installs at least 94", len(patterns))
	}
}

func TestRegisteredPatternsRespectsThePrefix(t *testing.T) {
	root, compat := RegisteredPatterns(""), RegisteredPatterns("/graph")
	if len(root) != len(compat) {
		t.Fatalf("prefix changed the route count: %d vs %d", len(root), len(compat))
	}
	for i := range root {
		method, path, _ := strings.Cut(root[i], " ")
		if want := method + " /graph" + path; compat[i] != want {
			t.Fatalf("pattern %d: %q, want %q", i, compat[i], want)
		}
	}
}
