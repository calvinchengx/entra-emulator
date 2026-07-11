//go:build pdp_integration

package compat

import (
	"context"
	"testing"

	"github.com/calvinchengx/entra-emulator/samples/externalized-authz/authz"
)

// This file defines the compatibility contract every PDP backend must satisfy:
// a fixed set of relationship facts and a fixed decision matrix. Each engine
// harness translates the canonical facts into engine-native writes; the shared
// runContract asserts the adapter reproduces the matrix exactly. Adding an
// engine means writing one PDPHarness — the assertions are reused.

// Fact is a canonical relationship, engine-agnostic. Subject is either a user
// ("user:<id>") or a group userset ("group:<id>#member"); the sample stores
// group grants as usersets and supplies the caller's group memberships at
// request time (from the token's `groups` claim), never from the PDP.
type Fact struct {
	Subject, Relation, Object string
}

// Check is one decision the matrix asserts: does Subject (optionally acting
// through Groups) have Relation on Object?
type Check struct {
	Name                      string
	Subject, Relation, Object string
	Groups                    []string
	Want                      bool
}

// canonicalFacts + canonicalChecks are the single source of truth. Every
// backend must reproduce this exact allow/deny matrix.
var canonicalFacts = []Fact{
	{"user:alice", "reader", "doc:readme"},        // direct user grant
	{"group:eng#member", "reader", "doc:handbook"}, // group (userset) grant
	{"user:bob", "writer", "doc:draft"},           // direct writer grant
}

var canonicalChecks = []Check{
	{Name: "direct reader", Subject: "user:alice", Relation: "reader", Object: "doc:readme", Want: true},
	{Name: "group reader", Subject: "user:alice", Relation: "reader", Object: "doc:handbook", Groups: []string{"group:eng"}, Want: true},
	{Name: "no tuple", Subject: "user:bob", Relation: "reader", Object: "doc:readme", Want: false},
	{Name: "wrong relation", Subject: "user:alice", Relation: "writer", Object: "doc:readme", Want: false},
	{Name: "direct writer", Subject: "user:bob", Relation: "writer", Object: "doc:draft", Want: true},
	{Name: "group without membership", Subject: "user:carol", Relation: "reader", Object: "doc:handbook", Want: false},
	{Name: "unknown object", Subject: "user:alice", Relation: "reader", Object: "doc:missing", Want: false},
}

// PDPHarness wraps one authorization engine: bring it up, translate the
// canonical facts into engine-native writes, and expose the sample's PDP port.
type PDPHarness interface {
	// Start brings the engine up (container or in-process) and loads its
	// authorization model. It must t.Skip when the engine is unavailable
	// (e.g. Docker missing) rather than fail.
	Start(t *testing.T)
	// Seed translates canonical facts into engine-native relationship writes.
	Seed(t *testing.T, facts []Fact)
	// PDP returns the adapter under test — it must satisfy authz.PDP.
	PDP() authz.PDP
	// Close tears the engine down.
	Close()
}

// runContract seeds the canonical facts and asserts the adapter reproduces the
// decision matrix — the core compatibility proof, shared across all engines.
func runContract(t *testing.T, h PDPHarness) {
	t.Helper()
	h.Start(t)
	t.Cleanup(h.Close)
	h.Seed(t, canonicalFacts)
	pdp := h.PDP()

	for _, c := range canonicalChecks {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			got, err := pdp.Check(context.Background(), authz.CheckRequest{
				Subject:  c.Subject,
				Relation: c.Relation,
				Object:   c.Object,
				Groups:   c.Groups,
			})
			if err != nil {
				t.Fatalf("Check(%+v): %v", c, err)
			}
			if got != c.Want {
				t.Fatalf("%s: Check(sub=%s rel=%s obj=%s groups=%v) = %v, want %v",
					c.Name, c.Subject, c.Relation, c.Object, c.Groups, got, c.Want)
			}
		})
	}
}
