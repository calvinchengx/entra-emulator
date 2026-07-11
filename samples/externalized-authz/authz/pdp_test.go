package authz

import (
	"context"
	"testing"
)

func TestInMemoryPDP(t *testing.T) {
	pdp := NewInMemoryPDP()
	pdp.Write("user:alice", "reader", "doc:readme")
	pdp.Write("group:eng#member", "writer", "doc:spec")

	ctx := context.Background()
	cases := []struct {
		name string
		req  CheckRequest
		want bool
	}{
		{"direct allow", CheckRequest{Subject: "user:alice", Relation: "reader", Object: "doc:readme"}, true},
		{"wrong relation", CheckRequest{Subject: "user:alice", Relation: "writer", Object: "doc:readme"}, false},
		{"wrong object", CheckRequest{Subject: "user:alice", Relation: "reader", Object: "doc:other"}, false},
		{"wrong subject", CheckRequest{Subject: "user:bob", Relation: "reader", Object: "doc:readme"}, false},
		{"group allow", CheckRequest{Subject: "user:bob", Relation: "writer", Object: "doc:spec", Groups: []string{"group:eng"}}, true},
		{"group miss", CheckRequest{Subject: "user:bob", Relation: "writer", Object: "doc:spec", Groups: []string{"group:sales"}}, false},
	}
	for _, tc := range cases {
		got, err := pdp.Check(ctx, tc.req)
		if err != nil {
			t.Fatalf("%s: unexpected error %v", tc.name, err)
		}
		if got != tc.want {
			t.Fatalf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
