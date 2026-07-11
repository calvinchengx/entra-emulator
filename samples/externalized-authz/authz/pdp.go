package authz

import (
	"context"
	"sync"
)

// The Policy Decision Point (PDP) is the "authorization" half of the pattern:
// given an authenticated principal and its group memberships, it decides
// whether a specific action on a specific object is allowed. The emulator (the
// IdP) never makes this call — it only proves identity. That separation is the
// whole point: identity from Entra, fine-grained authorization from a dedicated
// service such as OpenFGA (https://openfga.dev).
//
// CheckRequest mirrors an OpenFGA check: "is <subject> related to <object> via
// <relation>?" (e.g. user:alice is `reader` of doc:readme).
type CheckRequest struct {
	Subject  string // e.g. "user:<oid>"
	Relation string // e.g. "reader" | "writer"
	Object   string // e.g. "doc:readme"
	Groups   []string // group ids the subject belongs to (e.g. "group:<gid>")
}

// PDP is the port the resource server depends on. Swap the in-memory
// implementation below for a real OpenFGA client without touching the server:
//
//	// import openfga "github.com/openfga/go-sdk/client"
//	// func (p *openFGAPDP) Check(ctx, req) (bool, error) {
//	//     res, _ := p.client.Check(ctx).Body(fgaCheckBody(req)).Execute()
//	//     return res.GetAllowed(), nil
//	// }
type PDP interface {
	Check(ctx context.Context, req CheckRequest) (bool, error)
}

// tuple is a stored relationship (subject, relation, object) — the same shape
// OpenFGA persists. A subject may be a user ("user:<oid>") or a group binding
// ("group:<gid>#member").
type tuple struct {
	subject, relation, object string
}

// InMemoryPDP is a minimal relationship-tuple checker standing in for OpenFGA
// so the sample runs with zero external services. It supports direct user
// tuples and group-membership tuples (group:<gid>#member as a relation
// subject). It is intentionally tiny — real OpenFGA adds an authorization model
// (type definitions, computed/tuple-to-userset relations) this does not.
type InMemoryPDP struct {
	mu     sync.RWMutex
	tuples []tuple
}

func NewInMemoryPDP() *InMemoryPDP { return &InMemoryPDP{} }

// Write adds a relationship tuple (idempotent-ish; duplicates are harmless).
func (p *InMemoryPDP) Write(subject, relation, object string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tuples = append(p.tuples, tuple{subject, relation, object})
}

// Check returns true if the subject — directly or via one of its groups — has
// the requested relation to the object.
func (p *InMemoryPDP) Check(_ context.Context, req CheckRequest) (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, t := range p.tuples {
		if t.relation != req.Relation || t.object != req.Object {
			continue
		}
		if t.subject == req.Subject {
			return true, nil
		}
		for _, g := range req.Groups {
			if t.subject == g+"#member" {
				return true, nil
			}
		}
	}
	return false, nil
}
