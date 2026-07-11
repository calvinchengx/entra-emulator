//go:build pdp_integration

package compat

import (
	"context"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/calvinchengx/entra-emulator/samples/externalized-authz/authz"
)

// Casbin is an in-process RBAC/ABAC library — no container. This harness proves
// the PDP port works against Casbin's enforcer.
//
// Honest caveat (see README): Casbin is not ReBAC. We author an equivalent ACL
// model (sub, obj, act) and translate each canonical fact into a policy line;
// group grants are stored against the "group:<id>#member" pseudo-subject and
// the adapter ORs the caller's request-time groups — mirroring the sample's
// InMemoryPDP. What this proves is "our adapter + our model reproduce the
// contract", not that Casbin and OpenFGA are semantically identical.

const casbinModel = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`

type casbinHarness struct {
	enforcer *casbin.Enforcer
}

func (h *casbinHarness) Start(t *testing.T) {
	m, err := model.NewModelFromString(casbinModel)
	if err != nil {
		t.Fatalf("casbin model: %v", err)
	}
	e, err := casbin.NewEnforcer(m)
	if err != nil {
		t.Fatalf("casbin enforcer: %v", err)
	}
	h.enforcer = e
}

func (h *casbinHarness) Seed(t *testing.T, facts []Fact) {
	for _, f := range facts {
		// Casbin policy is (sub, obj, act); our relation is the act.
		if _, err := h.enforcer.AddPolicy(f.Subject, f.Object, f.Relation); err != nil {
			t.Fatalf("add policy %+v: %v", f, err)
		}
	}
}

func (h *casbinHarness) PDP() authz.PDP { return casbinPDP{h.enforcer} }

func (h *casbinHarness) Close() {}

// casbinPDP adapts a Casbin enforcer to the sample's PDP port. It checks the
// subject directly, then each request-time group as a userset subject — the
// same direct-or-group logic the reference InMemoryPDP uses.
type casbinPDP struct{ e *casbin.Enforcer }

func (p casbinPDP) Check(_ context.Context, req authz.CheckRequest) (bool, error) {
	if ok, err := p.e.Enforce(req.Subject, req.Object, req.Relation); err != nil {
		return false, err
	} else if ok {
		return true, nil
	}
	for _, g := range req.Groups {
		if ok, err := p.e.Enforce(g+"#member", req.Object, req.Relation); err != nil {
			return false, err
		} else if ok {
			return true, nil
		}
	}
	return false, nil
}

func TestCasbin(t *testing.T) {
	t.Run("contract", func(t *testing.T) { runContract(t, &casbinHarness{}) })
	t.Run("e2e", func(t *testing.T) { runE2E(t, &casbinHarness{}) })
}
