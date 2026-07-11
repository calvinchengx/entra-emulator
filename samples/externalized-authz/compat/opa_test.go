//go:build pdp_integration

package compat

import (
	"context"
	"testing"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"

	"github.com/calvinchengx/entra-emulator/samples/externalized-authz/authz"
)

// OPA (Open Policy Agent) is a Rego policy engine — embeddable in-process (no
// container, like Casbin). This leg proves the PDP port works against OPA.
//
// Honest caveat (see README): OPA is not ReBAC. We author a Rego policy that
// evaluates the same direct-or-group logic over the canonical facts (loaded as
// `data.tuples`), so this proves "our policy + adapter reproduce the contract",
// not engine equivalence with the Zanzibar engines.

const opaPolicy = `package authz

import rego.v1

default allow := false

# Direct grant: a tuple names the subject exactly.
allow if {
	some t in data.tuples
	t.subject == input.subject
	t.relation == input.relation
	t.object == input.object
}

# Group grant: a tuple names one of the caller's groups as a #member userset.
allow if {
	some g in input.groups
	some t in data.tuples
	t.subject == sprintf("%s#member", [g])
	t.relation == input.relation
	t.object == input.object
}
`

type opaHarness struct {
	query rego.PreparedEvalQuery
}

// Start is a no-op — OPA runs in-process, nothing to bring up.
func (h *opaHarness) Start(t *testing.T) {}

func (h *opaHarness) Seed(t *testing.T, facts []Fact) {
	tuples := make([]any, 0, len(facts))
	for _, f := range facts {
		tuples = append(tuples, map[string]any{
			"subject": f.Subject, "relation": f.Relation, "object": f.Object,
		})
	}
	store := inmem.NewFromObject(map[string]any{"tuples": tuples})
	q, err := rego.New(
		rego.Query("data.authz.allow"),
		rego.Module("authz.rego", opaPolicy),
		rego.Store(store),
	).PrepareForEval(context.Background())
	if err != nil {
		t.Fatalf("prepare rego: %v", err)
	}
	h.query = q
}

func (h *opaHarness) PDP() authz.PDP { return &opaPDP{h.query} }

func (h *opaHarness) Close() {}

// opaPDP adapts a prepared Rego query to the sample's PDP port. The policy
// itself expresses the direct-or-group logic, so the adapter just marshals the
// request into the Rego input document.
type opaPDP struct{ q rego.PreparedEvalQuery }

func (p opaPDP) Check(ctx context.Context, req authz.CheckRequest) (bool, error) {
	groups := req.Groups
	if groups == nil {
		groups = []string{}
	}
	rs, err := p.q.Eval(ctx, rego.EvalInput(map[string]any{
		"subject":  req.Subject,
		"relation": req.Relation,
		"object":   req.Object,
		"groups":   groups,
	}))
	if err != nil {
		return false, err
	}
	return rs.Allowed(), nil
}

func TestOPA(t *testing.T) {
	t.Run("contract", func(t *testing.T) { runContract(t, &opaHarness{}) })
	t.Run("e2e", func(t *testing.T) { runE2E(t, &opaHarness{}) })
}
