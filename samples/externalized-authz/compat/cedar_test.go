//go:build pdp_integration

package compat

import (
	"context"
	"fmt"
	"strings"
	"testing"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"

	"github.com/calvinchengx/entra-emulator/samples/externalized-authz/authz"
)

// Cedar (AWS) is a policy engine with a pure-Go implementation (cedar-go) —
// embeddable in-process, no container. This leg proves the PDP port works
// against Cedar.
//
// Honest caveat (see README): Cedar is not ReBAC. We translate each canonical
// fact into a `permit` policy (a direct user grant, or `principal in Group::..`
// for a group userset) and, per check, place the caller's request-time groups
// in the principal's entity `parents` so Cedar's `in` operator resolves group
// membership. This proves "our policy + adapter reproduce the contract", not
// engine equivalence with the Zanzibar engines.

type cedarHarness struct {
	policies *cedar.PolicySet
}

// Start is a no-op — Cedar runs in-process, nothing to bring up.
func (h *cedarHarness) Start(t *testing.T) {}

func (h *cedarHarness) Seed(t *testing.T, facts []Fact) {
	var b strings.Builder
	for _, f := range facts {
		objType, objID := cedarSplit(f.Object)
		if subjPart, _, isUserset := strings.Cut(f.Subject, "#"); isUserset {
			// Group userset: grant to any principal that is `in` the group.
			gType, gID := cedarSplit(subjPart)
			fmt.Fprintf(&b, "permit(principal in %s::\"%s\", action == Action::\"%s\", resource == %s::\"%s\");\n",
				cedarType(gType), gID, f.Relation, cedarType(objType), objID)
		} else {
			sType, sID := cedarSplit(f.Subject)
			fmt.Fprintf(&b, "permit(principal == %s::\"%s\", action == Action::\"%s\", resource == %s::\"%s\");\n",
				cedarType(sType), sID, f.Relation, cedarType(objType), objID)
		}
	}
	ps, err := cedar.NewPolicySetFromBytes("compat.cedar", []byte(b.String()))
	if err != nil {
		t.Fatalf("parse cedar policies: %v\n%s", err, b.String())
	}
	h.policies = ps
}

func (h *cedarHarness) PDP() authz.PDP { return &cedarPDP{h} }

func (h *cedarHarness) Close() {}

// cedarPDP adapts Cedar to the sample's PDP port. Cedar resolves group
// membership through the entity hierarchy, so the request-time groups become
// the principal's parents; the generated policies do the rest.
type cedarPDP struct{ h *cedarHarness }

func (p *cedarPDP) Check(_ context.Context, req authz.CheckRequest) (bool, error) {
	principal := cedarUID(req.Subject)

	groupUIDs := make([]types.EntityUID, 0, len(req.Groups))
	for _, g := range req.Groups {
		groupUIDs = append(groupUIDs, cedarUID(g))
	}
	entities := cedar.EntityMap{
		principal: types.Entity{UID: principal, Parents: types.NewEntityUIDSet(groupUIDs...)},
	}
	for _, g := range groupUIDs {
		entities[g] = types.Entity{UID: g}
	}

	decision, _ := cedar.Authorize(p.h.policies, entities, cedar.Request{
		Principal: principal,
		Action:    types.NewEntityUID("Action", types.String(req.Relation)),
		Resource:  cedarUID(req.Object),
	})
	return decision == cedar.Allow, nil
}

// cedarSplit parses "type:id" (ignoring any "#relation" userset suffix).
func cedarSplit(s string) (string, string) {
	objPart, _, _ := strings.Cut(s, "#")
	typ, id, _ := strings.Cut(objPart, ":")
	return typ, id
}

// cedarUID builds a Cedar EntityUID from "type:id" (or "type:id#relation").
func cedarUID(s string) types.EntityUID {
	typ, id := cedarSplit(s)
	return types.NewEntityUID(types.EntityType(cedarType(typ)), types.String(id))
}

// cedarType maps the sample's lowercase entity types to Cedar's PascalCase
// entity type names.
func cedarType(t string) string {
	switch t {
	case "user":
		return "User"
	case "group":
		return "Group"
	case "doc":
		return "Doc"
	}
	if t == "" {
		return t
	}
	return strings.ToUpper(t[:1]) + t[1:]
}

func TestCedar(t *testing.T) {
	t.Run("contract", func(t *testing.T) { runContract(t, &cedarHarness{}) })
	t.Run("e2e", func(t *testing.T) { runE2E(t, &cedarHarness{}) })
}
