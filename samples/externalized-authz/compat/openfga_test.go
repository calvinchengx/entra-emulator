//go:build pdp_integration

package compat

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	openfga "github.com/openfga/go-sdk"
	"github.com/openfga/go-sdk/client"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/calvinchengx/entra-emulator/samples/externalized-authz/authz"
)

// OpenFGA is the reference ReBAC (Google Zanzibar) engine — the canonical
// facts map 1:1 onto its relationship tuples, so this leg proves genuine
// cross-engine equivalence (unlike the Casbin leg's authored translation).
// It runs in a container via testcontainers and skips when Docker is absent.

// openFGAImage is pinned by tag *and* digest so tests are idempotent: the tag
// is human-readable, the @sha256 digest makes the pulled image byte-identical
// even if the tag is ever re-pushed upstream. Dependabot can bump both together.
const openFGAImage = "openfga/openfga:v1.8.0@sha256:a9e47c191ca6dcae91fb59320ff4ddb7e24ed56a04febdd1180c3a0946c50597"

// authModel mirrors the sample: docs grant reader/writer to users directly or
// to a group's members (a userset). Group membership itself is not stored — the
// caller's groups arrive at request time from the token, and the adapter checks
// each as a `group:<id>#member` userset.
const authModel = `{
  "schema_version": "1.1",
  "type_definitions": [
    {"type": "user"},
    {"type": "group",
     "relations": {"member": {"this": {}}},
     "metadata": {"relations": {"member": {"directly_related_user_types": [{"type": "user"}]}}}},
    {"type": "doc",
     "relations": {"reader": {"this": {}}, "writer": {"this": {}}},
     "metadata": {"relations": {
       "reader": {"directly_related_user_types": [{"type": "user"}, {"type": "group", "relation": "member"}]},
       "writer": {"directly_related_user_types": [{"type": "user"}, {"type": "group", "relation": "member"}]}
     }}}
  ]
}`

type openFGAHarness struct {
	container testcontainers.Container
	client    *client.OpenFgaClient
}

func (h *openFGAHarness) Start(t *testing.T) {
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        openFGAImage,
			Cmd:          []string{"run"},
			ExposedPorts: []string{"8080/tcp"},
			WaitingFor:   wait.ForHTTP("/healthz").WithPort("8080/tcp").WithStartupTimeout(90 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Skipf("OpenFGA container unavailable (Docker required): %v", err)
	}
	h.container = c

	host, err := c.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}
	port, err := c.MappedPort(ctx, "8080/tcp")
	if err != nil {
		t.Fatalf("mapped port: %v", err)
	}
	apiURL := fmt.Sprintf("http://%s:%s", host, port.Port())

	fga, err := client.NewSdkClient(&client.ClientConfiguration{ApiUrl: apiURL})
	if err != nil {
		t.Fatalf("openfga client: %v", err)
	}
	store, err := fga.CreateStore(ctx).Body(client.ClientCreateStoreRequest{Name: "compat"}).Execute()
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	if err := fga.SetStoreId(store.GetId()); err != nil {
		t.Fatalf("set store: %v", err)
	}

	var modelReq client.ClientWriteAuthorizationModelRequest
	if err := json.Unmarshal([]byte(authModel), &modelReq); err != nil {
		t.Fatalf("model json: %v", err)
	}
	modelResp, err := fga.WriteAuthorizationModel(ctx).Body(modelReq).Execute()
	if err != nil {
		t.Fatalf("write model: %v", err)
	}
	if err := fga.SetAuthorizationModelId(modelResp.GetAuthorizationModelId()); err != nil {
		t.Fatalf("set model: %v", err)
	}
	h.client = fga
}

func (h *openFGAHarness) Seed(t *testing.T, facts []Fact) {
	writes := make([]openfga.TupleKey, 0, len(facts))
	for _, f := range facts {
		writes = append(writes, openfga.TupleKey{User: f.Subject, Relation: f.Relation, Object: f.Object})
	}
	_, err := h.client.Write(context.Background()).Body(client.ClientWriteRequest{Writes: writes}).Execute()
	if err != nil {
		t.Fatalf("write tuples: %v", err)
	}
}

func (h *openFGAHarness) PDP() authz.PDP { return &openFGAPDP{h.client} }

func (h *openFGAHarness) Close() {
	if h.container != nil {
		_ = h.container.Terminate(context.Background())
	}
}

// openFGAPDP adapts the OpenFGA client to the sample's PDP port. Direct subject
// first, then each request-time group as a `#member` userset — the same
// direct-or-group semantics as the reference InMemoryPDP.
type openFGAPDP struct{ c *client.OpenFgaClient }

func (p *openFGAPDP) Check(ctx context.Context, req authz.CheckRequest) (bool, error) {
	subjects := append([]string{req.Subject}, usersets(req.Groups)...)
	for _, s := range subjects {
		res, err := p.c.Check(ctx).Body(client.ClientCheckRequest{
			User: s, Relation: req.Relation, Object: req.Object,
		}).Execute()
		if err != nil {
			return false, err
		}
		if res.GetAllowed() {
			return true, nil
		}
	}
	return false, nil
}

func usersets(groups []string) []string {
	out := make([]string, len(groups))
	for i, g := range groups {
		out[i] = g + "#member"
	}
	return out
}

func TestOpenFGA(t *testing.T) {
	t.Run("contract", func(t *testing.T) { runContract(t, &openFGAHarness{}) })
	t.Run("e2e", func(t *testing.T) { runE2E(t, &openFGAHarness{}) })
}
