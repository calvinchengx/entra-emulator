//go:build pdp_integration

package compat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/calvinchengx/entra-emulator/samples/externalized-authz/authz"
)

// Permify is a Zanzibar/ReBAC engine — the canonical facts map 1:1 onto its
// relationships, so this leg proves genuine cross-engine equivalence. It runs
// in a container via testcontainers (in-memory datastore, default tenant "t1")
// and skips when Docker is absent. Reached over its HTTP API with net/http.

// permifyImage is pinned by tag + digest for idempotent runs (see README).
const permifyImage = "ghcr.io/permify/permify:v1.2.0@sha256:832ac82f56c9ef91877ea245b8eb5499ace7fdc3d1927c71e5e6fbc25c4f914e"

const permifyTenant = "t1" // Permify ships with this default tenant.

// permifySchema mirrors the sample: a doc grants reader/writer to users
// directly or to a group's members (a userset). Group membership is not
// stored — the caller's groups arrive at request time and the adapter checks
// each as a `group:<id>#member` subject.
const permifySchema = `entity user {}

entity group {
	relation member @user
}

entity doc {
	relation reader @user @group#member
	relation writer @user @group#member
}`

type permifyHarness struct {
	container testcontainers.Container
	baseURL   string
}

func (h *permifyHarness) Start(t *testing.T) {
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        permifyImage,
			Cmd:          []string{"serve"},
			ExposedPorts: []string{"3476/tcp"},
			WaitingFor:   wait.ForListeningPort("3476/tcp").WithStartupTimeout(90 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Skipf("Permify container unavailable (Docker required): %v", err)
	}
	h.container = c

	host, err := c.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}
	port, err := c.MappedPort(ctx, "3476/tcp")
	if err != nil {
		t.Fatalf("mapped port: %v", err)
	}
	h.baseURL = fmt.Sprintf("http://%s:%s", host, port.Port())

	// Retry the schema write until the HTTP API is serving (readiness probe).
	var werr error
	for i := 0; i < 60; i++ {
		_, werr = h.post(ctx, "/v1/tenants/"+permifyTenant+"/schemas/write",
			map[string]any{"schema": permifySchema})
		if werr == nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if werr != nil {
		t.Fatalf("write schema (after retries): %v", werr)
	}
}

func (h *permifyHarness) Seed(t *testing.T, facts []Fact) {
	tuples := make([]map[string]any, 0, len(facts))
	for _, f := range facts {
		tuples = append(tuples, map[string]any{
			"entity":   permifyEntity(f.Object),
			"relation": f.Relation,
			"subject":  permifySubject(f.Subject),
		})
	}
	_, err := h.post(context.Background(), "/v1/tenants/"+permifyTenant+"/data/write",
		map[string]any{"metadata": map[string]any{"schema_version": ""}, "tuples": tuples})
	if err != nil {
		t.Fatalf("write data: %v", err)
	}
}

func (h *permifyHarness) PDP() authz.PDP { return &permifyPDP{h} }

func (h *permifyHarness) Close() {
	if h.container != nil {
		_ = h.container.Terminate(context.Background())
	}
}

func (h *permifyHarness) post(ctx context.Context, path string, body any) ([]byte, error) {
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, "POST", h.baseURL+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("%s -> %d: %s", path, resp.StatusCode, out)
	}
	return out, nil
}

// permifyPDP adapts Permify to the sample's PDP port: direct subject first, then
// each request-time group as a `#member` subject — the same direct-or-group
// semantics as the reference InMemoryPDP.
type permifyPDP struct{ h *permifyHarness }

func (p *permifyPDP) Check(ctx context.Context, req authz.CheckRequest) (bool, error) {
	subjects := append([]string{req.Subject}, usersets(req.Groups)...)
	for _, s := range subjects {
		out, err := p.h.post(ctx, "/v1/tenants/"+permifyTenant+"/permissions/check", map[string]any{
			"metadata":   map[string]any{"schema_version": "", "snap_token": "", "depth": 20},
			"entity":     permifyEntity(req.Object),
			"permission": req.Relation,
			"subject":    permifySubject(s),
		})
		if err != nil {
			return false, err
		}
		var res struct {
			Can string `json:"can"`
		}
		if err := json.Unmarshal(out, &res); err != nil {
			return false, err
		}
		if res.Can == "CHECK_RESULT_ALLOWED" {
			return true, nil
		}
	}
	return false, nil
}

// permifyEntity parses "type:id" into a Permify entity reference.
func permifyEntity(s string) map[string]any {
	typ, id, _ := strings.Cut(s, ":")
	return map[string]any{"type": typ, "id": id}
}

// permifySubject parses "type:id" or a "type:id#relation" userset into a Permify
// subject (the optional relation carries the userset, e.g. group#member).
func permifySubject(s string) map[string]any {
	objPart, rel, hasRel := strings.Cut(s, "#")
	typ, id, _ := strings.Cut(objPart, ":")
	sub := map[string]any{"type": typ, "id": id}
	if hasRel {
		sub["relation"] = rel
	}
	return sub
}

func TestPermify(t *testing.T) {
	t.Run("contract", func(t *testing.T) { runContract(t, &permifyHarness{}) })
	t.Run("e2e", func(t *testing.T) { runE2E(t, &permifyHarness{}) })
}
