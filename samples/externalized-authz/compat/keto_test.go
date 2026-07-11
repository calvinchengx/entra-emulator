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

// Ory Keto is a Zanzibar/ReBAC engine — the canonical facts map 1:1 onto its
// relation tuples, so this leg proves genuine cross-engine equivalence. It runs
// in a container via testcontainers (memory datastore, namespaces declared via
// a mounted config) and skips when Docker is absent.
//
// As with SpiceDB, we talk to Keto over its REST API with net/http rather than
// keto-client-go, keeping this module's go.mod lean.

// ketoImage is pinned by tag + digest for idempotent runs (see README).
const ketoImage = "oryd/keto:v0.12.0@sha256:eecd1cba4e7442e989e4f577a24165d9f8985064bc4bd706aa34b879eba0c9d6"

// ketoConfig declares the two namespaces the sample uses (doc, group) and an
// in-memory datastore. Keto is schema-light: namespaces need only a name; the
// engine stores tuples and expands subject-sets without relation type defs.
const ketoConfig = `version: v0.12.0
dsn: memory
namespaces:
  - id: 0
    name: doc
  - id: 1
    name: group
serve:
  read:
    host: 0.0.0.0
    port: 4466
  write:
    host: 0.0.0.0
    port: 4467
log:
  level: error
`

type ketoHarness struct {
	container testcontainers.Container
	readURL   string
	writeURL  string
}

func (h *ketoHarness) Start(t *testing.T) {
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        ketoImage,
			Cmd:          []string{"serve", "-c", "/home/ory/keto.yml"},
			ExposedPorts: []string{"4466/tcp", "4467/tcp"},
			Files: []testcontainers.ContainerFile{{
				Reader:            strings.NewReader(ketoConfig),
				ContainerFilePath: "/home/ory/keto.yml",
				FileMode:          0o644,
			}},
			WaitingFor: wait.ForListeningPort("4467/tcp").WithStartupTimeout(90 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Skipf("Keto container unavailable (Docker required): %v", err)
	}
	h.container = c
	host, err := c.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}
	readPort, err := c.MappedPort(ctx, "4466/tcp")
	if err != nil {
		t.Fatalf("read port: %v", err)
	}
	writePort, err := c.MappedPort(ctx, "4467/tcp")
	if err != nil {
		t.Fatalf("write port: %v", err)
	}
	h.readURL = fmt.Sprintf("http://%s:%s", host, readPort.Port())
	h.writeURL = fmt.Sprintf("http://%s:%s", host, writePort.Port())

	// Probe readiness: the write API may accept TCP before it serves. A no-op
	// create against a declared namespace confirms the API is up.
	var perr error
	for i := 0; i < 60; i++ {
		if perr = h.write(ctx, Fact{Subject: "user:__probe__", Relation: "reader", Object: "doc:__probe__"}); perr == nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if perr != nil {
		t.Fatalf("keto write API not ready: %v", perr)
	}
}

func (h *ketoHarness) Seed(t *testing.T, facts []Fact) {
	for _, f := range facts {
		if err := h.write(context.Background(), f); err != nil {
			t.Fatalf("write tuple %+v: %v", f, err)
		}
	}
}

func (h *ketoHarness) PDP() authz.PDP { return &ketoPDP{h} }

func (h *ketoHarness) Close() {
	if h.container != nil {
		_ = h.container.Terminate(context.Background())
	}
}

// write creates a relation tuple via the Keto write API.
func (h *ketoHarness) write(ctx context.Context, f Fact) error {
	ns, obj := ketoObject(f.Object)
	body := map[string]any{"namespace": ns, "object": obj, "relation": f.Relation}
	for k, v := range ketoSubject(f.Subject) {
		body[k] = v
	}
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, "PUT", h.writeURL+"/admin/relation-tuples", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("write -> %d: %s", resp.StatusCode, out)
	}
	return nil
}

// ketoPDP adapts Keto to the sample's PDP port: direct subject first, then each
// request-time group as a `#member` subject-set — the same direct-or-group
// semantics as the reference InMemoryPDP.
type ketoPDP struct{ h *ketoHarness }

func (p *ketoPDP) Check(ctx context.Context, req authz.CheckRequest) (bool, error) {
	subjects := append([]string{req.Subject}, usersets(req.Groups)...)
	ns, obj := ketoObject(req.Object)
	for _, s := range subjects {
		body := map[string]any{"namespace": ns, "object": obj, "relation": req.Relation}
		for k, v := range ketoSubject(s) {
			body[k] = v
		}
		raw, _ := json.Marshal(body)
		r, _ := http.NewRequestWithContext(ctx, "POST", p.h.readURL+"/relation-tuples/check", bytes.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			return false, err
		}
		out, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		// Keto returns 200 for allowed and 403 for denied — both carry an
		// {"allowed": bool} body. Any other status is a real error.
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusForbidden {
			return false, fmt.Errorf("check -> %d: %s", resp.StatusCode, out)
		}
		var res struct {
			Allowed bool `json:"allowed"`
		}
		if err := json.Unmarshal(out, &res); err != nil {
			return false, err
		}
		if res.Allowed {
			return true, nil
		}
	}
	return false, nil
}

// ketoObject parses "type:id" into (namespace, object).
func ketoObject(s string) (string, string) {
	ns, obj, _ := strings.Cut(s, ":")
	return ns, obj
}

// ketoSubject renders "user:alice" as an opaque subject_id, or a
// "group:eng#member" userset as a subject_set, returning the body fields to
// merge into a request.
func ketoSubject(s string) map[string]any {
	objPart, rel, hasRel := strings.Cut(s, "#")
	if !hasRel {
		return map[string]any{"subject_id": s}
	}
	ns, obj, _ := strings.Cut(objPart, ":")
	return map[string]any{"subject_set": map[string]any{"namespace": ns, "object": obj, "relation": rel}}
}

func TestKeto(t *testing.T) {
	t.Run("contract", func(t *testing.T) { runContract(t, &ketoHarness{}) })
	t.Run("e2e", func(t *testing.T) { runE2E(t, &ketoHarness{}) })
}
