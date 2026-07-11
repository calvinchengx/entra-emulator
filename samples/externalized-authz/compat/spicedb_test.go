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

// SpiceDB (Authzed) is a Zanzibar/ReBAC engine — the canonical facts map 1:1
// onto its relationships, so this leg proves genuine cross-engine equivalence.
// Runs in a container via testcontainers (memory datastore) and skips when
// Docker is absent.
//
// We talk to SpiceDB over its HTTP/REST gateway with net/http rather than the
// authzed-go gRPC SDK: the SDK pulls a heavy, conflict-prone dependency tree
// (buf.build protovalidate, cloud.google.com), and hand-rolling a handful of
// JSON calls keeps this module's go.mod lean — matching the emulator's own
// no-SDK philosophy.

// spiceDBImage is pinned by tag + digest for idempotent runs (see README).
const spiceDBImage = "authzed/spicedb:v1.35.3@sha256:a2bb8fbfcdcb1123b1b1f1c1e28f20041f8230e3fc6748918d258cd3093f7930"

const spiceDBPresharedKey = "compat-test-key"

// spiceSchema mirrors the sample: a doc grants reader/writer to users directly
// or to a group's members (a userset). Group membership is not stored — the
// caller's groups arrive at request time and the adapter checks each as a
// `group:<id>#member` subject.
const spiceSchema = `definition user {}

definition group {
	relation member: user
}

definition doc {
	relation reader: user | group#member
	relation writer: user | group#member
}`

// SpiceDB HTTP API shapes (subset of the v1 REST gateway).
type spiceObjRef struct {
	ObjectType string `json:"objectType"`
	ObjectID   string `json:"objectId"`
}
type spiceSubRef struct {
	Object           spiceObjRef `json:"object"`
	OptionalRelation string      `json:"optionalRelation,omitempty"`
}
type spiceRel struct {
	Resource spiceObjRef `json:"resource"`
	Relation string      `json:"relation"`
	Subject  spiceSubRef `json:"subject"`
}

type spiceDBHarness struct {
	container testcontainers.Container
	baseURL   string
}

func (h *spiceDBHarness) Start(t *testing.T) {
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        spiceDBImage,
			Cmd:          []string{"serve", "--grpc-preshared-key", spiceDBPresharedKey, "--http-enabled"},
			ExposedPorts: []string{"8443/tcp"},
			WaitingFor:   wait.ForListeningPort("8443/tcp").WithStartupTimeout(90 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Skipf("SpiceDB container unavailable (Docker required): %v", err)
	}
	h.container = c

	host, err := c.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}
	port, err := c.MappedPort(ctx, "8443/tcp")
	if err != nil {
		t.Fatalf("mapped port: %v", err)
	}
	h.baseURL = fmt.Sprintf("http://%s:%s", host, port.Port())

	// ForListeningPort fires when 8443 accepts TCP, but SpiceDB's HTTP gateway
	// may not be serving yet (first request EOFs). Retry the schema write —
	// which doubles as the readiness probe — until the gateway responds.
	var err2 error
	for i := 0; i < 60; i++ {
		if _, err2 = h.postCtx(ctx, "/v1/schema/write", map[string]any{"schema": spiceSchema}); err2 == nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err2 != nil {
		t.Fatalf("write schema (after retries): %v", err2)
	}
}

func (h *spiceDBHarness) Seed(t *testing.T, facts []Fact) {
	updates := make([]map[string]any, 0, len(facts))
	for _, f := range facts {
		updates = append(updates, map[string]any{
			"operation": "OPERATION_TOUCH",
			"relationship": spiceRel{
				Resource: spiceObject(f.Object),
				Relation: f.Relation,
				Subject:  spiceSubject(f.Subject),
			},
		})
	}
	if _, err := h.post(t, "/v1/relationships/write", map[string]any{"updates": updates}); err != nil {
		t.Fatalf("write relationships: %v", err)
	}
}

func (h *spiceDBHarness) PDP() authz.PDP { return &spiceDBPDP{h} }

func (h *spiceDBHarness) Close() {
	if h.container != nil {
		_ = h.container.Terminate(context.Background())
	}
}

// post issues an authenticated JSON POST to the SpiceDB HTTP gateway.
func (h *spiceDBHarness) post(t *testing.T, path string, body any) ([]byte, error) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", h.baseURL+path, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+spiceDBPresharedKey)
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

// spiceDBPDP adapts SpiceDB to the sample's PDP port: direct subject first, then
// each request-time group as a `#member` subject — the same direct-or-group
// semantics as the reference InMemoryPDP. Checks are fully-consistent so they
// always observe the seeded relationships.
type spiceDBPDP struct{ h *spiceDBHarness }

func (p *spiceDBPDP) Check(ctx context.Context, req authz.CheckRequest) (bool, error) {
	subjects := append([]string{req.Subject}, usersets(req.Groups)...)
	for _, s := range subjects {
		out, err := p.h.postCtx(ctx, "/v1/permissions/check", map[string]any{
			"consistency": map[string]any{"fullyConsistent": true},
			"resource":    spiceObject(req.Object),
			"permission":  req.Relation,
			"subject":     spiceSubject(s),
		})
		if err != nil {
			return false, err
		}
		var res struct {
			Permissionship string `json:"permissionship"`
		}
		if err := json.Unmarshal(out, &res); err != nil {
			return false, err
		}
		if res.Permissionship == "PERMISSIONSHIP_HAS_PERMISSION" {
			return true, nil
		}
	}
	return false, nil
}

// postCtx is like post but context-aware and without a *testing.T (used on the
// hot Check path).
func (h *spiceDBHarness) postCtx(ctx context.Context, path string, body any) ([]byte, error) {
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, "POST", h.baseURL+path, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+spiceDBPresharedKey)
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

// spiceObject parses "type:id" into an object reference.
func spiceObject(s string) spiceObjRef {
	typ, id, _ := strings.Cut(s, ":")
	return spiceObjRef{ObjectType: typ, ObjectID: id}
}

// spiceSubject parses "type:id" or a "type:id#relation" userset into a subject.
func spiceSubject(s string) spiceSubRef {
	objPart, rel, hasRel := strings.Cut(s, "#")
	typ, id, _ := strings.Cut(objPart, ":")
	sub := spiceSubRef{Object: spiceObjRef{ObjectType: typ, ObjectID: id}}
	if hasRel {
		sub.OptionalRelation = rel
	}
	return sub
}

func TestSpiceDB(t *testing.T) {
	t.Run("contract", func(t *testing.T) { runContract(t, &spiceDBHarness{}) })
	t.Run("e2e", func(t *testing.T) { runE2E(t, &spiceDBHarness{}) })
}
