# PDP compatibility suite

Proves the [`externalized-authz`](../) sample's **PDP port** behaves identically
against real authorization engines. There is exactly one seam to test — the
`authz.PDP` interface — so the whole suite is one decision matrix run against
many backends.

## What it proves

A single invariant:

> Given the same relationship facts and the same set of checks, every PDP
> adapter returns the same allow/deny matrix — and the full HTTP flow
> (emulator token → JWKS validation → PDP → 200/403) behaves identically
> regardless of which engine is wired in.

Two shared layers, defined once and reused by every engine:

| Layer | File | Proves |
|---|---|---|
| **Contract** | [`harness_test.go`](harness_test.go) | the adapter reproduces the canonical decision matrix |
| **End-to-end** | [`e2e_test.go`](e2e_test.go) | the real `ResourceServer` + a genuine emulator token + the engine-backed PDP produce the right HTTP status (catches `oid`→subject / `groups`→userset mapping bugs) |

The canonical facts and checks live in [`harness_test.go`](harness_test.go) —
that table *is* the compatibility proof.

## Engines

| Engine | Model | Runs as | Harness |
|---|---|---|---|
| **OpenFGA** | ReBAC (Zanzibar) | container (testcontainers) | [`openfga_test.go`](openfga_test.go) |
| **SpiceDB** (Authzed) | ReBAC (Zanzibar) | container (testcontainers) | [`spicedb_test.go`](spicedb_test.go) |
| **Ory Keto** | ReBAC (Zanzibar) | container (testcontainers) | [`keto_test.go`](keto_test.go) |
| **Permify** | ReBAC (Zanzibar) | container (testcontainers) | [`permify_test.go`](permify_test.go) |
| **Casbin** | RBAC/ABAC | in-process (library) | [`casbin_test.go`](casbin_test.go) |
| **OPA** | Rego policy | in-process (library) | [`opa_test.go`](opa_test.go) |
| **Cedar** (cedar-go) | Cedar policy | in-process (library) | [`cedar_test.go`](cedar_test.go) |

The operational shapes are deliberate. The four Zanzibar engines exercise the
container + bootstrap path (each translates the canonical facts into its own
relationship writes); the three policy/library engines exercise the zero-Docker
in-process path. Container engines are reached over their **HTTP APIs with
`net/http`** — only the OpenFGA leg uses a Go SDK; SpiceDB, Keto, and Permify
are hand-rolled to keep this module's `go.mod` lean and dodge SDK dependency
conflicts (the `authzed-go` tree, for one, pulls conflicting `buf.build` and
`cloud.google.com` deps). OPA (Rego) and Cedar (cedar-go) embed directly, like
Casbin.

## Honest caveat: ReBAC vs. RBAC/policy

The canonical facts are **ReBAC-shaped** (subject / relation / object). For the
Zanzibar engines — **OpenFGA, SpiceDB, Keto, Permify** — the translation is
faithful, so this genuinely proves cross-engine equivalence. For the policy
engines — **Casbin, OPA, Cedar** — we hand-author an equivalent model (a Casbin
policy, a Rego module, or generated Cedar `permit` policies) that yields the
same decisions. Those legs prove *"our adapter + our authored model reproduce
the contract"*, **not** that the engines are semantically identical. The green
checkmark is scoped accordingly.

Group membership is **not** stored in any PDP: the sample supplies the caller's
groups at request time (from the token's `groups` claim), and each adapter
resolves them as `group:<id>#member` usersets (ReBAC engines) or as the
principal's `parents` / group subjects (policy engines) — mirroring the
reference `InMemoryPDP`.

## Running it

Behind the `pdp_integration` build tag, so the default build stays
dependency-free and this never touches the emulator's `go.mod` (it's a separate
module with a `replace` back to the parent, like `e2e/go`).

```sh
cd samples/externalized-authz/compat

# Casbin only — no Docker:
CGO_ENABLED=0 go test -tags=pdp_integration -run TestCasbin ./...

# OpenFGA — needs Docker (testcontainers pulls the image):
CGO_ENABLED=0 go test -tags=pdp_integration -run TestOpenFGA ./...

# everything:
CGO_ENABLED=0 go test -tags=pdp_integration ./...
```

Container legs `t.Skip` automatically when Docker is unavailable, so the
Casbin leg still runs on a bare machine.

## Adding an engine

Implement `PDPHarness` (`Start` / `Seed` / `PDP` / `Close`) and add one
`TestXxx` that calls `runContract` and `runE2E`. The fixture and assertions are
reused — no new matrix. Add the engine to the CI matrix in
`.github/workflows/ci.yml` (`pdp-compat` job).

**Container engines must pin `tag@sha256:<digest>`** (see `openFGAImage`), not a
bare tag, so runs stay idempotent even if the tag is re-pushed upstream. Resolve
the digest with `docker buildx imagetools inspect <image>:<tag> --format
'{{.Manifest.Digest}}'`; Dependabot's Docker updater bumps tag + digest together.
