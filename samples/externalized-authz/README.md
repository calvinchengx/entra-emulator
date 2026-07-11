# Externalized authorization sample

**Pattern:** Entra (here, the emulator) **authenticates**; a dedicated Policy
Decision Point (PDP) such as [OpenFGA](https://openfga.dev) **authorizes**. The
resource API trusts the emulator only as a standards-compliant token issuer — it
uses **no emulator-specific features**.

```
client ──token──▶ resource API ──"can user:X read doc:Y?"──▶ PDP (OpenFGA)
                     │  1. validate JWT via JWKS (authN)
                     │  2. ask PDP for a decision      (authZ)
```

## Why separate them

- **Authentication** answers *who is calling and is the token genuine?* — solved
  by validating the RS256 signature against the tenant JWKS and checking
  `iss` / `aud` / `exp`. See [`validator.go`](validator.go).
- **Authorization** answers *may this principal do this action on this object?* —
  a fine-grained, data-dependent question that does **not** belong in the IdP.
  A relationship-based PDP (OpenFGA) models it as tuples like
  `user:alice reader doc:readme`. See [`pdp.go`](pdp.go).

The token carries identity (`oid`) and coarse context (`groups`); the PDP owns
the policy. Neither side needs to know the other's internals.

## Files

| File | Role |
|---|---|
| [`authz/validator.go`](authz/validator.go) | JWKS-backed RS256 token validator (authN) |
| [`authz/pdp.go`](authz/pdp.go) | `PDP` port + in-memory OpenFGA-style tuple checker (authZ) |
| [`authz/server.go`](authz/server.go) | Protected API: authenticate, then PDP-check per route |
| [`main.go`](main.go) | Standalone runner (env-configured) |
| [`main_test.go`](main_test.go) | End-to-end test against the in-process emulator |
| [`compat/`](compat/) | PDP-compatibility suite: the same decisions against **real** OpenFGA + Casbin |

The reusable pieces live in the importable `authz` package; `main.go` is only the
standalone runner. The [`compat/`](compat/) module (separate `go.mod`, behind the
`pdp_integration` build tag) proves the `PDP` port behaves identically against real
engines and is CI-verified by the `pdp-compat` job.

## Run it

```sh
# 1. start the emulator (see repo root), then:
EMULATOR_JWKS_URL=http://localhost:8080/<tenant>/discovery/v2.0/keys \
EMULATOR_ISSUER=http://localhost:8080/<tenant>/v2.0 \
RESOURCE_AUDIENCE=api://docs-api \
SEED_READER_OID=<alice-oid> \
go run ./samples/externalized-authz
```

Then call it with an access token whose `aud` is `api://docs-api`:

```sh
curl -H "Authorization: Bearer $TOKEN" http://localhost:9090/documents/readme
```

## Swapping in real OpenFGA

`InMemoryPDP` implements the `PDP` port. Replace it with an OpenFGA client —
the resource server does not change:

```go
// import openfga "github.com/openfga/go-sdk/client"
type openFGAPDP struct{ c *openfga.OpenFgaClient }

func (p *openFGAPDP) Check(ctx context.Context, req CheckRequest) (bool, error) {
    res, err := p.c.Check(ctx).Body(openfga.ClientCheckRequest{
        User: req.Subject, Relation: req.Relation, Object: req.Object,
    }).Execute()
    if err != nil { return false, err }
    return res.GetAllowed(), nil
}
```

Equivalent OpenFGA authorization model (DSL):

```
model
  schema 1.1
type user
type group
  relations
    define member: [user]
type doc
  relations
    define reader: [user, group#member]
    define writer: [user, group#member]
```
