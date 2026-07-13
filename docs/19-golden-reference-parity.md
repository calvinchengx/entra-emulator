# Golden-reference parity

The emulator's fidelity is tracked **mechanically** against canonical references,
not by eyeballing docs. Three golden references — one per protocol surface — are
committed under [`e2e/golden/`](https://github.com/calvinchengx/entra-emulator/tree/main/e2e/golden),
and the parity tests in
[`internal/server/golden_parity_test.go`](https://github.com/calvinchengx/entra-emulator/tree/main/internal/server/golden_parity_test.go)
boot the emulator in-process and assert its live responses conform. They run in
the normal `go test ./...` job, so **drift fails CI**.

## The three references

| Reference | Surface | Source of truth |
|---|---|---|
| `oidc-discovery.golden.json` | OIDC/OAuth discovery document | The real Entra discovery doc — `login.microsoftonline.com/common/v2.0/.well-known/openid-configuration` |
| `graph-resources.golden.json` | Microsoft Graph v1.0 resource shapes | The official Graph OpenAPI — [`microsoftgraph/msgraph-metadata`](https://github.com/microsoftgraph/msgraph-metadata) `openapi/v1.0` |
| `scim-schemas.golden.json` | SCIM 2.0 schemas & messages | RFC 7643 (Core Schema) + RFC 7644 (Protocol) |

Each carries a `source` and `captured` date; refresh instructions are in
[`e2e/golden/README.md`](https://github.com/calvinchengx/entra-emulator/tree/main/e2e/golden/README.md).

## What "parity" means

The emulator is a **deliberate localhost subset** of Entra, not a byte-identical
clone — so the tests assert *contract conformance*, and the honest status is a
matrix of `matches` / `subset` / `localhost-variant` / `out-of-scope`, never a
false "100% identical."

| Surface | Assertion | Status |
|---|---|---|
| **OIDC** — required fields | all 14 client-critical fields advertised | ✅ matches |
| **OIDC** — `subject_types` | equals `["pairwise"]` | ✅ matches |
| **OIDC** — `id_token_signing_alg` | includes `RS256` | ✅ matches |
| **OIDC** — `response_types` | ⊆ Entra's set (emulator: `["code"]`) | ◑ subset (code flow only) |
| **OIDC** — `response_modes` | ⊆ `{query, fragment, form_post}` | ✅ matches |
| **OIDC** — `scopes` / `claims` | includes the OIDC/Entra core | ✅ matches |
| **OIDC** — endpoints | same fields, `localhost` URLs | ◑ localhost-variant |
| **OIDC** — `kerberos_endpoint`, `mtls_*`, `cloud_*`, … | not emulated | ○ out-of-scope (reported) |
| **Graph** — user/group/application/servicePrincipal | emitted property set **exactly** equals the golden set (canonical Graph names, no drift) | ✅ no drift |
| **Graph** — full entity coverage | only the emulated property subset | ◑ subset |
| **SCIM** — schema URNs | exact RFC 7643/7644 URNs | ✅ matches |
| **SCIM** — `ListResponse` / `User` / `Group` | required attributes + `meta.resourceType` present | ✅ matches |

Legend: ✅ full parity · ◑ intentional subset/variant · ○ out-of-scope (surfaced,
not silently dropped).

## How the tests read

- **OIDC** (`TestGoldenParityOIDCDiscovery`) — fetches the discovery document and
  checks required fields, then that each protocol enum is a **compatible subset**
  of Entra's (never a value Entra doesn't support). Entra-only fields the emulator
  omits are **logged as documented divergences**, not failed.
- **Graph** (`TestGoldenParityGraph`) — for each resource, asserts the live
  property set **exactly equals** the golden set. Add, rename, or drop a property
  and the test fails until the golden is reconciled — a hard drift guard against
  inventing non-Graph fields.
- **SCIM** (`TestGoldenParitySCIM`) — asserts responses carry the **verbatim** RFC
  schema URNs and the required attributes (`schemas`, `id`, `userName`/`displayName`,
  `meta.resourceType`, `ListResponse` envelope).

## Why not diff the full specs?

The full Graph OpenAPI is tens of megabytes and the discovery doc is
host-specific — vendoring them whole would be noise, not signal. Instead each
reference captures the **contract the emulator commits to** (the fields, enums,
and URNs clients actually depend on), which is small, reviewable, and refreshable
in one commit. When Entra adds a field or you emulate a new property, you update
the golden reference and the diff shows exactly what parity changed.
