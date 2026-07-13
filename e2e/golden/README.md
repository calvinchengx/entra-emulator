# Golden references

Canonical, authoritative snapshots of the **real** Microsoft Entra / standards
contracts the emulator emulates. These are the *golden reference* the emulator is
diffed against, so parity is tracked mechanically rather than by eyeballing docs.

Each file is consumed by the parity tests in
[`internal/server/golden_parity_test.go`](../../internal/server/golden_parity_test.go),
which boot the emulator in-process and assert its live responses conform. The
tests run in the normal `go test ./...` job, so drift fails CI.

| File | Surface | Provenance |
|---|---|---|
| `oidc-discovery.golden.json` | OIDC/OAuth discovery document | Captured from `https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration` |
| `graph-resources.golden.json` | Microsoft Graph v1.0 resource shapes | Property names verified against [`microsoftgraph/msgraph-metadata`](https://github.com/microsoftgraph/msgraph-metadata) `openapi/v1.0` (the official Graph OpenAPI) |
| `scim-schemas.golden.json` | SCIM 2.0 schemas & protocol messages | RFC 7643 (Core Schema) + RFC 7644 (Protocol) |

## What "parity" means here

The emulator is a **deliberate localhost subset** of Entra, not a byte-identical
clone. So the tests assert *contract conformance*, not literal equality:

- **required fields present** — every field a client relies on is advertised;
- **protocol values compatible** — enum values are a valid **subset** of Entra's
  (e.g. `S256` PKCE, `RS256` signing, `pairwise` subjects) and never invent
  values Entra doesn't support;
- **no schema drift** — Graph responses use only canonical Graph property names;
  SCIM responses use the exact RFC schema URNs;
- **documented divergences** — fields Entra advertises that the emulator omits are
  listed explicitly (e.g. `kerberos_endpoint`) and reported, not silently ignored.

The parity matrix lives in
[docs/19-golden-reference-parity.md](../../docs/19-golden-reference-parity.md).

## Refreshing a reference

1. **OIDC:** re-fetch the discovery URL above and reconcile `required_fields` /
   `protocol_values` / `entra_only_fields_out_of_scope`. Bump `captured`.
2. **Graph:** cross-check property names against the current `msgraph-metadata`
   `openapi/v1.0/openapi.yaml`. Bump `captured`.
3. **SCIM:** the RFCs are stable; change only if a new resource/attribute is
   emulated.

Keep the change in its own commit so a reference bump is easy to review.
