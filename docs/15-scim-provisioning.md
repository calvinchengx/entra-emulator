# SCIM provisioning

SCIM 2.0 (RFC 7643/7644) is how identity providers **provision users and groups
across domains**. Entra plays SCIM two ways, and the emulator emulates both — in
two phases:

- **Phase 1 — SCIM service provider (server).** The emulator exposes
  `/scim/v2/Users` and `/Groups` over its directory, so any SCIM client can CRUD
  it. Also the foundation the client phase reuses (the SCIM↔store mapping).
- **Phase 2 — SCIM provisioning client.** The emulator *pushes* its directory
  out to a SCIM endpoint you configure, replicating Entra's real outbound
  provisioning — so you can test a **SCIM receiver you're building** against
  "what Entra actually sends," with no cloud tenant.

## Shared foundation: the SCIM ↔ store mapping

Both phases translate between the store's `User`/`Group` and SCIM core resources
(`urn:ietf:params:scim:schemas:core:2.0:{User,Group}`, plus the
`enterprise:2.0:User` extension):

| SCIM attribute | store field |
|---|---|
| `id` | `User.ID` / `Group.ID` (lowercase GUID) |
| `userName` | `User.UserPrincipalName` |
| `name.givenName` / `name.familyName` | `GivenName` / `Surname` |
| `displayName` | `DisplayName` |
| `emails[primary].value` | `Mail` |
| `active` | `AccountEnabled` |
| `password` (write-only) | scrypt-hashed into `PasswordHash` |
| `members[].value` | group membership (`group_members`) |
| `meta.{created,location,resourceType}` | derived |

Correlation is by **`userName`** (Entra's default matching attribute), so no
schema change is needed for phase 1. `externalId` persistence is a later add
(one nullable column) once the client phase needs it.

## Phase 1 — service provider

A new `internal/scim` surface, registered like `/graph` (Host-routed `scim.`
subdomain + `/scim/v2` on the compat origin).

**Endpoints (RFC 7644):**

| Method + path | Purpose |
|---|---|
| `GET /scim/v2/ServiceProviderConfig` | advertised capabilities (patch, filter, bulk=false) |
| `GET /scim/v2/ResourceTypes`, `/Schemas` | discovery |
| `GET /scim/v2/Users?filter=userName eq "x"&startIndex=1&count=100` | list (filter + pagination) |
| `POST /scim/v2/Users` | create → 201 |
| `GET/PUT/PATCH/DELETE /scim/v2/Users/{id}` | read / replace / PatchOp / delete |
| `…/Groups` (same shape) | groups + `members` PatchOp |

- **Auth:** bearer **secret token** (Entra's SCIM model — a static token, not a
  JWT). Configurable; a seeded dev default. `401` on mismatch.
- **PatchOp:** the common operations Entra emits — `replace active` (soft
  deprovision), attribute replaces, and `add`/`remove` on `members`.
- **Wire format:** `ListResponse` / `Error` message schemas, `application/scim+json`.

Backed entirely by the existing store repos (`CreateUser`, `ListUsers`,
`AddGroupMember`, …), so there's one directory whether you reach it via Graph,
the admin API, or SCIM.

## Phase 2 — provisioning client (emulate Entra outbound)

**Built** (`internal/scim` provisioner + admin API + portal view), including
member-correlated group provisioning and true incremental sync (an `updated_at`
watermark; only users changed since the last cycle are pushed).

A controllable provisioning engine (admin-triggered, not a real 40-min timer)
that pushes the directory to a configured target using Entra's request
sequence:

- **Configure:** `POST /admin/api/scim/target { endpoint, token, scope }`.
- **Sync:** `POST /admin/api/scim/sync { mode: "initial" | "incremental" }`.
  - *Initial:* per in-scope user/group → `GET /Users?filter=userName eq "…"`
    (existence probe), then `POST` or `PATCH` — the exact shape Entra uses.
  - *Incremental:* replay changes since a watermark.
  - *Deprovision:* disabled/removed → `PATCH {active:false}`, then `DELETE`.
- **Provisioning log:** `GET /admin/api/scim/log` — every SCIM request/response,
  mirroring the [audit trail](07-admin-api.md).
- **Fidelity:** `enterprise:2.0:User` extension, `externalId` correlation,
  soft-delete semantics, quarantine/retry on target errors.

**Portal:** a "Provisioning" view — configure the target, run a cycle, watch the
SCIM request log stream (reuses the Audit view pattern).

## Testing

- **Phase 1:** integration tests drive the SCIM endpoints against the seeded
  directory (create → list-by-filter → patch active → delete), asserting SCIM
  wire shapes and bearer auth.
- **Phase 2:** an e2e suite stands up a **mock SCIM target** (a tiny Go server),
  points the emulator at it, triggers a sync, and asserts the emulator emitted
  Entra-shaped requests (correlation filter, PatchOp, `active:false` on disable)
  — CI-verifiable like the [SDK matrix](11-e2e-sdk-matrix.md).

## Non-goals

The full SCIM filter grammar (only the `eq` correlation filters Entra uses),
bulk operations, ETags/versioning, and `/Me`. Provisioning runs on demand (via
the admin API or portal), not a background scheduler — deterministic for tests,
consistent with [clock control](02-configuration.md).
