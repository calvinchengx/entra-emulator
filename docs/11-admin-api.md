# 07 — Admin REST API & portal

Unauthenticated JSON API under `/admin/api` on the **portal** surface (and compat
origin). Powers the Svelte portal and scripted CI seeding.

## Conventions

- Server generates all IDs (lowercase GUIDs); client-supplied ids ignored.
- Response timestamps are ISO-8601 (converted from stored epoch seconds).
- Pagination on lists: `top` (default 50, max 200), `skip` (default 0), optional `search`
  (case-insensitive substring on name/UPN). Response
  `{ "value": [...], "count": total, "top": n, "skip": n }`.
- Error envelope:
  `{ "error": { "code", "message", "target"?, "details"?: [{field,message}] } }` with
  codes `validation_error` 400, `not_found` 404, `conflict` 409, `invalid_reference` 400,
  `internal_error` 500.

## Tenants (multi-tenant, roadmap #15b)

| Method | Path | → |
|---|---|---|
| GET | `/admin/api/tenants` | `{ value: [Tenant] }`, home first |
| POST | `/admin/api/tenants` | 201 Tenant |
| GET | `/admin/api/tenants/{id}` | 200 Tenant |
| DELETE | `/admin/api/tenants/{id}` | 204 (home → 400) |

Tenant DTO: `{ id, displayName, issuer, initialDomain?, isHome, createdAt }`. Create body
is optional `{ displayName?, initialDomain? }`; missing fields are generated with gofakeit
(`displayName` → a company name, `initialDomain` → `<slug>.onmicrosoft.com` derived from
the name). The server assigns a GUID `id`, sets the GUID-form `issuer`
(`{login}/{id}/v2.0`), and lazily provisions the tenant's RS256 signing key so its
discovery/JWKS/token endpoints work immediately. Delete cascades the tenant's apps, users,
groups, grants, and signing keys; the home tenant cannot be deleted (400). To register an
app in a non-home tenant, pass `tenantId` on `POST /admin/api/apps`.

## Workspace identities (Fabric, roadmap #16)

| Method | Path | → |
|---|---|---|
| GET | `/admin/api/workspace-identities` | `{ value: [WorkspaceIdentity] }` |
| POST | `/admin/api/workspace-identities` | 201 WorkspaceIdentity |
| GET | `/admin/api/workspace-identities/{id}` | 200 |
| PATCH | `/admin/api/workspace-identities/{id}` | 200 (rename / state) |
| DELETE | `/admin/api/workspace-identities/{id}` | 204 (cascades the SP app) |

WorkspaceIdentity DTO: `{ id, appId, tenantId, workspaceId, workspaceName, state, createdAt }`
— `id` is the identity's service-principal object id and `appId` its client id. Create body
is optional `{ workspaceName?, workspaceId?, tenantId? }`; a missing `workspaceName` is
generated with gofakeit and a missing `workspaceId` gets a GUID. Creation provisions a
confidential app registration (the SP) whose display name **follows the workspace** — PATCH
`{workspaceName}` renames both. PATCH `{state}` accepts `Active`, `Provisioning`, `Failed`,
`Deprovisioning`. The identity's tokens are minted internally (no caller-held credential) at
`GET /fabric/workspaceidentities/{id}/token?resource=<uri>` on the STS/compat surface —
default resource is `https://api.fabric.microsoft.com`; only `Active` identities mint
(others → 409). Delete removes the identity by deleting its SP app (cascade).

## Users

| Method | Path | → |
|---|---|---|
| GET | `/admin/api/users` | paged Users |
| POST | `/admin/api/users` | 201 User |
| GET / PATCH / DELETE | `/admin/api/users/{id}` | 200 / 200 / 204 |
| GET | `/admin/api/users/{id}/groups` | paged groups for user |

User DTO: `{ id, userPrincipalName, displayName, givenName?, surname?, mail?,
accountEnabled, hasPassword, createdAt }` — never the hash. Create requires
`userPrincipalName` (unique → 409) + `displayName`; optional `password` (scrypt-hashed).
Patch accepts any subset; `password: null` clears, string sets.

## Groups

| Method | Path | → |
|---|---|---|
| GET / POST | `/admin/api/groups` | paged / 201 |
| GET / PATCH / DELETE | `/admin/api/groups/{id}` | 200 / 200 / 204 |
| GET | `/admin/api/groups/{id}/members` | paged member Users |
| POST | `/admin/api/groups/{id}/members` `{userId}` | 204 (idempotent) |
| DELETE | `/admin/api/groups/{id}/members/{userId}` | 204 |

Group DTO: `{ id, displayName, description?, memberCount, createdAt }`. Unknown `userId`
on add → 400 `invalid_reference`.

## App registrations

| Method | Path | → |
|---|---|---|
| GET / POST | `/admin/api/apps` | paged / 201 |
| GET / PATCH / DELETE | `/admin/api/apps/{id}` | 200 (with sub-collections) / 200 / 204 cascade |

App DTO: `{ id, displayName, isConfidential, appIdUri?, redirectUris[{id,uri,type}],
exposedScopes[{id,value,adminConsentDisplayName,isEnabled}],
appRoles[{id,value,displayName,allowedMemberTypes,isEnabled}],
secrets[{id,displayName,hint,expiresAt,createdAt}], createdAt }` — secrets list **hint
only**. Non-null `appIdUri` must be unique (409) for `.default` resolution. Create accepts
an optional `tenantId` to register the app in a non-home tenant (unknown → 400
`invalid_reference`); it defaults to the home tenant. PATCH covers scalars only;
sub-collections use:

| Method | Path | Notes |
|---|---|---|
| POST / DELETE | `.../redirectUris[/{id}]` | duplicate (app,uri) → 409 |
| POST / DELETE | `.../secrets[/{id}]` | **show-once** below |
| POST / PATCH / DELETE | `.../scopes[/{id}]` | duplicate value → 409 |
| POST / PATCH / DELETE | `.../roles[/{id}]` | duplicate value → 409 |

**Secret show-once:** `POST .../secrets {displayName?, expiresInDays?}` → 201
`{ id, displayName, hint, secretText, expiresAt, createdAt }`. `secretText` (high-entropy
generated plaintext) appears **only here**; only scrypt hash + hint persist.

Token configuration (optional claims / group claims) is managed via app PATCH fields
`optionalClaims`, `groupMembershipClaims`, `groupOverageLimit` (see 04).

## Token forge (roadmap #2 — testing superpower)

`POST /admin/api/tokens` mints an **arbitrary signed JWT** without running any flow —
for exercising resource-API validation paths that are otherwise hard to reach. All
fields optional; defaults give a valid access token for the seeded SPA.

```jsonc
{
  "tokenType": "access",              // "access" (default) | "id"
  "clientId": "<appId>",              // default: seeded SPA
  "userId": "<oid>",                  // set => delegated; omit => app-only
  "scopes": ["User.Read"],            // access delegated → scp
  "roles": ["Tasks.Read.All"],        // access app-only → roles
  "audience": "api://…",              // override aud (wrong-audience tests)
  "expiresInSeconds": 3600,           // negative → already-expired token
  "notBeforeSeconds": 0,
  "nonce": "…",                       // id tokens
  "extraClaims": { "ipaddr": "…" },   // merged last; overrides any base claim
  "signature": "valid"               // "valid" (default) | "invalid" (fails JWKS)
}
```

Response: `{ "token", "tokenType", "kid", "claims" }`. A `valid` token verifies against
JWKS and is accepted by the emulator Graph; `expired`, wrong-`audience`, and
`signature:"invalid"` tokens are rejected 401 — exactly what a resource API's negative
tests need. Open like the rest of the admin API (dev tool).

## Fault injection (roadmap #5 — testing superpower)

Make the token endpoint misbehave on demand, to test client failure handling the real
Entra can't reproduce.

| Method | Path | → |
|---|---|---|
| GET | `/admin/api/faults` | current fault config |
| POST | `/admin/api/faults` | arm faults; returns the stored config |
| DELETE | `/admin/api/faults` | 204 — disarm all faults |

Config: `{ tokenError?, tokenErrorDescription?, tokenLatencyMs?, probability? }`.
`tokenError` (e.g. `temporarily_unavailable` → 503, `invalid_grant` → 400) forces the
`/token` endpoint to return that OAuth error instead of a token; `tokenLatencyMs` delays
every token response; `probability` (0–1, default 1) makes a set error intermittent.
In-memory only — cleared by DELETE or a process restart.

## Flow audit trail (roadmap #8 — "why won't sign-in work")

Every authorize/token exchange is recorded with its concrete accept/reject reason, so a
failing MSAL flow becomes a log line instead of a guess.

| Method | Path | → |
|---|---|---|
| GET | `/admin/api/audit` `?limit=100` | `{ value: [event…], count }`, newest first |
| DELETE | `/admin/api/audit` | 204 — clear the trail |

Event: `{ time, timeISO, flow ("token"\|"authorize"), grantType, clientId, status, ok,
error, reason }`. `error`/`reason` carry the OAuth code + `error_description` (e.g.
`invalid_grant` / "the redirect URI does not match", `invalid_client` / bad secret).
Authorize errors delivered via redirect (`?error=…`) are captured too. In-memory ring
buffer (last 500); injected faults show up here as well.

## Directory import/export (roadmap #7 — shareable fixtures)

Dump the directory as a portable JSON fixture and load it back — versionable, shareable
CI states.

| Method | Path | → |
|---|---|---|
| GET | `/admin/api/export` | JSON snapshot (users, groups + memberships, apps + redirect URIs/secrets/scopes/roles) |
| POST | `/admin/api/import` | replace the directory from a snapshot → `{ imported: { users, groups, apps } }` |

Excludes signing keys (tenant crypto, kept stable) and live grants (transient). Password
and secret **hashes are included**, so a round-trip preserves authentication (the daemon
secret still works after import). Import is replace-semantics inside one transaction,
preserving the tenant row and signing keys.

## Clock control (roadmap #6 — testing superpower)

Freeze or offset the emulator clock so token-expiry and refresh logic are testable
without real sleeps. Every timestamp the emulator stamps (token `iat`/`exp`, refresh and
device-code expiry, sessions) flows through this clock.

| Method | Path | → |
|---|---|---|
| GET | `/admin/api/clock` | `{ offsetSeconds, frozen, now, nowISO }` |
| POST | `/admin/api/clock` | `{ offsetSeconds?, advanceSeconds?, frozen? }` — apply, returns state |
| DELETE | `/admin/api/clock` | 204 — reset to real time |

`advanceSeconds` moves time forward (e.g. past a token's lifetime to make it expire);
`offsetSeconds` sets an absolute offset; `frozen` pins/resumes time (unfreeze is
continuous — no jump). In-memory; DELETE or restart restores real time.

## System

| Method | Path | → |
|---|---|---|
| POST | `/admin/api/seed` `{force?=false}` | `{seeded: bool}` — no-op unless empty; `force` = idempotent skip-existing, never destructive |
| POST | `/admin/api/reset` `{reseed?=true, resetKeys?=false}` | `{reset:true, reseeded}` — empties data tables, preserves tenant + active signing key unless `resetKeys` |
| GET | `/admin/api/health` | same shape as `/health` |
| GET | `/admin/api/certificate` | cert metadata (fingerprint, SANs, paths) |
| GET | `/admin/api/certificate/pem` | the cert PEM (for trust scripts) |

`/health` (also at the root of the portal/compat surface):
`{ "status":"ok", "version", "uptimeSeconds", "tls", "tenantId",
"origins": { "login", "portal", "graph" } }`.

## Portal (Svelte SPA)

Built with Vite from `portal/` → `portal/dist`, embedded via `go:embed`, served as the
SPA fallback on the portal/compat surfaces (any non-API GET → `index.html`; API prefixes
are never shadowed — unknown API paths return JSON 404, never HTML).

Feature set: dashboard (stat tiles, issuer/endpoint list
with copy, health/version chip, cert trust download), users/groups/apps tables (search +
pagination + drawers for create/edit), group membership management, app sub-resources
(redirect URIs, scopes, roles, secrets with the copy-once dialog), MSAL config snippet
generator per app (browser/node tabs, redirect-URI selector, derived from the advertised
origins), and seed/reset actions. Visual identity: Fluent-mimic (Azure-portal
familiarity) with a persistent amber "LOCAL EMULATOR" badge as the not-production
signal.

## Custom authentication extensions (roadmap #10)

Emulate the Entra `onTokenIssuanceStart` event: a per-app webhook called during
delegated-token minting whose returned claims are merged into the token.

| Method | Path | → |
|---|---|---|
| GET | `/admin/api/custom-extensions` | `{value: {<appId>: config}}` — all registrations |
| PUT | `/admin/api/apps/{id}/custom-extension` | register/update `{endpoint, claims?, timeoutMs?}` |
| DELETE | `/admin/api/apps/{id}/custom-extension` | 204 — remove |

During minting the emulator POSTs the Microsoft `onTokenIssuanceStartCalloutData`
shape (type, source, tenantId, authenticationContext with the client SP + user) to
`endpoint`, carrying an emulator-minted system bearer, and merges the
`provideClaimsForToken` claims the webhook returns. `claims` optionally allowlists
which returned names are merged. Semantics match Entra: **protocol claims can never be
overridden**, and a slow/failing webhook is **timeout-and-continue** (default ~2 s,
overridable via `timeoutMs`) — the token is still issued, just unenriched. In-memory
config (dev tool).
