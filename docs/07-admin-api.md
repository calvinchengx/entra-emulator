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
only**. Non-null `appIdUri` must be unique (409) for `.default` resolution. PATCH covers
scalars only; sub-collections use:

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
