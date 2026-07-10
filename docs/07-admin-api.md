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
