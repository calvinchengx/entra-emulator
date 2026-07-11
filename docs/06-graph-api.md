# 06 — Minimal Microsoft Graph

Read-only, backed by the same store. Served on the **graph** surface as `/v1.0/...` and
`/oidc/userinfo`; the compat origin also serves them prefixed: `/graph/v1.0/...`,
`/graph/oidc/userinfo`.

## Authorization model

Every route requires `Authorization: Bearer <access_token>` validating per 04: signature
via JWKS, `iss` = emulator issuer, `exp`/`nbf` ±60 s, `aud` = `GRAPH_RESOURCE_ID`,
`ver:"2.0"` accepted. **No fine-grained scope/role enforcement** (documented divergence —
possession of a valid Graph-audience token suffices). `/me` and userinfo additionally
require a **delegated** token (`oid` present); app-only → 403.

## Routes

| Method | Path | Returns |
|---|---|---|
| GET | `/v1.0/me` | user resolved from token `oid` (404 if gone) |
| GET | `/v1.0/me/memberOf` | signed-in user's groups (directory objects) |
| GET | `/v1.0/users` | paged user collection |
| GET | `/v1.0/users/{id}` | by GUID **or UPN** |
| GET | `/v1.0/users/{id}/memberOf` | a user's groups (directory objects) |
| GET | `/v1.0/groups` | paged group collection |
| GET | `/v1.0/groups/{id}` | single group |
| GET | `/v1.0/groups/{id}/members` | member users |
| GET, POST | `/oidc/userinfo` | OIDC UserInfo claims |

`memberOf` items carry an `@odata.type` (`#microsoft.graph.group`).

### Writes (roadmap #18)

| Method | Path | Notes |
|---|---|---|
| POST | `/v1.0/users` | 201; requires `displayName` + `userPrincipalName`; optional `passwordProfile.password` |
| PATCH / DELETE | `/v1.0/users/{id}` | 204 / 204 |
| POST | `/v1.0/groups` | 201; requires `displayName` |
| PATCH / DELETE | `/v1.0/groups/{id}` | 204 / 204 |
| POST | `/v1.0/groups/{id}/members/$ref` | 204; body `{"@odata.id": ".../directoryObjects/{userId}"}` |
| DELETE | `/v1.0/groups/{id}/members/{userId}/$ref` | 204 |
| POST | `/v1.0/applications` | 201; object `id` == `appId` (documented conflation) |
| PATCH / DELETE | `/v1.0/applications/{id}` | 204 / 204 |

Backed by the same store as the admin API. Store errors map to Graph shapes: not-found →
404 `Request_ResourceNotFound`, unique conflict (e.g. duplicate UPN) → 400
`Request_BadRequest`. No fine-grained permission enforcement (documented divergence).

## Shapes

User: `{ "@odata.context", id, displayName, userPrincipalName, mail, givenName, surname,
accountEnabled }`. Group: `{ "@odata.context", id, displayName, description,
mailEnabled: false, securityEnabled: true }`. Collections:
`{ "@odata.context", "value": [...], "@odata.nextLink"? }`.

- `@odata.context` built from the **graph origin**; single entities use the `$entity`
  suffix; collection items omit per-item context.
- Paging: `$top` (default 100, max 999) + `$skiptoken` (integer offset). `nextLink` only
  when more rows remain and **preserves the caller's query params**. Collections ordered
  by `id`.

### OData query options (basic)

- `$select=a,b` — projects to the named fields; `id` is always retained. Applies to
  collections and single entities.
- `$filter` — a **single clause**: `field eq 'v'` / `field ne 'v'`, `field eq true|false`,
  or `startswith(field,'v')` / `endswith(field,'v')`. Logical `and`/`or` is out of scope;
  a malformed filter returns **400 `BadRequest`**.
- `$count=true` — adds `@odata.count` (total **after** filtering).
- Filtering and projection run in-memory over the shaped entities (fine at emulator sizes);
  `$top`/`$skiptoken` paging is applied after filtering.

## Graph errors

`{ "error": { "code": "...", "message": "..." } }` — codes:
`InvalidAuthenticationToken` (401, with `WWW-Authenticate: Bearer error="invalid_token"`),
`Authorization_RequestDenied` (403, app-only on /me), `Request_ResourceNotFound` (404).
Never HTML.

## UserInfo

Success (delegated Graph-audience token; `Cache-Control: no-store`):

```jsonc
{ "sub": "<same pairwise sub as the token>", "oid": "...", "tid": "...",
  "name": "...", "preferred_username": "...",
  "given_name": "...", "family_name": "...", "email": "..." }   // nullables omitted
```

Errors (RFC 6750): missing/invalid/expired/wrong-aud → 401 +
`WWW-Authenticate: Bearer error="invalid_token"` and matching JSON body; app-only token →
403 `insufficient_scope`; user missing/disabled → 401.
