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
| GET | `/v1.0/users` | paged user collection |
| GET | `/v1.0/users/{id}` | by GUID **or UPN** |
| GET | `/v1.0/groups` | paged group collection |
| GET | `/v1.0/groups/{id}` | single group |
| GET | `/v1.0/groups/{id}/members` | member users |
| GET, POST | `/oidc/userinfo` | OIDC UserInfo claims |

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
