# Data model & seed

SQLite via `modernc.org/sqlite` (pure Go). One connection pool per process; pragmas
`journal_mode=WAL`, `foreign_keys=ON`, `busy_timeout=5000`. Forward-only migrations
tracked in `schema_migrations`, idempotent at boot. Conventions: all identifiers are
lowercase GUID strings; timestamps are **integer Unix epoch seconds** in `*_at` columns;
booleans are `INTEGER 0/1`.

## Schema



| Table | Columns (PK bold) | Notes |
|---|---|---|
| `schema_migrations` | **version**, applied_at | |
| `tenants` | **id**, display_name, issuer, created_at | Single row, the fixed tenant. |
| `users` | **id**, tenant_id FK, user_principal_name UNIQUE, display_name, given_name?, surname?, mail?, password_hash?, account_enabled=1, created_at | `id` == `oid`. Index on mail. |
| `groups` | **id**, tenant_id FK, display_name, description?, created_at | |
| `group_members` | **(group_id, user_id)** both FK CASCADE | Index on user_id. |
| `app_registrations` | **app_id**, tenant_id FK, display_name, is_confidential=0, app_id_uri?, optional_claims? (JSON), group_membership_claims='None', group_overage_limit?, created_at | `app_id_uri` unique when non-null (enforced by admin API, 409 on dup). |
| `app_redirect_uris` | **id** AUTOINC, app_id FK CASCADE, uri, type='web' | UNIQUE(app_id, uri); type ∈ web\|spa\|native. |
| `app_secrets` | **id**, app_id FK CASCADE, display_name?, secret_hash, hint?, expires_at?, created_at | Plaintext returned once at creation (admin API). |
| `app_scopes` | **id**, app_id FK CASCADE, value, admin_consent_display_name?, is_enabled=1 | UNIQUE(app_id, value). Delegated `scp` values. |
| `app_roles` | **id**, app_id FK CASCADE, value, display_name?, allowed_member_types='Application' (CSV), is_enabled=1 | UNIQUE(app_id, value). App-only `roles`. |
| `signing_keys` | **kid**, tenant_id FK, alg='RS256', public_jwk (JSON), private_pkcs8 (PEM, plaintext — documented dev-tool tradeoff), is_active=1, created_at, not_after? | Index (tenant_id, is_active). One active per tenant. |
| `authorization_codes` | **code**, app_id FK, user_id FK, redirect_uri, scopes, resource?, code_challenge?, code_challenge_method?, nonce?, expires_at, consumed=0, created_at | Single-use via atomic consume. Index on expires_at. |
| `refresh_tokens` | **token** (= SHA-256 hex of plaintext), app_id FK, user_id FK, scopes, resource?, expires_at, rotated_from?, revoked=0, created_at | Hashed at rest. Index (app_id, user_id). |
| `sessions` | **id**, user_id FK, created_at, expires_at | SSO cookie backing. 8h TTL. |
| `device_codes` | **device_code** (= SHA-256 hex), user_code UNIQUE, app_id FK, user_id?, scopes, status='pending', interval=5, expires_at, created_at | status ∈ pending\|approved\|denied\|expired. |

## Repository layer (Go)

One struct per entity in `internal/store`, methods taking `*sql.Tx`-or-DB via a small
`Querier` interface. Critical atomic operations (contracts other packages rely on):

- `AuthCodes.Consume(code)` — `UPDATE ... SET consumed=1 WHERE code=? AND consumed=0`;
  caller requires exactly 1 row affected.
- `RefreshTokens.GetByHash(hash)` — returns rows **regardless** of revoked/expired state
  (reuse detection depends on seeing revoked rows).
- `RefreshTokens` rotation — inside one transaction: CAS `revoked=1 WHERE token=? AND
  revoked=0` (require 1 row), then insert successor with `rotated_from`.
- `DeviceCodes.ConsumeApproved(hash, appID, now)` — `DELETE ... WHERE device_code=? AND
  app_id=? AND status='approved' AND expires_at>? RETURNING *`; token mint only on a
  returned row (closes the TOCTOU double-mint window).
- `Reset(reseed, resetKeys)` — one transaction: delete all data rows, **preserve** the
  tenants row and (unless resetKeys) the active signing key; reseed skip-existing.
- `Seed(force)` — idempotent `INSERT OR IGNORE` of the fixed seed; no-op when a tenant
  exists and !force.

## Hashing

- **Passwords & client secrets:** scrypt (N=16384, r=8, p=1, 32-byte key, 16-byte salt),
  encoded `scrypt$<salt-b64>$<hash-b64>`, constant-time compare.
- **Refresh tokens, device codes:** SHA-256 hex of the opaque plaintext is the stored PK.
- **Auth codes:** stored as issued (opaque ≥256-bit base64url, 5-min TTL, single-use).

## Deterministic seed (fixed GUIDs)

| Entity | GUID | Values |
|---|---|---|
| Tenant | `6f89cf12-978b-4d23-ac18-9ef0c127cf87` | `Entra Emulator` (display), issuer derived |
| User Alice | `df8ec5dd-1599-45ef-908b-4ae020cd1dbe` | `alice@entraemulator.dev`, "Alice Example", mail set, password `Password1!` (scrypt) |
| User Bob | `0d4ba1f9-cab1-4200-b516-d4cb8b340930` | `bob@entraemulator.dev`, password `Password1!` |
| Group | `54a9d08c-889d-489e-b534-336fe19dbfce` | `Engineering`; members Alice + Bob |
| App: Sample SPA | `189c7070-78a3-4c13-aa18-20a2ca5755ca` | public (`is_confidential=0`), redirect `https://localhost:3000`, `app_id_uri=api://<the GUID at left>`, scope `access_as_user` |
| App: Sample Daemon | `00d88624-f0d7-46f6-a641-6232c2608928` | confidential, secret `daemon-app-secret` (hashed, hint stored), `app_id_uri=api://<the GUID at left>`, app role `Tasks.Read.All` (Application) |

The signing key is **generated**, not seeded (real RSA material, persisted for a stable
`kid`); tests may insert a fixed key for byte-reproducible output.

### Seed GUIDs changed in v0.4.0 (breaking)

These IDs were previously patterned placeholders (`aaaaaaaa-…`, `cccccccc-…`). They are
still **fixed and deterministic** — only the values changed. Real Entra never issues
GUIDs with repeating nibbles, and a uniform GUID is a weak test oracle: it survives
segment transposition and most mis-slicing, so a parsing bug can pass unnoticed.

| Entity | Old | New |
|---|---|---|
| Tenant | `11111111-1111-1111-1111-111111111111` | `6f89cf12-978b-4d23-ac18-9ef0c127cf87` |
| User Alice | `aaaaaaaa-0000-0000-0000-000000000001` | `df8ec5dd-1599-45ef-908b-4ae020cd1dbe` |
| User Bob | `aaaaaaaa-0000-0000-0000-000000000002` | `0d4ba1f9-cab1-4200-b516-d4cb8b340930` |
| Group Engineering | `bbbbbbbb-0000-0000-0000-000000000001` | `54a9d08c-889d-489e-b534-336fe19dbfce` |
| App: Sample SPA | `cccccccc-0000-0000-0000-000000000001` | `189c7070-78a3-4c13-aa18-20a2ca5755ca` |
| App: Sample Daemon | `cccccccc-0000-0000-0000-000000000002` | `00d88624-f0d7-46f6-a641-6232c2608928` |

The daemon app doubles as the default managed-identity client ID, so
`ENTRA_MANAGED_IDENTITY_CLIENT_ID` moves with it. `arm-emulator` v0.2.0 adopts the same
tenant and daemon IDs — the two must agree for its quickstart token exchange.

Prefer the exported constants (`store.SeedUserAliceID`, `config.DefaultTenantID`) over
literals; Go code that used them needed no change across this rename.
