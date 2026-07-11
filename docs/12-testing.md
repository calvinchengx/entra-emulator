# 09 — Testing strategy

The emulator's value is protocol fidelity, so tests assert HTTP contracts and token
shapes, not internals.

## Layers

### 1. Unit tests (`go test ./internal/...`)

Pure logic, no listener:

- **tokens** — JWS sign/verify round-trip; claim assembly per token type (ID vs access,
  delegated vs app-only); PKCE `S256`/`plain` verification; lifetime arithmetic;
  kid stability across store reloads.
- **store** — seed determinism (same GUIDs every time); scrypt verify; SHA-256 token
  hashing; one-time consumption of auth codes; refresh rotation invalidating the parent;
  migration idempotence; persistence round-trip (open → mutate → reopen).
- **config** — precedence (env > file > defaults); validation failures name the key.
- **httpx** — tenant alias resolution (`common`/`organizations`/`consumers` → the fixed
  tenant); host → surface routing; compat origin serving all surfaces.

### 2. Integration tests (`go test ./internal/server`)

Spin up the full handler stack with `httptest.Server` (TLS), ephemeral data dir, fixed
seed. One test per contract:

- Discovery document: exact field set, issuer matches config.
- JWKS: RSA key with `kid`, tokens verify against it.
- **Auth Code + PKCE end-to-end**: GET /authorize → sign-in page → POST account pick →
  302 with `code` + `state` → POST /token → verify ID + access token claims (`iss`,
  `aud`, `tid`, `oid`, `scp`, `nonce`, `ver`) → call /userinfo → /logout redirect.
- Confidential client: secret required and validated; wrong secret → `invalid_client`.
- Client Credentials: `roles` claim from app roles, no `scp`, `idtyp: app`.
- Refresh: rotation (new RT returned, old RT rejected on reuse).
- Device Code: devicecode → `authorization_pending` → approve via portal route →
  token issued; `expired_token` after expiry; `slow_down` semantics if implemented.
- Negative cases per grant: bad redirect_uri, PKCE mismatch, expired/consumed code,
  unknown client, disabled user — asserting the exact OAuth error body
  (`error`, `error_description` with AADSTS-style prefix, `error_codes`, `timestamp`).
- Graph: each route with a valid token; 401 shapes for missing/expired/wrong-audience
  tokens; group members; pagination.
- Admin API: CRUD each resource, secret show-once, seed/reset, health.

### 3. Conformance sweep

A single test walks every issued token type and asserts: header `{typ, alg, kid}`,
verifies against `/discovery/v2.0/keys`, `iss` equals discovery `issuer`, required
claims present with correct types.

### 4. Manual / smoke (documented, not automated)

`curl --insecure` script exercising discovery, client_credentials, device code, Graph
`/me` — used as the post-build sanity check and kept in the README.

## Determinism

Fixed tenant GUID, fixed seed GUIDs/secrets, ephemeral `t.TempDir()` data dirs, no
wall-clock assertions tighter than ±lifetime. No network access needed by any test.
