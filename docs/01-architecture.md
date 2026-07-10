# 01 — Architecture

> Entra Emulator is a local, MSAL-compatible emulator of Microsoft Entra ID in Go. It
> exposes the OIDC/OAuth 2.0 v2.0 endpoint surface MSAL talks to, a minimal read-only
> Microsoft Graph, and an unauthenticated admin REST API — one process, one HTTPS
> listener. Its emulated surface is compatible with
> [entra-local](https://github.com/cmaneu/entra-local) (TypeScript prior art).

## Goals

1. **MSAL compatibility first.** An MSAL app pointed at the emulator's authority works
   with configuration changes only.
2. **Standards-correct tokens.** Real RS256-signed JWTs, verifiable against a working
   JWKS endpoint, with Entra v2.0 claim shapes (`tid`, `oid`, `scp`/`roles`, `ver`).
3. **Zero-friction setup.** `go build` produces a single static binary; first run
   self-generates a TLS cert and a deterministic seed directory.
4. **Inspectable & resettable.** Admin API to list/create/reset everything; fixed seed
   GUIDs and secrets for reproducible CI.

**Non-goals** mirror entra-local: no multi-tenant, implicit flow, ROPC, OBO, SAML,
MFA/Conditional Access/consent, certificate client auth, or Graph writes. This is a
development tool — intentionally insecure (open admin API, seeded public secrets,
self-signed TLS).

## Implementation choices vs entra-local

| Concern | entra-local (TypeScript) | entra-emulator (Go) | Why |
|---|---|---|---|
| Runtime | Node 22+, pnpm, Fastify | Single static Go binary, `net/http` | Go's stdlib covers the whole surface; no SEA packaging step needed |
| Persistence | SQLite (`node:sqlite`) | SQLite (`modernc.org/sqlite`, pure Go — no cgo) | Same file format and semantics as entra-local; the pure-Go driver keeps cross-compilation and the static binary |
| JWT/crypto | `jose` | `crypto/rsa` + hand-rolled compact JWS (RS256 only) | One algorithm, ~100 lines, no dependency |
| Admin portal | React SPA (Vite) | **Svelte SPA** (Vite build), compiled assets embedded in the binary via `go:embed` | Smaller runtime bundle than React; Node toolchain needed only when working on the portal — the shipped binary stays self-contained |
| Validation | zod | plain Go validation funcs | — |
| Password hashing | scrypt | scrypt (`golang.org/x/crypto/scrypt`) | Parity; only non-stdlib dependency |

Everything protocol-visible — paths, parameters, claim shapes, error bodies, seed
GUIDs/secrets, lifetimes — matches entra-local so MSAL clients and resource APIs cannot
tell the difference. Data files are **not** interchangeable between the two projects.

## Process shape

```
  Your app (MSAL)                      entra-emulator (one process, one :8443 TLS listener)
 ┌───────────────┐                     ┌──────────────────────────────────────────┐
 │  SPA / Web /  │  authority =        │ Host-header router                        │
 │ Daemon / CLI  │─ login host ──────▶ │  login.entra.localhost  → STS/OIDC        │
 └───────────────┘  :8443/{tenant}     │  graph.entra.localhost  → minimal Graph   │
        ▲                              │  portal.entra.localhost → admin API+pages │
        │ validate JWT via JWKS        │  (localhost/127.0.0.1 = compat: all)      │
 ┌──────┴────────┐                     │ Token service (RS256, persisted key)      │
 │  Resource API │◀──── JWKS ──────────│ JSON store (data/entra-emulator.json)     │
 └───────────────┘                     └──────────────────────────────────────────┘
```

Three surfaces share one HTTPS listener, routed by `Host` header. The
`localhost`/`127.0.0.1` origin is a backward-compat host serving **every** route
(`ORIGIN_MODE=compat` collapses all advertised origins onto it — the default when the
subdomains can't resolve, e.g. in a container).

## Package layout

```
entra-emulator/
├── cmd/entra-emulator/     main: flags/subcommands, boot sequence
├── internal/
│   ├── config/             env → JSON file → defaults; validation
│   ├── store/              entities, SQLite persistence + migrations, seed,
│   │                       scrypt/SHA-256 hashing
│   ├── tokens/             RSA key mgmt, JWKS, RS256 JWS, claim assembly,
│   │                       auth-code / refresh-token / device-code issuance
│   ├── identity/           discovery, authorize + sign-in page, token grants,
│   │                       devicecode, userinfo, logout
│   ├── graph/              /v1.0 me/users/groups (+ bearer validation)
│   ├── admin/              /admin/api CRUD, seed/reset, health, cert endpoints,
│   │                       embedded portal assets (go:embed of portal/dist)
│   ├── httpx/              host routing, tenant resolution, OAuth/Graph/admin
│   │                       error envelopes
│   ├── tlscert/            self-signed wildcard cert generation + persistence
│   └── server/             wiring: mux per surface, TLS listener, graceful stop
├── portal/                 Svelte SPA (Vite); `npm run build` → portal/dist,
│                           embedded into the Go binary at compile time
└── docs/                   this design set
```

The portal is a **pre-built asset** from the Go toolchain's point of view: `portal/dist`
is committed (or produced in CI before `go build`), so `go build` alone always yields a
complete binary. The Node toolchain is only required when changing the portal itself.

Dependency rule: `identity`/`graph`/`admin` depend on `tokens` + `store`; nothing
depends on `server`. `store` and `tokens` know nothing about HTTP.

## Boot sequence

1. Load + validate config (fail fast, non-zero exit naming the offending key).
2. Open the SQLite store; apply pending schema migrations.
3. Seed if the directory is empty (`SEED_ON_START` semantics).
4. Load or generate the RSA signing key (persisted in the store → stable `kid`).
5. Load or generate the TLS certificate (persisted under `TLS_CERT_DIR`).
6. Build the three surface muxes, wrap in the host router, listen on `HOST:PORT`.

## Runtime state on disk

```
data/
├── entra-emulator.db      SQLite: directory + signing keys + live grants
│                          (auth codes, refresh tokens, device codes, sessions)
└── tls/
    ├── cert.pem           self-signed wildcard cert (stable fingerprint)
    └── key.pem
```

## Reference sources

1. **`~/calvinchengx/entra-docs`** — the official Microsoft Entra documentation
   (source of learn.microsoft.com/entra). Canonical for protocol behavior, claim
   semantics, and MSAL client configuration: `docs/identity-platform/` (OAuth/OIDC,
   tokens, MSAL), `docs/identity/authentication/` (auth methods incl. passkeys/FIDO2),
   `docs/external-id/` (CIAM / native auth). When emulator behavior is in question,
   this wins over inference.
2. **`~/calvinchengx/entra-local`** — the TypeScript prior-art emulator; canonical for
   the emulated surface cut, seed data, and error conventions (its `specs/` folder).

## Design doc set

| Doc | Covers |
|---|---|
| [02-configuration.md](02-configuration.md) | Every config key, precedence, validation |
| [03-data-model-and-seed.md](03-data-model-and-seed.md) | Entities, JSON document shape, deterministic seed |
| [04-token-service.md](04-token-service.md) | Keys, JWKS, claim assembly, lifetimes, grant artifacts |
| [05-oidc-endpoints.md](05-oidc-endpoints.md) | Discovery, authorize/sign-in, token grants, device code, userinfo, logout, errors |
| [06-graph-api.md](06-graph-api.md) | Graph routes, bearer validation, response/error shapes |
| [07-admin-api.md](07-admin-api.md) | Admin REST routes, DTOs, pagination, portal pages |
| [08-tls-and-origins.md](08-tls-and-origins.md) | Cert generation, origin modes, host routing |
| [09-testing.md](09-testing.md) | Unit/integration/conformance test strategy |
