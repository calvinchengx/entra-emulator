# Entra Emulator

**A local, MSAL-compatible emulator of Microsoft Entra ID (Azure AD), in a single Go
binary.** A faithful port of [entra-local](https://github.com/cmaneu/entra-local) — the
same OIDC/OAuth 2.0 v2.0 endpoints MSAL talks to, a minimal read-only Microsoft Graph,
and an unauthenticated admin REST API, so you can develop sign-in, token acquisition,
and protected-API calls offline with no cloud tenant.

> ⚠️ **Local development tool only — intentionally insecure.** Open admin API,
> publicly known seeded users/secrets, self-signed TLS, signing key stored unencrypted.
> Run it on `localhost` only. Never point real users or secrets at it.

## Quick start

```bash
go build ./cmd/entra-emulator
./entra-emulator
# Health:    https://portal.entra.localhost:8443/health   (compat: https://localhost:8443/health)
# Discovery: https://login.entra.localhost:8443/11111111-1111-1111-1111-111111111111/v2.0/.well-known/openid-configuration
```

First run creates `./data/` with the SQLite store, a persisted self-signed wildcard TLS
certificate (stable fingerprint), a persisted RSA signing key (stable `kid`), and a
deterministic seed directory. Subdomain names need hosts entries
(`./entra-emulator hosts --apply`), or set `ORIGIN_MODE=compat` to keep everything on
`https://localhost:8443`.

## What works

- **Flows:** Authorization Code + PKCE (S256/plain), Client Credentials
  (`<resource>/.default`, app-role auto-grant), rotating Refresh Tokens with
  family-revocation-on-reuse, Device Code (RFC 8628, with the human approval page),
  front-channel logout, OIDC UserInfo.
- **Tokens:** real RS256-signed JWTs with Entra v2.0 claim shapes (`tid`, `oid`,
  `scp`/`roles`, pairwise `sub`, `ver: "2.0"`, `client_info`), verifiable against the
  live JWKS (`kid` = RFC 7638 thumbprint). Optional claims + group claims (with the
  Entra-style overage payload) per app registration.
- **Graph:** `/v1.0/me`, `/users`, `/users/{id-or-upn}`, `/groups`, `/groups/{id}`,
  `/groups/{id}/members` with `@odata` envelopes and `$top`/`$skiptoken` paging.
- **Admin API:** full CRUD for users, groups (+membership), app registrations
  (+redirect URIs, show-once secrets, scopes, app roles), `seed`/`reset`, health,
  certificate download.
- **Surfaces:** one HTTPS listener, `Host`-routed — `login.` / `portal.` /
  `graph.entra.localhost`, with `localhost` as the serve-everything compat origin.

## Point MSAL at it

```jsonc
{
  "auth": {
    "clientId": "cccccccc-0000-0000-0000-000000000001",
    "authority": "https://login.entra.localhost:8443/11111111-1111-1111-1111-111111111111",
    "knownAuthorities": ["login.entra.localhost:8443"],
    "redirectUri": "https://localhost:3000"
  }
}
```

Trust the self-signed cert (`./entra-emulator trust` prints the platform command;
`NODE_EXTRA_CA_CERTS=$( ./entra-emulator cert-path )` for Node clients).

## Seed data (fixed GUIDs, reproducible CI)

| What | Value |
|---|---|
| Tenant | `11111111-1111-1111-1111-111111111111` |
| Users | `alice@entralocal.dev`, `bob@entralocal.dev` (password `Password1!`), group `Engineering` |
| Public SPA app | `cccccccc-…-0001`, redirect `https://localhost:3000`, scope `access_as_user` |
| Confidential daemon | `cccccccc-…-0002`, secret `daemon-app-secret`, app role `Tasks.Read.All` |

## Configuration

Environment > `entra-emulator.config.json` > defaults; invalid config aborts naming the
offending key. Key settings: `PORT` (8443), `TENANT_ID`, `ORIGIN_MODE`
(`subdomains`|`compat`), `PUBLIC_ORIGIN`, `REQUIRE_PASSWORD`, `DB_PATH`,
`TOKEN_LIFETIME_*`. Full reference: [docs/02-configuration.md](docs/02-configuration.md).

## Design & development

The full design lives in [docs/](docs) — architecture, configuration, data model +
seed, token service, endpoint contracts, Graph, admin API, TLS/origins, testing, and
the post-parity roadmap (embeddable Go test library, token forge, fault injection…).

```bash
go build ./...   # everything, including the CLI
go test ./...    # integration tests drive the full handler stack
go vet ./...
./e2e/run.sh     # real-SDK e2e: @azure/msal-node, MSAL Go + azidentity, MSAL Python
```

The e2e suites prove unmodified Microsoft SDKs complete real flows against the
emulator (see [docs/11-e2e-sdk-matrix.md](docs/11-e2e-sdk-matrix.md)): client
credentials, Authorization Code + PKCE with `client_info` account identity, silent
refresh, and device code with headless approval — in TypeScript, Go, and Python.

Dependencies: `modernc.org/sqlite` (pure-Go SQLite, no cgo) and `golang.org/x/crypto`
(scrypt). Cross-compiles to a single static binary on all platforms.

### Deliberate divergences from entra-local

Protocol surface, claim shapes, error bodies, seed GUIDs, and lifetimes are ported
faithfully. Internals differ: Go stdlib `net/http` instead of Fastify, hand-rolled
RS256 JWS instead of `jose`, and a Svelte portal (in progress) instead of React. Data
files are not interchangeable between the two projects.

## Disclaimer

An independent developer tool, not affiliated with or endorsed by Microsoft.
"Microsoft Entra ID", "Azure AD", "Microsoft Graph", and "MSAL" are Microsoft
trademarks. This project emulates publicly documented protocol behavior for local
development and testing only.
