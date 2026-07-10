# 02 — Configuration

Configuration is loaded with precedence **environment variables → config file → built-in
defaults** (highest first). The config file is `entra-emulator.config.json` in the working
directory, or the path in `CONFIG_FILE`; an absent file is not an error. The merged object
is validated at startup; **any failure aborts with a non-zero exit naming the offending
key(s)** — no partial boot.

## Reference table

| Env key | Config-file field | Type | Default | Description |
|---|---|---|---|---|
| `HOST` | `host` | string | `localhost` | Bind host (bind-only; does not affect advertised origins). Docker uses `0.0.0.0`. |
| `PORT` | `port` | int 1–65535 | `8443` | Listen port. |
| `TENANT_ID` | `tenantId` | GUID | `11111111-1111-1111-1111-111111111111` | The single fixed tenant; also the allowlisted `{tenant}` path value. |
| `ORIGIN_MODE` | `originMode` | `subdomains` \| `compat` | `subdomains` | `subdomains` advertises `login./portal./graph.<baseDomain>`; `compat` collapses every advertised origin to `https://localhost:<port>`. |
| `BASE_DOMAIN` | `baseDomain` | hostname | `entra.localhost` | Apex for the three subdomains and the wildcard cert. |
| `LOCAL_DOMAINS` | `localDomains` | CSV → []string | empty | Extra apex domains; each adds cert SANs (apex + wildcard) and hosts-file entries. |
| `PUBLIC_ORIGIN` | `publicOrigin` | URL | derived | When set, **all three** origins collapse to it (legacy single-origin). |
| `LOGIN_ORIGIN` / `PORTAL_ORIGIN` / `GRAPH_ORIGIN` | `loginOrigin` etc. | URL | derived | Per-surface overrides; win over `PUBLIC_ORIGIN` and `ORIGIN_MODE`. |
| `ISSUER` | `issuer` | URL | `${loginOrigin}/${tenantId}/v2.0` | Must equal discovery `issuer` and token `iss`. |
| `DB_PATH` | `dbPath` | path | `./data/entra-emulator.db` | SQLite file. |
| `TLS_ENABLED` | `tls.enabled` | bool | `true` | `false` → plain HTTP on loopback. |
| `TLS_CERT` / `TLS_KEY` | `tls.certPath` / `tls.keyPath` | path | auto | Custom PEM pair; setting exactly one is a validation error. |
| `TLS_CERT_DIR` | `tls.certDir` | path | `./data/tls` | Where the auto-generated cert/key persist. |
| `REQUIRE_PASSWORD` | `requirePassword` | bool | `false` | Password form instead of the account picker. |
| `SEED_ON_START` | `seedOnStart` | bool | `true` | Apply the deterministic seed when the DB has no tenant row. |
| `TOKEN_LIFETIME_AUTH_CODE_SECONDS` | `tokenLifetimes.authCode` | int | `300` | Auth code TTL (single-use). |
| `TOKEN_LIFETIME_ID_SECONDS` | `tokenLifetimes.idToken` | int | `3600` | ID token TTL. |
| `TOKEN_LIFETIME_ACCESS_SECONDS` | `tokenLifetimes.accessToken` | int | `3600` | Access token TTL. |
| `TOKEN_LIFETIME_REFRESH_SECONDS` | `tokenLifetimes.refreshToken` | int | `86400` | Refresh token TTL (rotating, rolling). |
| `TOKEN_LIFETIME_DEVICE_CODE_SECONDS` | `tokenLifetimes.deviceCode` | int | `900` | Device code TTL. |
| `DEVICE_CODE_INTERVAL_SECONDS` | `deviceCodeInterval` | int | `5` | Advertised device-code poll interval. |
| `GRAPH_RESOURCE_ID` | `graphResourceId` | string | `https://graph.microsoft.com` | Default audience for Graph access tokens. |
| `MANAGED_IDENTITY_SECRET` | `managedIdentitySecret` | string | `managed-identity-secret` | Matched against `X-IDENTITY-HEADER` on `/msi/token` (dev value). |
| `MANAGED_IDENTITY_CLIENT_ID` | `managedIdentityClientId` | GUID | seeded daemon app | The system-assigned managed identity's appId. |
| `LOG_LEVEL` | `logLevel` | enum | `info` | `error|warn|info|debug`. |
| `CONFIG_FILE` | — | path | `./entra-emulator.config.json` | Config-file location. |

## Origin derivation (order of precedence per surface)

1. Explicit per-surface override (`LOGIN_ORIGIN` / `PORTAL_ORIGIN` / `GRAPH_ORIGIN`).
2. `PUBLIC_ORIGIN` — collapses all three to one origin.
3. `ORIGIN_MODE=compat` — collapses all three to `${scheme}://localhost:${port}`.
4. Default: `${scheme}://{login|portal|graph}.${baseDomain}:${port}`.

`issuer` derives from the resolved login origin unless `ISSUER` is set explicitly.
`HOST`/`PORT` are bind-only and never leak into advertised URLs (a container binds
`0.0.0.0` while advertising `localhost`).

## Validation rules

- `TENANT_ID` must be a lowercase GUID; `PORT` in range; origins/issuer must parse as URLs.
- Exactly one of `TLS_CERT`/`TLS_KEY` set → error ("both or neither").
- Lifetimes must be positive integers.
- The frozen, validated config struct is the single source read by every package.
