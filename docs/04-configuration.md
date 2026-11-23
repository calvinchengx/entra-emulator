# Configuration

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
| `TENANT_ID` | `tenantId` | GUID | `6f89cf12-978b-4d23-ac18-9ef0c127cf87` | The single fixed tenant; also the allowlisted `{tenant}` path value. |
| `ORIGIN_MODE` | `originMode` | `subdomains` \| `compat` | `subdomains` | `subdomains` advertises `login./portal./graph.<baseDomain>`; `compat` collapses every advertised origin to `https://localhost:<port>`. |
| `BASE_DOMAIN` | `baseDomain` | hostname | `entra.localhost` | Apex for the three subdomains and the wildcard cert. |
| `LOCAL_DOMAINS` | `localDomains` | CSV → []string | empty | Extra apex domains; each adds cert SANs (apex + wildcard) and hosts-file entries. |
| `PUBLIC_ORIGIN` | `publicOrigin` | URL | derived | When set, **all three** origins collapse to it (legacy single-origin). |
| `LOGIN_ORIGIN` / `PORTAL_ORIGIN` / `GRAPH_ORIGIN` | `loginOrigin` etc. | URL | derived | Per-surface overrides; win over `PUBLIC_ORIGIN` and `ORIGIN_MODE`. |
| `ISSUER` | `issuer` | URL | `${loginOrigin}/${tenantId}/v2.0` | Must equal discovery `issuer` and token `iss`. |
| `ENTRA_DATA_DIR` | — | path | `./data` | The state directory: the SQLite file and the generated TLS material live under it. This is the family-wide `<PREFIX>_DATA_DIR` convention. Set it to the **empty string** to keep nothing — an in-memory database and a certificate generated per run; *unset* and *set-empty* differ deliberately. |
| `DB_PATH` | `dbPath` | path | `<ENTRA_DATA_DIR>/entra-emulator.db` | SQLite file. Predates `ENTRA_DATA_DIR` and still **wins** when set, so existing deployments are unaffected. |
| `TLS_ENABLED` | `tls.enabled` | bool | `true` | `false` → plain HTTP on loopback. |
| `TLS_CERT` / `TLS_KEY` | `tls.certPath` / `tls.keyPath` | path | auto | Custom PEM pair; setting exactly one is a validation error. |
| `TLS_CERT_DIR` | `tls.certDir` | path | `<ENTRA_DATA_DIR>/tls` | Where the auto-generated cert/key persist. Wins over `ENTRA_DATA_DIR` when set. |
| `REQUIRE_PASSWORD` | `requirePassword` | bool | `false` | Password form instead of the account picker. |
| `REQUIRE_CONSENT` | `requireConsent` | bool | `false` | Show a consent screen during authorize before issuing the code. |
| `GRAPH_PERMISSIONS` | `graphPermissions` | bool | `false` | Gate Graph operations on the caller's permissions the way real Entra does: delegated calls need the scope in `scp`, app-only calls the role in `roles`, `Directory.*` is the superset, denials are `403 Authorization_RequestDenied`. Off by default because any valid Graph-audience token has always been accepted — turn it on to prove your app requests the permissions it needs. |
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
| `RECORD_RESPONSES` | — | path | unset | Append one JSON line per Microsoft Graph response (method, path, query, status, body; **never a header**, so no bearer token) to this file. Diagnostic for CI: the recording is the input to `scripts/check_graph_conformance.py`, which holds real-SDK traffic to Microsoft's published Graph OpenAPI. Environment only, deliberately not a config-file key. An unwritable path logs and records nothing rather than stopping the emulator. |
| `CONFIG_FILE` | — | path | `./entra-emulator.config.json` | Config-file location. |
| `MANIFEST_FILE` | `manifestFile` | path | unset | Load the directory from a [manifest](#manifest) instead of the deterministic seed. Its `tenantId` and `tokenLifetimes` replace `TENANT_ID` and `TOKEN_LIFETIME_*`, and `SEED_ON_START` is ignored. |

## Manifest

A manifest is a JSON file describing the whole directory: one tenant, its applications,
users and groups, their app-role assignments, and token lifetimes. Point `MANIFEST_FILE`
(or `manifestFile` in the config file) at one, and on every start the emulator replaces
the directory with the manifest's contents instead of applying the deterministic seed.

- **Replaced by the manifest:** `TENANT_ID`, `TOKEN_LIFETIME_*` and `SEED_ON_START`, from
  the environment and the config file alike. A lifetime the manifest leaves out uses the
  default, not the environment value.
- **Still from the environment or config file:** everything else, including the port,
  TLS (`TLS_CERT`/`TLS_KEY`), origins and the issuer.
- **Every start re-applies it:** users, groups, apps and app-role assignments created
  at runtime (Graph, admin API, portal) are discarded at the next start, as are
  sessions and refresh tokens. The tenant row and signing keys are kept.
- **Errors stop startup**, each named by its JSON path, for example
  `MANIFEST_FILE: applications[0].appId: must be a GUID`. Unknown properties are errors,
  so a misspelt property is reported rather than ignored.

Property names are camelCase and follow Microsoft Graph's application, user and group
resources (`identifierUris`, `api.oauth2PermissionScopes`, `appRoles`,
`web`/`spa`/`publicClient.redirectUris`). The JSON Schema is
[`schemas/manifest.schema.json`](../schemas/manifest.schema.json): reference it from the
manifest's `$schema` for completion and validation in editors. A complete example
(an API, an SPA, a BFF web app, a worker using client credentials, users and a group) is
[`samples/manifest/entra-emulator.manifest.json`](../samples/manifest/entra-emulator.manifest.json):

```jsonc
{
  "$schema": "../../schemas/manifest.schema.json",
  "tenantId": "3c8f2a91-6d4e-4b7a-9e15-0a2b7c4d8e6f",
  "applications": [
    {
      "appId": "8a1d5e7c-2f4b-4c9a-b3e6-5d7f9a1c3e2b",
      "displayName": "Contoso API",
      "identifierUris": ["api://contoso-api"],
      "api": { "oauth2PermissionScopes": [{ "value": "access_as_user" }] },
      "appRoles": [{ "value": "Tasks.Admin", "allowedMemberTypes": ["User"] }]
    }
  ],
  "users": [
    {
      "userPrincipalName": "alice@contoso.local",
      "displayName": "Alice Admin",
      "password": "Password1!",
      "appRoleAssignments": [{ "resourceAppId": "8a1d5e7c-2f4b-4c9a-b3e6-5d7f9a1c3e2b", "appRole": "Tasks.Admin" }]
    }
  ]
}
```

- `tenantId` and each `appId` are GUIDs. Users, groups, scopes and roles may leave out
  `id`: it is then derived from the tenant and the object's name (UPN, display name or
  value), so it is stable across restarts.
- An application with `clientSecrets` is a confidential client; secrets and passwords
  are given in plain text and stored hashed.
- `appRoleAssignments` name the resource by `appId` and the role by `value`, and can sit
  on a user, a group (for its direct members) or an application (application
  permissions). Leaving out `appRole` gives the default access assignment, which carries
  no role. The role must allow the holder's member type: `User` for users and groups,
  `Application` for applications.
- Group `members` are users, named by `userPrincipalName` or `id`.
- `identifierUris` holds at most one URI.

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
