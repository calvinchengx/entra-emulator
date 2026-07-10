# 04 — Token service

All tokens are RS256-signed compact JWTs verifiable against the JWKS endpoint. The token
service is pure Go over `crypto/rsa` + `crypto/sha256`; an injectable clock keeps tests
deterministic.

## Signing keys & JWKS

- RSA-2048, RS256 only. Generated on first boot when the tenant has no active key;
  persisted in `signing_keys` (public JWK JSON + PKCS8 PEM private) so `kid` and
  signatures are stable across restarts.
- **`kid` = RFC 7638 JWK thumbprint** (base64url SHA-256 of the canonical public JWK).
- `GET /{tenant}/discovery/v2.0/keys` → `{"keys":[{kty:"RSA",use:"sig",alg:"RS256",kid,n,e}]}`;
  lists active + retired-but-unexpired keys (rotation-ready); never private fields.
  `Cache-Control: public, max-age=86400`.
- Token header: `{"typ":"JWT","alg":"RS256","kid":"<active kid>"}`.

## Token response JSON (success, all grants)

```jsonc
{
  "token_type": "Bearer",
  "expires_in": 3600,             // access-token TTL
  "ext_expires_in": 3600,
  "scope": "openid profile email offline_access access_as_user",
  "access_token": "<JWT>",
  "id_token": "<JWT>",            // iff openid granted
  "refresh_token": "<opaque>",    // iff offline_access granted
  "client_info": "<base64url>"    // delegated flows only
}
```

`client_info` = `base64url({"uid":"<user oid>","utid":"<tenantId>"})` — required for MSAL
account/cache identity. Present on all **delegated** responses (auth code, refresh,
device code); **omitted** for client credentials. `Cache-Control: no-store`,
`Pragma: no-cache` on every token response.

## ID token claims

| Claim | Value |
|---|---|
| `iss` | GUID-form issuer `${loginOrigin}/${tenantId}/v2.0` |
| `sub` | pairwise: `base64url(SHA-256(user.id + "|" + appId + "|" + tenantId))` |
| `aud` | client `appId` |
| `exp`/`iat`/`nbf` | `iat`=`nbf`=now; `exp`=iat+ID lifetime |
| `tid` / `oid` | tenant GUID / user id |
| `name` / `preferred_username` | display_name / UPN |
| `email` | user.mail (omitted when null) |
| `nonce` | echoed from authorize (absent on refresh re-mint) |
| `ver` | `"2.0"` |

## Access token claims

| Claim | Delegated | App-only (client credentials) |
|---|---|---|
| `iss`, `exp`, `iat`, `nbf`, `tid`, `ver` | same as ID token | same |
| `sub` | pairwise (user+app) | the app's `appId` |
| `aud` | per audience rule below | per audience rule |
| `oid` | user id | **omitted** |
| `azp` / `appid` | client appId | client appId |
| `scp` | space-delimited granted scope **names** | **omitted** |
| `roles` | omitted | array of auto-granted app roles (may be `[]`) |

**Audience rule:** resource scope `api://<x>/<scope>` or app GUID → `aud` = that
`app_id_uri`/GUID. Graph scopes (`https://graph.microsoft.com/...` or known bare names
like `User.Read`) → `aud` = `GRAPH_RESOURCE_ID`. OIDC-only requests → `aud` defaults to
`GRAPH_RESOURCE_ID` (so `/me` works post-sign-in). `scp` carries short names only
(`User.Read`, not the prefixed form).

**Graph scope carve-out:** Microsoft Graph delegated scopes are auto-consented and valid
without registration — fully-qualified `<GRAPH_RESOURCE_ID>/<name>` or bare known names
(`User.Read`, `User.ReadBasic.All`, `User.Read.All`, `Group.Read.All`). OIDC scopes
(`openid profile email offline_access`) are handled as OIDC, never as resource scopes.

## Optional claims & group claims (token configuration)

Per app registration (`optional_claims` JSON, `group_membership_claims`,
`group_overage_limit`):

- ID-token optional claims come from the **client** app's config; access-token claims
  from the **resource** app's config.
- Supported ID-token claims: `given_name`, `family_name`, `upn`, `ipaddr`, `groups` (+
  others per upstream's supported set); supported access-token set excludes `auth_time`.
  Unsupported configured claims are stored but never emitted.
- `groups` emits the user's group GUIDs when `group_membership_claims != None` or
  `groups` is listed as an optional claim. Above the overage limit, emit the Entra-style
  overage payload (`_claim_names`/`_claim_sources`) instead.
- Claims never carry empty values — unavailable source data means the claim is omitted.

## Lifetimes (config defaults)

| Artifact | Default | Notes |
|---|---|---|
| Authorization code | 300 s | single-use, atomic consume |
| ID token | 3600 s | |
| Access token | 3600 s | `expires_in` mirrors this |
| Refresh token | 86400 s | rotating; **rolling** TTL on each rotation |
| Device code | 900 s | interval 5 s |
| SSO session | 8 h | `el_session` cookie + row TTL |

## Grant artifact contracts

**Auth code:** opaque 32-byte base64url. Redeem validates: exists, not consumed (replay),
not expired, `app_id` + `redirect_uri` match, PKCE (if a challenge was stored a verifier
is required; `S256`: `base64url(SHA-256(verifier)) == challenge`; `plain`: equality).
Then atomic consume. Any failure → `invalid_grant`.

**Refresh token:** opaque 32-byte base64url, stored as SHA-256. Redeem: lookup by hash
(including revoked/expired rows) →
- missing → `invalid_grant`;
- `revoked=1` → **reuse**: revoke the whole rotation family (walk `rotated_from`
  ancestors + descendants), `invalid_grant`. Reuse takes precedence over expiry;
- `revoked=0` but expired → `invalid_grant`, no family revocation;
- active → CAS-revoke, insert successor (`rotated_from`), fresh rolling TTL. Scope
  narrowing: requested scopes must be a subset of the grant, else `invalid_scope`;
  new refresh token returned iff (narrowed) scopes still include `offline_access`.
  ID token re-minted when grant includes `openid` (no nonce).

**Device code:** opaque 32-byte base64url stored as SHA-256; `user_code` = 8 chars from
`BCDFGHJKLMNPQRSTVWXZ` grouped `XXXX-XXXX`, compared case-insensitively ignoring dashes/
whitespace, stored plaintext (UNIQUE).

## Access-token validation (consumed by Graph + userinfo)

Verify: RS256 signature via `kid` lookup, `alg` must be RS256, `iss` equals issuer,
`exp`/`nbf` within ±60 s skew, `aud` in the accepted set (default `GRAPH_RESOURCE_ID`),
plus optional required scopes (`scp`) / roles. Typed errors map to RFC 6750 401/403 at
the endpoints. The validator accepts `ver:"2.0"` (emulator tokens are v2 even for Graph).
