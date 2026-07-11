# How-to: test a protected API with forged tokens

Your resource API validates a `Bearer` token — checks the signature against
Entra's JWKS, the issuer, the audience, expiry, and the scopes/roles. To test
that logic you normally need to *drive a whole sign-in flow* just to get a
token, and getting a **deliberately bad** one (expired, wrong audience, tampered)
is even harder.

The **token forge** ([roadmap #2](17-roadmap.md)) skips the flow: one call mints
any token you want — valid or intentionally broken — so you can assert your API
accepts the good ones and rejects the bad ones. This guide drives it with
`curl`; the same is a form in the portal's **Token forge** panel.

## Point your API at the emulator

Configure your API's JWT middleware with the emulator's issuer and JWKS
(compat mode → `https://localhost:8443`):

| Setting | Value |
|---|---|
| Issuer | `https://localhost:8443/11111111-1111-1111-1111-111111111111/v2.0` |
| JWKS URI | `https://localhost:8443/11111111-1111-1111-1111-111111111111/discovery/v2.0/keys` |
| Audience | your API's app-id URI, e.g. `api://my-api` |

(These come from the [discovery document](08-oidc-endpoints.md); trust the
self-signed cert as in the [quickstart](01-quickstart.md).) Everything below
assumes `MY_API` is your protected endpoint.

## Mint a token and call your API

The forge lives on the admin surface. It returns `{ token, kid, claims }`;
`jq -r .token` pulls the JWT:

```sh
FORGE=https://localhost:8443/admin/api/tokens
CACERT="--cacert ./data/tls/cert.pem"

mint() { curl -sS $CACERT "$FORGE" -H 'Content-Type: application/json' -d "$1" | jq -r .token; }

# A normal, valid access token for your API, as user Alice with a scope:
TOKEN=$(mint '{
  "audience": "api://my-api",
  "userId":   "aaaaaaaa-0000-0000-0000-000000000001",
  "scopes":   ["Tasks.Read"]
}')

curl $CACERT -H "Authorization: Bearer $TOKEN" "$MY_API"   # expect: 200
```

## The negative tests (the point)

Each of these should make a correct API return **401** (authentication) or
**403** (authorization). If any returns 200, your validation has a gap.

```sh
# Expired 5 minutes ago → 401
mint '{"audience":"api://my-api","expiresInSeconds":-300}'

# Wrong audience (token minted for someone else) → 401
mint '{"audience":"api://a-different-api"}'

# Tampered signature (valid structure, fails JWKS verification) → 401
mint '{"audience":"api://my-api","signature":"invalid"}'

# Not valid yet (nbf one hour in the future) → 401
mint '{"audience":"api://my-api","notBeforeSeconds":3600}'

# Authenticated but missing the required scope → 403 (your authorization)
mint '{"audience":"api://my-api","userId":"aaaaaaaa-0000-0000-0000-000000000001","scopes":[]}'

# App-only token with a specific role, to test role-based authorization
mint '{"audience":"api://my-api","roles":["Tasks.ReadWrite.All"]}'
```

:::tip[Test claim-based logic without a directory change]
`extraClaims` is merged last and overrides anything — mint a token carrying
exactly the claim your code branches on:

```sh
mint '{"audience":"api://my-api","extraClaims":{"ipaddr":"10.0.0.1","acr":"1"}}'
```
:::

## Forge fields

`POST /admin/api/tokens` — every field is optional; defaults produce a normal
access token for the seeded SPA.

| Field | Effect |
|---|---|
| `tokenType` | `access` (default) or `id` |
| `clientId` | issuing app (default: seeded SPA) |
| `userId` | set → delegated (user) token; omit → app-only |
| `scopes` | `scp` on a delegated access token |
| `roles` | `roles` on an app-only access token |
| `audience` | override `aud` (default: Graph) |
| `expiresInSeconds` | default 3600; **negative → already expired** |
| `notBeforeSeconds` | `nbf` offset from now |
| `nonce` | id-token nonce |
| `extraClaims` | merged last — override/add any claim |
| `signature` | `valid` (default) or `invalid` (fails JWKS) |

## See how the emulator judged it

After a run, the **Audit trail** (portal, or `GET /admin/api/audit`) shows each
token request with its concrete accept/reject reason — handy when your API and
the emulator disagree about why a token is bad. And **[clock control](04-configuration.md)**
(`POST /admin/api/clock {"advanceSeconds": …}`) expires a *real* issued token
with no `sleep`, if you'd rather test expiry end-to-end than forge it.

## Next

- [Token service](07-token-service.md) — the exact claim shapes the forge emits.
- [Admin REST API](11-admin-api.md) — the full forge + audit + clock reference.
- [Testing](12-testing.md) — embedding the emulator in your test suite.
