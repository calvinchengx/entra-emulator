# OIDC / OAuth 2.0 endpoints

All under `/{tenant}/...` on the login surface. `{tenant}` is allowlisted to the
configured GUID plus the aliases `common`, `organizations`, `consumers` — all resolve to
the single tenant. Invalid segment → `404` JSON (discovery/JWKS) or OAuth
`400 invalid_request` (authorize/token). The **issuer is always GUID-form**, whatever
alias was used.

## Canonical path map (login surface)

| Method | Path |
|---|---|
| GET | `/{tenant}/v2.0/.well-known/openid-configuration` |
| GET | `/{tenant}/discovery/v2.0/keys` |
| GET, POST | `/{tenant}/oauth2/v2.0/authorize` |
| POST | `/{tenant}/oauth2/v2.0/token` |
| POST | `/{tenant}/oauth2/v2.0/devicecode` (RFC JSON) |
| GET | `/{tenant}/oauth2/v2.0/devicecode` (approval page) |
| POST | `/{tenant}/oauth2/v2.0/devicecode/verify` (approval form) |
| GET | `/{tenant}/oauth2/v2.0/logout` |

UserInfo lives on the **Graph** surface: `GET|POST /oidc/userinfo` (compat origin:
`/graph/oidc/userinfo`) — see 06.

## Discovery document

`Cache-Control: public, max-age=3600`. Fields (URLs built from resolved origins):

```jsonc
{
  "issuer": "<loginOrigin>/<tenantId>/v2.0",
  "authorization_endpoint": "<loginOrigin>/<tenantId>/oauth2/v2.0/authorize",
  "token_endpoint": "<loginOrigin>/<tenantId>/oauth2/v2.0/token",
  "device_authorization_endpoint": "<loginOrigin>/<tenantId>/oauth2/v2.0/devicecode",
  "jwks_uri": "<loginOrigin>/<tenantId>/discovery/v2.0/keys",
  "userinfo_endpoint": "<graphOrigin>/oidc/userinfo",
  "end_session_endpoint": "<loginOrigin>/<tenantId>/oauth2/v2.0/logout",
  "response_types_supported": ["code"],
  "response_modes_supported": ["query", "fragment", "form_post"],
  "grant_types_supported": ["authorization_code", "refresh_token",
    "client_credentials", "urn:ietf:params:oauth:grant-type:device_code"],
  "subject_types_supported": ["pairwise"],
  "scopes_supported": ["openid", "profile", "email", "offline_access"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
  "code_challenge_methods_supported": ["S256", "plain"],
  "claims_supported": ["sub","iss","aud","exp","iat","nbf","tid","oid",
    "name","preferred_username","email","nonce","ver"]
}
```

No Microsoft cloud-host fields (`tenant_region_scope` etc.); no front-channel-logout
capability flags (not implemented).

## Canonical OAuth error convention (token-shaped endpoints)

JSON, correct 4xx, `Cache-Control: no-store`:

```jsonc
{
  "error": "invalid_grant",
  "error_description": "AADSTS70008: ... human message",
  "error_codes": [70008],
  "timestamp": "2026-07-10T12:00:00Z",
  "trace_id": "<uuid>",
  "correlation_id": "<uuid>"
}
```

| Condition | `error` | HTTP |
|---|---|---|
| Unknown grant_type | `unsupported_grant_type` | 400 |
| Missing/invalid required param, bad tenant alias | `invalid_request` | 400 |
| Bad/expired/replayed code, PKCE mismatch, redirect mismatch, RT invalid/reused, client_id≠binding | `invalid_grant` | 400 |
| Unknown client, wrong/missing secret, public client sending a secret, non-confidential on client_credentials | `invalid_client` | 401 |
| Unregistered/invalid scope, non-subset narrowing, bad `.default` | `invalid_scope` | 400 |
| Device poll pending / denied / expired / unknown code | `authorization_pending` (70016) / `authorization_declined` (70018) / `expired_token` (70020) / `bad_verification_code` (70019) | 400 |

## Authorize — `GET|POST /{tenant}/oauth2/v2.0/authorize`

Params: `client_id`* , `response_type`* (=`code`), `redirect_uri`* (exact match against
registered), `scope`* (must include `openid`), `state` (echoed), `code_challenge`
(required for public clients) + `code_challenge_method` (`S256`|`plain`), `nonce`,
`response_mode` (`query` default | `fragment` | `form_post` auto-submit HTML), `prompt`
(`login`/`select_account` force picker; `none` without session → redirect
`error=login_required`), `login_hint` (pre-selects user).

Error rules: invalid `client_id`/`redirect_uri` → **400 error page, never redirect**;
other errors with a valid redirect_uri → redirect back with `error`+`state`.

**Sign-in interaction:** server-rendered account picker listing enabled users (display
name + UPN); selection POSTs back and creates a session. `REQUIRE_PASSWORD=true` swaps in
a username+password form (`users.VerifyPassword`); wrong credentials re-render with an
error. Authorize params survive the interactive POST via an HMAC-signed hidden state
field (`__ee_state`, per-process key). Cookies: `ee_session` (HttpOnly, SameSite=Lax,
Secure-when-TLS, 8 h — must be the **first** Set-Cookie) and `ee_recent` (recent UPNs,
30 d). A valid session + no forcing `prompt` skips the picker (SSO) and issues the code
directly.

On success: issue code (via token service) → deliver `code` + `state` per response_mode.

## Token — `POST /{tenant}/oauth2/v2.0/token` (form-encoded, grant-multiplexed)

**Client authentication (shared):** confidential → `client_secret` via body
(`client_secret_post`) or `Authorization: Basic` (`client_secret_basic`); wrong/missing →
`invalid_client`. Public → must NOT send a secret (sending one → `invalid_client`).

### grant_type=authorization_code
`code`*, `redirect_uri`*, `client_id`*, `code_verifier` (required iff challenge stored),
`client_secret` (confidential). Redeems per 04's contract → full token response
(`refresh_token` iff `offline_access`).

### grant_type=refresh_token
`refresh_token`*, `client_id`*, optional `scope` narrowing, `client_secret`
(confidential; PKCE never re-checked). Rotation + family-revocation-on-reuse per 04.

### grant_type=client_credentials
`client_id`*, `client_secret`*, `scope`* = exactly one `<resource>/.default`.
Resolution order: `GRAPH_RESOURCE_ID` → app by `app_id_uri` → app by GUID → else
`invalid_scope`. **Reserved OIDC scopes (`openid profile offline_access`) accompanying
`.default` are silently ignored** — MSAL Go and azidentity append them to
client-credentials requests and real Entra tolerates that (found by the Go e2e
suite). Any other extra scope → `invalid_scope`.
Roles auto-granted from the resource app's enabled Application-type roles (`[]` for
Graph). Response has NO id_token/refresh_token/client_info. Public client → `invalid_client`.

### grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer (On-Behalf-Of)
A confidential middle-tier exchanges a user access token it received for a downstream
token as the same user. Params: `client_id`* + `client_secret`* (confidential only),
`assertion`* (the incoming user token), `scope`* (downstream), `requested_token_use`*
= `on_behalf_of`. **Rule (entra-docs):** the assertion's `aud` must be this middle-tier
(its `appId` or `app_id_uri`) — a token for another resource (e.g. Graph) is rejected
`invalid_grant`. The assertion must be delegated (has `oid`); app-only → `invalid_grant`.
Result: a new delegated token, same `oid`/`sub`-user, `azp`/`appid` = the middle-tier,
`aud` = the downstream resource. (Cert-based `client_assertion` is roadmap #13.)

### Device code grant
`grant_type` accepts **both** `urn:ietf:params:oauth:grant-type:device_code` (canonical,
advertised) **and** bare `device_code` (what msal-node actually sends). Params:
`device_code`*, `client_id`*. Extra params (`scope`, `client_info=1`, telemetry) are
**ignored** — granted scopes come solely from the stored row. Status mapping (error
names match entra-docs, not the RFC): pending → `authorization_pending`; approved →
atomic `ConsumeApproved` then mint (loser of a race → `bad_verification_code`); denied →
`authorization_declined` + delete; expired → `expired_token` + delete (lazy);
unknown/consumed → `bad_verification_code`; app mismatch → `bad_verification_code`.
`slow_down` is never emitted (interval advertised only).

## Device authorization — `POST /{tenant}/oauth2/v2.0/devicecode`

Form: `client_id`* (+ secret if confidential), `scope`* (validated identically to
authorize). Success:

```jsonc
{
  "device_code": "<opaque 256-bit>",
  "user_code": "BCDF-GHJK",
  "verification_uri": "<loginOrigin>/{tenant-as-requested}/oauth2/v2.0/devicecode",
  "expires_in": 900, "interval": 5,
  "message": "To sign in, open ... and enter the code ..."
}
```

`verification_uri` echoes the requested tenant alias. **`verification_uri_complete` is
deliberately omitted** — real Entra does not return it (entra-docs
`v2-oauth2-device-code`), even though RFC 8628 lists it as optional; we match Entra.

**Approval page:** GET renders code entry (pre-filled from `?user_code=`); POST
`/verify` is a 3-step state machine (`__ee_step` = `lookup` → `signin` → `decide`)
reusing the sign-in chrome and `ee_session` SSO. CSRF: `__ee_state` HMAC-signs
`{userCode, sid}` where `sid` must equal the live session id on `decide`; the device code
row is re-validated server-side at every step. Approve → `status=approved` +
`user_id`; deny → `denied`. Distinct error pages for not-found / expired / already-used /
denied codes.

## Logout — `GET /{tenant}/oauth2/v2.0/logout`

Query: `post_logout_redirect_uri`, `client_id`, `id_token_hint` (unverified, used only to
infer client_id), `state`. Behavior: delete the session row + expire the cookie
(idempotent). Redirect only when `post_logout_redirect_uri` exactly matches a registered
redirect URI of a resolvable client — else render the "signed out" page (200). `state`
appended on redirect.

## Managed identity — `GET /msi/token` (App Service protocol)

Emulates the App Service / Functions / Container Apps managed-identity endpoint
(roadmap #3). Served on the login and compat surfaces.

- **Auth:** header `X-IDENTITY-HEADER: <MANAGED_IDENTITY_SECRET>` (SSRF mitigation in
  real Azure); missing/wrong → 401.
- **Query:** `resource`* (the audience), `api-version`, and optionally
  `client_id`/`object_id`/`mi_res_id` to select a user-assigned identity. No id →
  system-assigned (`MANAGED_IDENTITY_CLIENT_ID`, default the seeded daemon app).
- **Response (App Service format):** `{ access_token, expires_on (string), expires_in
  (string), not_before (string), resource, token_type: "Bearer", client_id }`. The
  token is app-only (`sub`=`appid`=identity, no `oid`), `aud`=resource, `roles`
  auto-granted from the resource app's Application roles.

A workload sets `IDENTITY_ENDPOINT=<origin>/msi/token` + `IDENTITY_HEADER=<secret>`;
`azidentity.ManagedIdentityCredential` / `DefaultAzureCredential` then acquires a token
with no secret in the app. We emulate the env-var endpoint, not raw IMDS
(`169.254.169.254` is link-local and unroutable to the emulator).

## Passkey / WebAuthn ceremonies (roadmap #11)

`POST /{tenant}/webauthn/register/begin|finish` and `.../assert/begin|finish` implement
FIDO2/WebAuthn. The relying party is built **per request from the Host header** (RP ID =
host without port, origin = scheme://host), so passkeys work on whichever origin the
emulator is reached on. `begin` takes `{upn}` and returns the standard
`PublicKeyCredentialCreation/RequestOptions`; ceremony state is held server-side keyed by
a short-lived `ee_webauthn` cookie. `assert/finish` verifies the assertion and creates an
`ee_session` tagged `fido`, so a subsequent `/authorize` (SSO) issues a code whose ID
token carries `amr: ["fido"]`. Password/picker sign-in yields `amr: ["pwd"]`. Manage a
user's passkeys via `GET/DELETE /admin/api/users/{id}/passkeys`.
