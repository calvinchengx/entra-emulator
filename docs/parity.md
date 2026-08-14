# Feature parity: entra-emulator vs. real Microsoft Entra ID

How the emulator's surface maps to real Entra ID (as documented at
[learn.microsoft.com/entra](https://learn.microsoft.com/en-us/entra/)), and —
the point of this table — **whether real work happens or just the API shape**.

The design bet is that the durable, testable surface is *protocol + real
cryptography + directory state*, and those are done for real: real RS256 JWTs
that third-party validators accept, every OAuth2 grant a real MSAL speaks, real
WebAuthn ceremonies, a real SQLite directory. What is deliberately left out is
the **policy engine** — Conditional Access, MFA, Identity Protection — which is
what would turn a dev-loop emulator into an IdP.

**"Real via our own wire-protocol implementation."** A row is 🟢 **Real** not
only when real cryptography does the work, but also when the emulator itself
implements Entra's wire protocol and the logic behind it — so a real,
unmodified client (MSAL in five languages, the Graph SDK, a SCIM connector)
gets byte- and behaviour-identical responses.

:::note[Absent means 404, not 501]
This emulator has **no `501` stubs**: a feature that isn't implemented simply
has no route, so a client sees a **404**. A 🔴 below therefore means "absent",
not "honestly refused". Likewise 🟠 means *"real when you attach a real engine"*
— where a toy fallback ships instead, the row says so.
:::

## Legend

| | Meaning |
|---|---|
| 🟢 **Real** | Genuine work: real signed JWTs, real crypto, real state, real logic enforced — no pretending. |
| 🟡 **Emulated** | Faithful API contract + persisted state, but no engine — clock-derived or management-only. |
| 🟠 **Bring-your-own-engine** | Real when you attach a real external engine; a toy or companion stands in otherwise. |
| 🔴 **Not implemented** | Absent (404). |

## Token service (`07-token-service`)

| Entra feature | Emulator | Type |
|---|---|---|
| RS256-signed access / ID tokens | Real compact JWS over `crypto/rsa` — real 2048-bit keys, real signatures any validator accepts | 🟢 Real |
| `kid` / JWKS | RFC 7638 JWK thumbprint; JWKS publishes active **and** retired-but-unexpired keys | 🟢 Real |
| Signing-key rotation | Real: new active key, old retired but still served until it expires, mutex-guarded signer swap | 🟢 Real |
| Entra v2.0 claim shapes (`tid`/`oid`/`azp`/`appid`/`scp`/`roles`/`ver`/`idtyp`, pairwise `sub`) | Full | 🟢 Real |
| `amr` (`pwd` / `fido`) | Threaded from the actual grant used | 🟢 Real |
| `wids` (directory-role template GUIDs) | Emitted, gated on `groupMembershipClaims` | 🟢 Real |
| Optional claims + **group overage** (`_claim_names` / `_claim_sources`) | Real Entra overage payload above the limit; protocol claims non-overridable. The `_claim_sources` endpoint is **live**, not decorative: `getMemberObjects` / `getMemberGroups` are served, so a client that follows the pointer really recovers the group list the token could not carry | 🟢 Real |
| Token signing algorithm | RS256 only — which is **exactly what real Entra v2.0 advertises** (`id_token_signing_alg_values_supported: ["RS256"]`, captured in `e2e/golden/`). ES256/PS256 are absent from Entra too, so there is no gap to close: adding them would *diverge*, not converge | 🟢 Real |

## OIDC / OAuth2 endpoints (`08-oidc-endpoints`)

| Entra feature | Emulator | Type |
|---|---|---|
| OIDC discovery + JWKS | Full, conformance-tested against the real Entra discovery document | 🟢 Real |
| **Instance discovery** (`/common/discovery/instance`) | Served — MSAL calls it before every token request, and a 404 fails the whole login | 🟢 Real |
| **User realm probe** (`/common/UserRealm/{user}`) | Served, always `Managed` — the emulator holds every credential it can verify, so claiming `Federated` would send a client to an IdP that does not exist. MSAL Go probes this **before** it will attempt a username/password request and gives up on a non-200, so without it ROPC is unreachable from that SDK | 🟢 Real |
| `authorization_code` + **PKCE** (S256/plain) | Real, with atomic single-use code consumption. Narrowing on exchange resolves the client's scope vocabulary before comparing — a request for `api://<app>/<scope>` matches the short name the grant stored — and the response echoes the client's own strings, because MSAL treats a requested scope missing from the response as declined. The OIDC protocol scopes every MSAL appends unconditionally are tolerated rather than counted against the grant | 🟢 Real |
| `refresh_token` | Real rotation, plus **family revocation on reuse** — replaying a rotated token kills the whole chain. Narrowing and the scope echo behave as on the code exchange | 🟢 Real |
| `client_credentials` | Real; `.default` only, tolerating the stray scopes MSAL-Go/azidentity send | 🟢 Real |
| `password` (ROPC) | Real scrypt verification → `amr:["pwd"]`; the user-realm probe MSAL Go requires first is served too | 🟢 Real |
| `urn:ietf:params:oauth:grant-type:jwt-bearer` (on-behalf-of) | Real; enforces assertion audience, rejects app-only assertions, and carries the user through to the downstream token. The response echoes the scopes **as the client asked for them** rather than the short names — MSAL Go treats a requested scope missing from the response as declined and fails the acquisition | 🟢 Real |
| Device code (spec form **and** the bare `device_code` msal-node sends) | Real, with an atomic approve→mint step that closes the double-mint window | 🟢 Real |
| `private_key_jwt` client assertion | Real: assertion verified against the app's registered certificate, advertised in `token_endpoint_auth_methods_supported` so a spec-driven client actually attempts it. Both **RS256 and PS256** are accepted — MSAL Go signs client assertions with PS256 by default, so RS256-only verification refuses Microsoft's own Go client. `none` and the HMAC algorithms are refused | 🟢 Real |
| RP-initiated logout (`end_session_endpoint`) | Real: clears the SSO session and honours a **validated** `post_logout_redirect_uri` + `state`; advertised via `http_logout_supported` | 🟢 Real |
| Front-channel logout (OP calls each RP's `frontchannel_logout_uri`) | Real: apps register a logout URI, the emulator records which apps each SSO session signed into, and logout renders one hidden iframe per **signed-into** RP carrying `iss` and `sid`. Apps the session never used are deliberately not notified. Now advertised, because it now happens | 🟢 Real |
| Implicit / hybrid flow | Real: `response_type=id_token` and `code id_token` mint a genuine signed ID token at the authorize endpoint, delivered by fragment or form_post with the nonce echoed. OIDC's rules are enforced — a nonce is required, `response_mode=query` is refused for an id_token, and PKCE is demanded only when a code is actually issued. `id_token token` is not implemented and so is not advertised | 🟢 Real |
| **mTLS / PoP / certificate-bound tokens** | — | 🔴 Not implemented |
| JAR by reference (`request_uri`, RFC 9101) | Real: the signed request object is fetched, verified against the app's **registered keys**, and its parameters override the query — and the fetch is SSRF-guarded, reaching only origins the tenant already trusted as this app's redirect URIs, with no redirects followed and the body size- and time-capped. **Deliberate divergence, not parity:** Entra answers `request_uri_parameter_supported: false`, so this capability exists here and not there — code that relies on it will fail against Entra. Recorded in the golden reference and watched by `scripts/check_golden_drift.py` | 🟢 Real |
| Inline `request` parameter | Refused — and **not an Entra feature either**: the real discovery document leaves `request_parameter_supported` absent, which per OIDC means false. Implementing it would diverge, not converge | 🟢 Real |
| PAR (pushed authorization requests) | Not implemented — and **not an Entra feature either**: the real discovery document advertises no `pushed_authorization_request_endpoint`, so this is parity, not a gap | 🟢 Real |
| **CAE** (continuous access evaluation) | — | 🔴 Not implemented |
| Token lifetime policies | Real and load-bearing: `policies/tokenLifetimePolicies` plus the `$ref` assignment onto an application, parsed from Entra's own JSON-inside-a-string `definition` with .NET `[d.]hh:mm:ss` durations. An assigned policy (or `isOrganizationDefault`) changes the **`exp` of the tokens actually minted**, and a definition that would be silently inert is refused | 🟢 Real |
| **Claims-mapping policies** | Not implemented as a policy resource. Per-app claim shaping is available instead through `optionalClaims`, `groupMembershipClaims`, and custom authentication extensions | 🔴 Not implemented |

## Microsoft Graph (`09-graph-api`)

| Entra feature | Emulator | Type |
|---|---|---|
| Directory reads (`/me`, users, groups, members, `memberOf`, `userinfo`) | Full, over the real store | 🟢 Real |
| Directory **writes** (users, groups, applications; group membership `$ref`) | Full CRUD, persisted | 🟢 Real |
| Recycle bin (`directory/deletedItems`, restore, permanent delete) | Real state machine; the 30-day window is **clock-derived**, so it's testable | 🟡 Emulated |
| OAuth2 permission grants (consent) | Stored **and load-bearing**: consented scopes are intersected into the token's `scp`, honouring `AllPrincipals` vs per-principal | 🟢 Real |
| Directory roles (`roleManagement/directory`) | Full CRUD, and assignments really drive `wids` in tokens | 🟢 Real |
| Authentication methods inventory (password / FIDO2) | Read + delete | 🟡 Emulated |
| `getMemberObjects` / `getMemberGroups` | Served for `/users/{id}` and `/me`. This is the endpoint the group-overage `_claim_sources` points at, so it is what makes that payload recoverable rather than a dangling pointer. The directory has no nested groups, so direct membership is the transitive closure; `getMemberObjects` additionally returns directory-role template ids | 🟢 Real |
| OData `$select` / `$filter` / `$top` / `$skiptoken` / `$count` | Supported (single `$filter` clause) | 🟢 Real |
| Graph permission enforcement (scopes/roles gating operations) | Real gate behind `GRAPH_PERMISSIONS`: delegated calls need the scope in `scp`, app-only calls the role in `roles`, `Directory.*` acts as the superset, denials are `403 Authorization_RequestDenied`. **Off by default** — the emulator has always accepted any valid Graph-audience token, so enabling it is opt-in | 🟢 Real |
| Separate servicePrincipal store | An app registration **is** its own SP; object `id` and `appId` are conflated | 🟡 Emulated |
| Custom role definitions | Real CRUD over `roleManagement/directory/roleDefinitions`: tenant-authored roles list beside the built-ins, are assignable, and deleting one cascades to its assignments. Built-ins are protected from modification, and custom roles are **excluded from `wids`** — real Entra emits built-in role *template* GUIDs there only | 🟢 Real |
| Administrative units | Real CRUD over `directory/administrativeUnits` plus membership of both users and groups (each returned with its own `@odata.type`), `Public`/`HiddenMembership` visibility, a dangling member refused, and FK-cascade so deleting a unit takes its memberships with it | 🟢 Real |
| Custom security attributes | Real: attribute sets and `String`/`Integer`/`Boolean` definitions (id is Entra's `{set}_{name}` composite), assigned onto users with the declared **type enforced** — an Integer attribute refuses a string and a scalar refuses a collection slot. Returned only on explicit `$select`, exactly as Graph does | 🟢 Real |
| **Graph `beta` endpoint** | v1.0 only | 🔴 Not implemented |
| Sign-in logs (Graph `auditLogs/signIns`) | Real: served over the flow recorder, so every row is an exchange that actually happened. The recorder now carries the **user each exchange resolved**, so a delegated row names `userId`/`userPrincipalName` while an app-only row is userless (correct, not missing); failures carry their concrete reason and every row has a stable id to de-duplicate on. `conditionalAccessStatus` is always `notApplied` — there is no CA engine, by design | 🟢 Real |
| Directory audit logs (Graph `auditLogs/directoryAudits`) | Real: every mutation through the Graph write surface is journaled with its activity, category, target resource, and the caller it is attributed to (an app-only caller reports no user, which is correct rather than missing). The emulator's own admin API is a control surface with no Entra equivalent, so its mutations are deliberately not journaled | 🟢 Real |

## SCIM 2.0 (`10-scim-provisioning`)

| Entra feature | Emulator | Type |
|---|---|---|
| SCIM **service provider** (inbound): `ServiceProviderConfig`, `ResourceTypes`, `Schemas`; Users + Groups CRUD, PatchOp | Real RFC 7643/7644 shapes over real HTTP, bearer static-secret auth as Entra does | 🟢 Real |
| SCIM **provisioning client** (outbound): filter-probe → create / update / `active:false` deprovision, member-correlated groups, incremental watermark | Real — the emulator pushes the directory out using Entra's actual sequence | 🟢 Real |
| Provisioning **scheduler** (the ~40-minute cycle) | Admin-triggered instead of timed — deliberate, so tests are deterministic | 🟡 Emulated |
| `PUT /Groups/{id}` | Real RFC 7644 §3.5.1 wholesale replace — `displayName` overwritten and membership reconciled to exactly the submitted set (absent members removed) | 🟢 Real |

## Sign-in experience

| Entra feature | Emulator | Type |
|---|---|---|
| Passkey / WebAuthn sign-in | Real ceremonies (real assertion verification, real CBOR/COSE); RP derived per-request from the Host, so passkeys work on any origin; drives `amr:["fido"]` | 🟢 Real |
| Attestation policy / AAGUID allowlists / cross-device CTAP | Stated non-goals | 🔴 Not implemented |
| **MFA / step-up authentication** | — | 🔴 Not implemented |
| **Conditional Access** (policies, named locations, auth strengths) | — the line the project deliberately doesn't cross | 🔴 Not implemented |
| **Identity Protection / risky users** | — | 🔴 Not implemented |
| Password reset (Graph `authentication/passwordMethods/{id}/resetPassword`) | Real: the new password is scrypt-hashed into the directory, so the old credential immediately stops signing in and the new one works. Omitting `newPassword` returns a system-generated one in Entra's `passwordResetResponse` shape, with `202` + `Location` as Graph answers this long-running operation | 🟢 Real |
| **Interactive SSPR** (verify by email / SMS / security questions at `passwordreset.microsoftonline.com`) | Not implemented — it is a first-party web flow, not a documented protocol, so emulating it would mean inventing a wire format rather than reproducing one | 🔴 Not implemented |
| **SAML 2.0 SP-initiated SSO** | Real: an AuthnRequest by either binding, a signed assertion posted back. The assertion is signed with the tenant's own RSA key under exclusive c14n, carries AudienceRestriction, Recipient, InResponseTo and a five-minute window, and the reply URL is validated against the app's registered `saml-acs` endpoints rather than taken from the request. IdP metadata at Entra's own path publishes the same key as an X.509 certificate | 🟢 Real |
| **WS-Federation** | Not implemented. SAML's sibling, and reachable from the same signing path, but nothing drives it yet | 🔴 Not implemented |
| **B2C user flows / External ID / CIAM** | — stated non-goal | 🔴 Not implemented |
| B2B guest invitations | Real: `POST /invitations` creates an actual directory user with Entra's external shape — `#EXT#` UPN, `userType: Guest`, `externalUserState: PendingAcceptance` — and the returned redeem link flips that state to `Accepted` and redirects to the inviting app. Members keep `userType: Member` with a null external state | 🟢 Real |
| **Cross-tenant access policies** (partner settings, inbound/outbound trust) | — | 🔴 Not implemented |

## Workload & platform identity

| Entra feature | Emulator | Type |
|---|---|---|
| **Managed identity** (`/msi/token`, App Service protocol) | Real — `azidentity`'s ManagedIdentityCredential gets a real token | 🟢 Real |
| Fabric-audience tokens + workspace identity (app reg + SP + managed credential, state machine, cascade delete) | Real at the token layer | 🟢 Real |
| Fabric **control plane** | Out of scope by design — the companion `fabric-emulator` serves it | 🟠 BYO-companion |
| **Workload identity federation** (`federatedIdentityCredential`) | Real token exchange: an external workload presents ITS OWN OIDC token as the `client_assertion` and the emulator matches a registered issuer/subject/audience trust, then **verifies the signature against keys fetched from that issuer's published JWKS** — no secret exists anywhere, which is the whole point. Expiry, wrong subject, wrong audience, forged signature and revoked credential are each refused. Managed through the admin API (`/admin/api/apps/{id}/federated-credentials`) rather than the Graph `federatedIdentityCredentials` route | 🟢 Real |
| Graph route for `federatedIdentityCredentials` | Real CRUD on `applications/{id}/federatedIdentityCredentials`, writing the **same rows the token endpoint matches** — a trust created here immediately authenticates an external workload, PATCHing its subject changes who can, and DELETE revokes it. (Applications are addressed by the conflated object id / appId, as on every `/applications` route) | 🟢 Real |
| **Device registration / Intune compliance / device-bound tokens** | — | 🔴 Not implemented |
| **Application Proxy** | — | 🔴 Not implemented |
| **PIM / privileged access**, **entitlement management**, **access reviews** | — | 🔴 Not implemented |
| **Group writeback / hybrid sync (AD Connect)** | — | 🔴 Not implemented |

## Authorization beyond the token

| Entra feature | Emulator | Type |
|---|---|---|
| Externalized authorization (fine-grained, relationship-based) | A PDP **port**: real engines attach — OpenFGA, SpiceDB, Keto, Permify, Casbin, OPA, Cedar, all exercised in CI. A ~50-line `InMemoryPDP` ships so the sample runs with nothing attached; it is explicitly *not* a real engine | 🟠 BYO-engine |
| Custom authentication extensions (token-issuance webhook callout) | Real callout — you bring the endpoint | 🟠 BYO-engine |

## Directory, storage & transport

| Entra feature | Emulator | Type |
|---|---|---|
| Persisted directory | Real SQLite (WAL, foreign keys, forward-only migrations) | 🟢 Real |
| Credential hashing | Real scrypt for passwords/secrets; SHA-256 for refresh/device codes | 🟢 Real |
| Concurrency contracts (single-use codes, refresh-reuse detection, device-code approve→mint) | Real atomic SQL — not best-effort | 🟢 Real |
| Multi-tenant | Multiple tenants exist and are isolated | 🟡 Emulated |
| TLS with a wildcard cert over the emulator's origins | Real self-signed X.509, regenerated on SAN drift, stable fingerprint otherwise | 🟢 Real |
| CORS on the OIDC surface | Real: discovery, JWKS and instance discovery reflect the caller's `Origin` and `Vary` on it; the **token endpoint is gated exactly as Entra gates it** — CORS only for an origin the application registered as an `spa` redirect URI, so an app that works here will not fail against real Entra. Preflight answers with the telemetry headers MSAL.js sends. Without any of this, **no browser SPA can authenticate at all** | 🟢 Real |
| Cloud-instance metadata (`tenant_region_scope`, `cloud_instance_name`, `cloud_graph_host_name`, `msgraph_host`, `rbac_url`) | Advertised in discovery, pointing at the emulator's **own** origins — a client that reads them is never sent to the real cloud | 🟢 Real |
| **Sovereign clouds** (US Gov / China / Germany instance routing) | Single local instance only | 🔴 Not implemented |

## Emulator-only (no Entra equivalent — these exist for testing)

| Feature | Purpose |
|---|---|
| Token forge (`/admin/api/tokens`) | Mint arbitrary claims, negative expiry, or a deliberately invalid signature — test your validator's failure paths |
| Clock control (`/admin/api/clock`) | Freeze/advance — makes token expiry and the 30-day recycle bin deterministic |
| Fault injection (`/admin/api/faults`) | Forced token errors, latency, probabilistic flakiness |
| Audit trail (`/admin/api/audit`) | Every authorize/token exchange, for assertions |
| Export / import | Snapshot a directory; deliberately excludes signing keys and live grants |
| Admin portal | Inspect and drive the directory in a browser |

## Ecosystem conformance: real clients as witnesses

The bar: **real clients, unmodified**. Two knobs make them work — instance
discovery disabled per-SDK, and TLS trust injected per-SDK.

| Real client (pinned) | Surface exercised | Status |
|---|---|---|
| `@azure/msal-node` | client_credentials, auth code + PKCE, refresh, device code; `client_info` account identity, `nonce`, `ver:"2.0"` | 🟢 CI `sdk-e2e` |
| `@microsoft/microsoft-graph-client` | Through the SDK's own pipeline: user CRUD, role assignment, consent grant, app-role assignment, auth methods, recycle-bin round-trip | 🟢 CI `sdk-e2e` |
| MSAL **Go** + **`azidentity`** | client_credentials, device code, `ClientSecretCredential`, **ManagedIdentityCredential**, embedded-library mode | 🟢 CI `sdk-e2e` |
| MSAL **Python** | client_credentials, device code | 🟢 CI `sdk-e2e` |
| **MSAL.NET** (`Microsoft.Identity.Client`) | client_credentials + token-cache hit, app-only claim shape | 🟢 CI `sdk-e2e` |
| **msal4j** (Java) | client_credentials, with the emulator cert in a real trust store | 🟢 CI `sdk-e2e` |
| OpenFGA · SpiceDB · Keto · Permify · Casbin · OPA · Cedar | The PDP port against real engines | 🟢 CI `pdp-compat` (7-way matrix) |
| Flutter (`http`, `flutter_appauth`) | Device code on real Android/iOS | 🟡 Nightly, not a PR gate; the auth-code leg is a manual screen |
| **`@azure/msal-browser`** | Real browser (Playwright + Chromium) completing the auth-code + PKCE redirect flow against the emulator | 🟢 CI `browser-e2e` |
| Chromium `navigator.credentials` | Passkey register + assert on the emulator origin (CDP virtual authenticator); ID token `amr:["fido"]` | 🟢 CI `passkey-e2e` |
| fabric-emulator (workspace-identity handshake) | Provision / mint / rename / deprovision / cascade-delete against this entra via `go.mod` replace | 🟢 CI `fabric-e2e` |
| Chromium implicit / hybrid | Front-channel `id_token` and `code id_token` redirects (msal-browser cannot emit these) | 🟢 CI `implicit-e2e` |
| Azure CLI (`az`) | `az cloud register` + `az login --service-principal`; Graph and ARM audience tokens | 🟢 CI `az-cli-e2e` |

### Contract conformance: golden references as witnesses

Real clients prove the emulator *works*; **golden references** prove its wire
contracts haven't **drifted**. Three canonical references — the real Entra OIDC
discovery document, the official Microsoft Graph OpenAPI, and the SCIM 2.0 RFCs
— are committed under `e2e/golden/` and diffed against the live emulator on
every push. Several 🟢 rows above name those tests as their witness
(`TestGoldenParityOIDCDiscovery`, `TestGoldenParityGraph`,
`TestGoldenParitySCIM`). See
[golden-reference parity](19-golden-reference-parity.md) for what each asserts
and the documented divergences it reports.

## Scope boundary: a dev-loop emulator, not an IdP

The line is drawn by one question: does this need a policy engine, a risk
model, or a tenant's compliance posture? Everything above it can be **real**,
because none of it needs any of the three. A token this emulator signs is a
real token; a passkey it verifies is really verified; an assertion it signs is
signed with the same key and verifies in an unmodified service provider.

MFA, Conditional Access and Identity Protection fail that question and stay
out. Crossing to them would change the project's character from *"the identity
provider your tests run against"* to *"an identity provider"*, which is a
different product with a different duty of care.

**SAML was on the wrong side of this line and has moved.** It answers the
question the same way a token does: a signed assertion needs no policy engine,
and the emulator already had the key. The list of non-goals is not a fixed
boundary either, which is worth saying plainly — implicit flow, ROPC, OBO,
consent, certificate client auth and Graph writes were all once on it and are
now green rows. What has never moved is the criterion.
