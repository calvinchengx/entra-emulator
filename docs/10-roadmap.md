# 10 — Roadmap (post-parity)

Phase 0 is the core protocol surface (docs 02–08). Everything
below is sequenced *after* parity ships, ordered by value-for-effort.

Status legend: ✅ done · 🚧 in progress · ⬜ not started.

## Phase 1 — Go-native superpowers

The features only a Go implementation can offer; cheap and differentiating.

1. ✅ **Embeddable test library.** Public package so Go tests can run the emulator
   in-process: `emu := entraemulator.Start(t)` → returns issuer, JWKS URL, seeded
   client IDs/secrets, and a `*http.Client` trusting the emulator cert. Zero external
   processes for OIDC integration tests.
2. ✅ **Token forge.** `POST /admin/api/tokens` (+ library call): mint an arbitrary signed
   token — any user/app, scopes, roles, groups, custom expiry (including already
   expired), even deliberately malformed claims — without running a flow. Resource-API
   teams get "a token with `scp=Tasks.Read` that expired 5 min ago" in one curl.
3. ✅ **Managed-identity endpoint.** Emulates the App Service / Functions / Container
   Apps managed-identity protocol: `GET /msi/token?resource=<r>&api-version=…` guarded
   by the `X-IDENTITY-HEADER` secret, returning the App Service token JSON
   (`access_token`, `expires_on`, `resource`, `token_type`, `client_id`). A workload
   sets `IDENTITY_ENDPOINT=<origin>/msi/token` + `IDENTITY_HEADER=<secret>` and
   `azidentity.ManagedIdentityCredential` / `DefaultAzureCredential` acquires an
   app-only token with **no secret in the app** — exactly the production experience.
   Backed by the existing app-only minting; the identity maps to a designated seed
   service principal (system-assigned, default the daemon app) or a
   `client_id`/`object_id`/`mi_res_id`-selected one (user-assigned). We emulate the
   **env-var endpoint**, not raw IMDS (`169.254.169.254` is link-local and can't be
   redirected without network shims). Proven by an `azidentity` e2e test.
   Ref: `entra-docs/docs/identity/managed-identities-azure-resources/how-to-use-vm-token.md`.
4. ✅ **Distribution.** ~13 MB distroless Docker image (pure-Go, no cgo) with a
   built-in HEALTHCHECK, GHCR publish on tag, and GoReleaser cross-platform binaries
   (linux/darwin/windows × amd64/arm64). CI smoke-tests the image on every push.
   (Homebrew tap still open.)

## Phase 2 — Testing ergonomics beyond the real Entra

5. ✅ **Fault injection.** Admin-togglable failure modes on the token endpoint:
   force a chosen OAuth error (`temporarily_unavailable`→503, `invalid_grant`, …),
   inject latency, and make it intermittent via `probability`. Controlled through
   `GET/POST/DELETE /admin/api/faults`; in-memory. (Unknown-`kid` / key-rotation
   faults fold into roadmap #14.)
6. ✅ **Clock control.** Controllable clock (offset / advance / freeze / reset) wired
   into every emulator timestamp via `Store.Now`; `GET/POST/DELETE /admin/api/clock`.
   Advancing past a token's lifetime expires it with no real sleep.
7. ✅ **Directory import/export.** `GET /admin/api/export` / `POST /admin/api/import`
   dump/replace the directory (users, groups + memberships, apps + sub-resources) as a
   JSON fixture. Hashes preserved so a round-trip keeps auth; signing keys + live grants
   excluded. Shareable, versionable CI states.
8. ✅ **Flow audit trail.** Every authorize/token exchange recorded with its concrete
   accept/reject reason (OAuth `error` + `error_description`), including
   redirect-delivered authorize errors and injected faults. `GET/DELETE /admin/api/audit`;
   in-memory ring buffer. Turns "why won't MSAL sign in" into reading a log.
   (Portal surfacing still open.)

## Phase 3 — Protocol surface parity-plus

Deeper Microsoft identity platform coverage:

9. ✅ **On-Behalf-Of (OBO)** — `grant_type=jwt-bearer` + `requested_token_use=on_behalf_of`.
   A middle-tier exchanges a user token (aud=itself) for a downstream token preserving
   the user; enforces the assertion-aud rule and rejects app-only assertions. Advertised
   in discovery. (Cert `client_assertion` deferred to #13.)
10. ✅ **Custom authentication extensions** — `onTokenIssuanceStart` webhook per app:
    during delegated minting the emulator POSTs the Microsoft-documented
    `onTokenIssuanceStartCalloutData` shape and merges the returned
    `provideClaimsForToken` claims (optional allowlist). Faithful semantics:
    timeout-and-continue (~2 s default, token issued unenriched on failure/timeout),
    protocol claims never overridable, callout carries an emulator-minted system
    bearer. `GET /admin/api/custom-extensions`, `PUT/DELETE
    /admin/api/apps/{id}/custom-extension`. 4 integration tests (merge, protocol-claim
    protection, allowlist, timeout-and-continue).
    Ref: `entra-docs/docs/identity-platform/custom-extension-tokenissuancestart-*`.
11. ✅ **Passkey (FIDO2/WebAuthn) sign-in method** — register + assert ceremonies
    (`go-webauthn/webauthn`) at `/{tenant}/webauthn/{register,assert}/{begin,finish}`,
    a `webauthn_credentials` table, admin management (`GET/DELETE
    /admin/api/users/{id}/passkeys`), and `amr: ["fido"]` threaded session → auth code
    → ID token. The relying party is built **per request from the Host header**, so a
    passkey works on any origin the emulator serves (no static RP config). Browserless
    integration tests use a virtual authenticator (`descope/virtualwebauthn`) —
    full register → assert → SSO → amr chain. Non-goals: attestation policy, AAGUID
    allowlists, cross-device CTAP.
    Ref: `entra-docs/docs/identity/authentication/concept-authentication-passkeys-fido2.md`.
12. ✅ **ROPC** — `grant_type=password`: verifies user credentials, mints a delegated
    token (`amr:["pwd"]`, refresh when `offline_access`). Public or confidential
    clients; bad credential → `invalid_grant` (AADSTS50126). Advertised in discovery.
    4 integration tests. Deprecated in production but pragmatic for headless CI.
13. ✅ **`private_key_jwt` / certificate client authentication.** Apps register a PEM
    public key or X.509 cert (`GET/POST/DELETE /admin/api/apps/{id}/keyCredentials`);
    clients authenticate any grant with `client_assertion_type=jwt-bearer` +
    `client_assertion` (a JWT with `iss=sub=client_id`, `aud`=token endpoint/issuer,
    RS256-signed). Verified in `authenticateClient` against all registered keys.
    5 integration tests (happy path, wrong key, expired, wrong audience, no key).
14. ✅ **Signing-key rotation** — `POST /admin/api/signing-keys/rotate {graceSeconds}`
    generates a new active key and retires the previous one (JWKS keeps publishing it
    until `not_after`), so tokens already issued still verify during the grace window;
    `graceSeconds:0` drops the old key immediately. Signer swap is mutex-guarded
    (race-clean). 2 integration tests (grace cross-verify, no-grace drop).
15. ✅ **Consent + multi-tenant.** (a) ✅ **Optional consent screen** — `REQUIRE_CONSENT`
    gates a scope-consent page during authorize (Accept -> code, Cancel ->
    `access_denied`); 2 integration tests. (b) ✅ **Multi-tenant** directories — each
    tenant carries its own `tid`, GUID-form issuer (`{login}/{tid}/v2.0`), and lazily
    provisioned RS256 signing key; the token service threads the resolved tenant through
    id/access minting (`resolveTenant`/`issuerForTenant`/`signerForTenant`), and
    `tenantSegment` resolves the `{tenant}` path (home GUID + `common`/`organizations`/
    `consumers` aliases -> home, any other GUID -> that tenant if it exists, else 404).
    Per-tenant discovery + JWKS; apps can be registered in a non-home tenant
    (`tenantId` on create). Admin tenant CRUD (`/admin/api/tenants`) generates realistic
    metadata with gofakeit — `displayName` + `<slug>.onmicrosoft.com` initial domain.
    1 integration test proving isolation (tenant-B `client_credentials` -> `tid`=B,
    B-issuer, RS256-verifiable against B's JWKS with a distinct kid; home unchanged;
    unknown tenant rejected; home tenant undeletable).
16. ✅ **Fabric-flavored identities (Entra layer only).** The emulator issues the tokens a
    Microsoft Fabric environment relies on, without emulating Fabric itself:
    (a) ✅ recognizes the Fabric resource — `https://api.fabric.microsoft.com` and the legacy
    `https://analysis.windows.net/powerbi/api` (well-known first-party app id
    `00000009-0000-0000-c000-000000000000`) — so `client_credentials` with
    `<fabric>/.default` mints a correct-`aud` token (`fabricAud` maps the first-party app id
    to the canonical Fabric aud); (b) ✅ a **workspace-identity** object (`internal/store/
    fabric.go`) — an app registration + service principal with an emulator-managed
    credential and a linked workspace name/GUID, name-follows-workspace + cascade-delete +
    the Fabric state enum (`Active`/`Provisioning`/`Failed`/`Deprovisioning`); its tokens are
    minted internally like managed identity (#3) via `GET /fabric/workspaceidentities/{id}/
    token` — the caller never handles a credential, and only `Active` identities mint;
    (c) ✅ auto-consents delegated **Fabric scopes** (`Fabric.Embed`, `Item.Read.All`, plus
    resource-prefixed forms) with aud=Fabric, like the Graph carve-out. Admin CRUD at
    `/admin/api/workspace-identities` (gofakeit workspace name). 3 integration tests
    (CC aud for all three resource forms + JWKS verify; delegated carve-out; workspace-
    identity lifecycle: internal token, name-follows-rename, state gating, cascade delete).
    **Strict boundary:** Entra token layer only — the Fabric control plane (REST API,
    workspace RBAC, identity lifecycle orchestration, OneLake) is *out of scope* and belongs
    to the companion project ([12-fabric-companion.md](12-fabric-companion.md)). Composes with
    #2/#3. Refs: `fabric-docs/docs/security/workspace-identity.md`,
    `fabric-docs/docs/data-warehouse/service-principals.md`.

## Phase 4 — Broader Graph & samples

17. ✅ `/me/memberOf` (+ `/users/{id}/memberOf`) returning the user's groups as directory
    objects (`@odata.type`-tagged). Basic OData in `internal/graph/odata.go`: `$select`
    (projection, always keeps `id`; also on single entities), `$filter` (single clause —
    `field eq|ne 'v'|true|false`, `startswith`/`endswith(field,'v')`; malformed → 400),
    `$top`/`$skiptoken` paging (preserved), and `$count=true` (`@odata.count` = matches,
    post-filter). Filtering/projection run in-memory over shaped entities at emulator
    scale. 2 integration tests (memberOf delegated + app-only; select/filter/count/combined
    + bad-filter 400).
18. ✅ User/group/app **writes** through Graph (`internal/graph/writes.go`), backed by the
    same store as the portal admin API. Users: `POST /v1.0/users` (201, requires
    displayName + userPrincipalName, optional passwordProfile), `PATCH` (204, partial),
    `DELETE` (204). Groups: `POST`/`PATCH`/`DELETE /v1.0/groups`, plus membership via the
    `$ref` link shape — `POST /v1.0/groups/{id}/members/$ref` with `{"@odata.id": ".../
    directoryObjects/{userId}"}` and `DELETE .../members/{userId}/$ref`. Applications:
    `POST`/`PATCH`/`DELETE /v1.0/applications` (object id == appId — documented conflation).
    Store sentinels map to Graph errors (`ErrNotFound`→404 `Request_ResourceNotFound`,
    `ErrConflict`→400 `Request_BadRequest`). No permission enforcement (documented
    divergence). 3 integration tests (user CRUD + duplicate-UPN 400; group CRUD + `$ref`
    membership; application CRUD verified via admin read-back).
19. ✅ Service principals / `/applications` read surface (`internal/graph/reads.go`).
    `GET /v1.0/applications` + `/{id}` and `GET /v1.0/servicePrincipals` + `/{id}`, both
    honouring the basic OData options (`$select`/`$filter`/`$count`/paging) — e.g.
    `$filter=appId eq '<guid>'`. Applications expose `appRoles` and
    `api.oauth2PermissionScopes`; service principals add `servicePrincipalType`,
    `oauth2PermissionScopes`, and `servicePrincipalNames`. No separate SP store — each app
    registration is its own SP and the object id is conflated with `appId` (documented
    divergence). 2 integration tests (applications list/get/$filter/404 with role+scope
    assertions; servicePrincipals list/$count/get).
20. ✅ **Externalized authorization** (`samples/externalized-authz/`,
    [full guide](16-externalized-authorization.md)) — a Go resource API that validates
    emulator JWTs via JWKS (RS256 + `iss`/`aud`/`exp`, key cache with rotation refresh)
    then delegates fine-grained decisions to a `PDP` port, passing `user:<oid>` +
    `group:<gid>` derived from the token's `oid`/`groups`. Strict authN/authZ separation —
    the emulator only proves identity; no emulator features needed, consumed purely as a
    token issuer.
    - (a) ✅ **Sample.** Ships an in-memory OpenFGA-style tuple checker (`InMemoryPDP`) so
      it runs with zero external services. Part of the root module so CI covers it. 1
      end-to-end test (direct-grant allow, no-grant deny, group-derived allow, missing-token
      401, wrong-audience 401) using the admin token forge to mint the access tokens.
    - (b) ✅ **PDP compatibility suite** (`compat/`, `pdp_integration` tag, separate
      module). Proves the `PDP` port yields the same decision matrix — and the same
      end-to-end `200`/`403` — against **real** engines: [OpenFGA](https://openfga.dev)
      (ReBAC, via testcontainers) and [Casbin](https://casbin.org) (in-process). One
      canonical fixture, reused per engine; Keto/SpiceDB/OPA/Cerbos drop in as near-copies.
      CI-verified on every push by the `pdp-compat` matrix job.

## Phase 5 — SCIM provisioning

21. ✅ **SCIM 2.0 (RFC 7643/7644).** Emulate Entra's provisioning both ways
    ([full design](15-scim-provisioning.md)):
    - (a) ✅ **Service provider (server).** `/scim/v2/{Users,Groups}` over the directory —
      list + `userName eq` correlation filter + pagination, create, read, replace, PatchOp
      (soft-deprovision `active:false`, member add/remove), delete; bearer-secret auth;
      `application/scim+json` + ListResponse/Error schemas; discovery endpoints. Backed by
      the shared store, wired on the compat origin at `/scim`. 3 integration suites.
    - (b) ✅ **Provisioning client.** Admin-controlled outbound provisioning
      (`POST /admin/api/scim/{target,sync}`, `GET /admin/api/scim/log`): reconciles each
      user to a configured SCIM endpoint with Entra's request sequence — `GET` existence
      probe → `POST` create (new+active) / `PATCH active:false` (deprovision disabled) /
      `PATCH` attributes (update) — plus **member-correlated group** provisioning (each
      member's `userName` is probed to resolve the target's id), **true incremental** sync
      via an `updated_at` watermark (only changed users), a provisioning-request log, and
      a portal **"Provisioning"** view (configure target, run a cycle, stream the log).
      Verified by a stateful mock-target e2e (create, deprovision, member correlation,
      incremental) + portal tests.

## Explicit non-goals

SAML/WS-Fed, B2C user flows, MFA/Conditional Access emulation, production hardening.
These change the project's character from "dev-loop emulator" to "IdP".
