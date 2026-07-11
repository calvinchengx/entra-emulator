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
15. ⬜ **Optional consent screen** (currently auto-consent), then **multi-tenant**
    directories (`tid` per tenant) last — it touches everything.
16. ⬜ **Fabric-flavored identities (Entra layer only).** Make the emulator issue the
    tokens a Microsoft Fabric environment relies on, without emulating Fabric itself:
    (a) recognize the Fabric resource — `https://api.fabric.microsoft.com` and the legacy
    `https://analysis.windows.net/powerbi/api` (well-known first-party app id
    `00000009-0000-0000-c000-000000000000`) — so `client_credentials` with
    `<fabric>/.default` mints a correct-`aud` token; (b) a **workspace-identity** object
    (an app registration + service principal variant with an emulator-managed credential
    and a linked workspace name/GUID, name-follows-workspace + cascade-delete + the Fabric
    state enum), its tokens minted internally like managed identity (#3) — the caller
    never handles a credential; (c) auto-consent delegated **Fabric scopes**
    (`Fabric.Embed`, `Item.Read.All`) like the Graph carve-out. **Strict boundary:** this
    is the Entra token layer only — the Fabric control plane (REST API, workspace RBAC,
    identity lifecycle orchestration, OneLake) is *out of scope* and belongs to the
    companion project ([12-fabric-companion.md](12-fabric-companion.md)). Composes with
    #2/#3. Refs: `fabric-docs/docs/security/workspace-identity.md`,
    `fabric-docs/docs/data-warehouse/service-principals.md`.

## Phase 4 — Broader Graph & samples

17. ⬜ `/me/memberOf`, basic OData (`$select`, `$filter`, `$top`, `$count`).
18. ⬜ User/group/app **writes** through Graph (portal already covers admin writes).
19. ⬜ Service principals / `/applications` read surface.
20. ⬜ **Externalized-authorization sample** — a Go resource API validating emulator JWTs
    via JWKS, then calling a third-party PDP (e.g. OpenFGA) with `oid` + `groups` for
    fine-grained decisions. No emulator features needed — pure `samples/` teaching
    material for the Entra-authenticates / external-service-authorizes pattern.

## Explicit non-goals

SAML/WS-Fed, B2C user flows, MFA/Conditional Access emulation, production hardening.
These change the project's character from "dev-loop emulator" to "IdP".
