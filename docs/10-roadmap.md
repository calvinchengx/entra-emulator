# 10 — Roadmap (post-parity)

Phase 0 is the faithful port of entra-local's protocol surface (docs 02–08). Everything
below is sequenced *after* parity ships, ordered by value-for-effort.

## Phase 1 — Go-native superpowers

The features only a Go implementation can offer; cheap and differentiating.

1. **Embeddable test library.** Public package so Go tests can run the emulator
   in-process: `emu := entraemulator.Start(t)` → returns issuer, JWKS URL, seeded
   client IDs/secrets, and a `*http.Client` trusting the emulator cert. Zero external
   processes for OIDC integration tests.
2. **Token forge.** `POST /admin/api/tokens` (+ library call): mint an arbitrary signed
   token — any user/app, scopes, roles, groups, custom expiry (including already
   expired), even deliberately malformed claims — without running a flow. Resource-API
   teams get "a token with `scp=Tasks.Read` that expired 5 min ago" in one curl.
3. **Distribution.** Cross-compiled release binaries (darwin/linux/windows, amd64/arm64),
   `FROM scratch` Docker image, Homebrew tap. All near-free with the Go toolchain.

## Phase 2 — Testing ergonomics beyond the real Entra

4. **Fault injection.** Admin-togglable failure modes: return chosen AADSTS errors,
   inject latency, serve an unknown `kid`, rotate the signing key mid-session, drop
   refresh tokens. Lets apps test failure handling that a real tenant can't reproduce
   on demand.
5. **Clock control.** Freeze/offset the emulator clock via config + admin API so token
   expiry and refresh logic are testable without sleeps.
6. **Directory import/export.** `GET /admin/api/export` / `POST /admin/api/import`
   dumping the whole directory as a JSON fixture — shareable, versionable CI states.
7. **Flow audit trail.** Record every authorize/token exchange with the concrete
   accept/reject reason ("PKCE verifier mismatch", "redirect_uri not registered");
   expose via admin API and the portal. Turns "why won't MSAL sign in" into reading a log.

## Phase 3 — Protocol surface parity-plus

Upstream entra-local's own deferred roadmap, adopted here:

8. **On-Behalf-Of (OBO)** — the biggest real-world gap for multi-tier APIs.
9. **Custom authentication extensions** — emulate the `onTokenIssuanceStart` webhook
   (per-app endpoint config; POST the Microsoft-documented request shape during
   minting; merge returned claims). Model the real semantics faithfully:
   timeout-and-continue (~2 s cap, token issued unenriched on failure), protocol
   claims never overridable, webhook authenticated with an emulator-minted system
   token. Lets developers build custom claims providers entirely locally.
   Ref: `entra-docs/docs/identity-platform/custom-extension-overview.md`.
10. **Passkey (FIDO2/WebAuthn) sign-in method** — WebAuthn register + assert
    ceremonies on the sign-in page (`go-webauthn/webauthn`), a `webauthn_credentials`
    table, admin/portal management, `amr: ["fido"]` in ID tokens. RP ID =
    `entra.localhost` (trusted cert becomes a hard prerequisite); CI via Playwright's
    CDP virtual authenticator. Non-goals: attestation policy, AAGUID allowlists,
    cross-device CTAP. Ref:
    `entra-docs/docs/identity/authentication/concept-authentication-passkeys-fido2.md`.
11. **ROPC** — deprecated in production, but pragmatic for headless CI sign-ins.
12. **`private_key_jwt` / certificate client authentication.**
13. **Signing-key rotation** — multiple keys in JWKS, admin-triggered rollover.
14. **Optional consent screen** (currently auto-consent), then **multi-tenant**
    directories (`tid` per tenant) last — it touches everything.

## Phase 4 — Broader Graph & samples

15. `/me/memberOf`, basic OData (`$select`, `$filter`, `$top`, `$count`).
16. User/group/app **writes** through Graph (portal already covers admin writes).
17. Service principals / `/applications` read surface.
18. **Externalized-authorization sample** — a Go resource API validating emulator JWTs
    via JWKS, then calling a third-party PDP (e.g. OpenFGA) with `oid` + `groups` for
    fine-grained decisions. No emulator features needed — pure `samples/` teaching
    material for the Entra-authenticates / external-service-authorizes pattern.

## Explicit non-goals

SAML/WS-Fed, B2C user flows, MFA/Conditional Access emulation, production hardening.
These change the project's character from "dev-loop emulator" to "IdP", and upstream
excludes them too.
