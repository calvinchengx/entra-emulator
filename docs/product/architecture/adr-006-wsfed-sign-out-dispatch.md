# ADR-006: Dispatch `wa=wsignout1.0` on existing `/{tid}/wsfed` (never mint; 302 to registered SignOutWreply)

## Status

Accepted — 15 Aug 2026 (feature `ws-fed-sign-out`)

Supersedes the **witness freeze** in [ADR-001](adr-001-grow-existing-federationmetadata.md) (“advertise sign-out; do **not** witness `wsignout1.0`”). ADR-001’s metadata decision (grow the existing FederationMetadata URL; both STS endpoints = `/{tid}/wsfed`; same cert) is unchanged.

## Context

v0.8.0 already advertises sign-out on `PassiveRequestorEndpoint` = `/{tid}/wsfed`. `handleWSFed` does **not** branch on `wa`. A live emulator session on `wa=wsignout1.0` can SSO-deliver a `wresult` (DISCUSS D12). That mints a token while Priya asked to sign out.

Spike (15 Aug 2026, `Microsoft.AspNetCore.Authentication.WsFederation` 8.0.19 `SignOutAsync`): the unmodified library **GET-redirects** to `TokenEndpoint` with `wa=wsignout1.0`, `wtrealm`, and `wreply` (first of `RedirectUri` / `SignOutWreply` / `Wreply`). **No `wresult`.** Multi-RP `wsignoutcleanup1.0` fan-out is the opposite direction (IdP → RP `RemoteSignOutPath`) and is **not** required for single-RP `SignOut`.

**Return URL trap:** if `SignOutWreply` is unset, `wreply` is the sign-in callback (`CallbackPath` / `Wreply`, e.g. `/signin-wsfed`). A **GET** there without POST `wresult` fails the RP handler. v0.8.0 `e2e/wsfed` registers only `/signin-wsfed`. Quality ranking unchanged from v0.8.0: auditability, interoperability, maintainability, protocol-surface safety; scale out of scope.

## Decision

1. **Same route.** Answer `GET|POST /{tid}/wsfed` with `wa=wsignout1.0` on the existing Identity WS-Fed adapter (same `audited("wsfed")` wrap). Do **not** add `/wsfed/signout`, do **not** alias onto `GET /{tid}/oauth2/v2.0/logout`, do **not** invent a WS-Fed-only cookie or a second process.

2. **Dispatch on `wa` before any mint.** `wa=wsignout1.0` takes the sign-out branch even when a session exists, even when a `wresult` body or signed picker Kind is also present. Sign-out **never** mints an RSTR / `wresult`. Empty `wa` and `wa=wsignin1.0` remain the v0.8.0 sign-in path. Any other non-empty `wa` is refused on the emulator (no token, no bounce).

3. **Session-end analog.** Reuse the existing shared SSO cookie end: `clearSession` plus forget session-app rows (same mechanism `handleLogout` already uses). Do **not** render OIDC front-channel logout iframes and do **not** fan out `wsignoutcleanup1.0` to other relying parties. Idempotent: repeating sign-out with no session still returns to a valid registered reply (or stays on the emulator if the request is unsafe).

4. **302 to a registered `wsfed-reply`.** Prefer the library-sent `wreply` when it is an **exact** URI of type `wsfed-reply` for the `wtrealm` app (`HasRedirectURIOfType`, never type-blind `HasRedirectURI`). If `wreply` is omitted, use a registered `wsfed-reply` for that app (not `saml-acs`, not `web`). Unknown/empty `wtrealm`, wrong-type, cross-app, or unregistered return → 4xx LOCAL EMULATOR HTML, **no** `Location` to the caller URL.

5. **Walking skeleton `SignOutWreply` (observable contract, same stranger).** Extend existing `e2e/wsfed` (ADR-005) in **DELIVER** — DISTILL asserts the ports; no second e2e project. The stranger already registers `wsfed-reply` via Admin `POST /admin/api/apps` (v0.8.0 `Program.cs`). This cut:

   - Registers **two** URIs of type `wsfed-reply` for `api://tasks-api`: the existing sign-in callback (`CallbackPath` / `Wreply`, example `https://rp.example.test/signin-wsfed`) **and** a distinct sign-out return (example `https://rp.example.test/wsfed-signed-out`).
   - Sets unmodified library `SignOutWreply` to that distinct URI. `CallbackPath` / `Wreply` stay the sign-in callback.
   - The distinct path **is not** `CallbackPath`, so the STS 302 GET is not treated as a WS-Fed sign-in message (spike trap). After the round-trip, `GET /secure` is unauthenticated (RP cookie is cleared by unmodified library `SignOut` on the Tasks API host, not by the emulator). Next `wsignin1.0` shows Pick an account.

   Crafter owns how the .NET host answers GET on the SignOutWreply path (must not be the token callback). DISTILL does not seed a second suite. Keep v0.8.0 sign-in green. Do not extend `e2e/dotnet`. Do not ship in-process-Go-only as the stranger.

6. **Audit.** Same recorder, `Flow=wsfed`, `ClientID=wtrealm`. When a session was ended, record the subject (Alice). Never persist raw `wresult`. Graph already treats `Flow=wsfed` as interactive (ADR-004).

## Alternatives considered

1. **Alias `wsignout1.0` onto OIDC `/{tid}/oauth2/v2.0/logout`** — Reuse one logout handler. **Rejected:** the locked stranger GET-redirects to metadata `TokenEndpoint` (`/{tid}/wsfed`), not `end_session_endpoint`. OIDC logout also uses type-blind `HasRedirectURI` for `post_logout_redirect_uri` and may render front-channel iframes — both violate WS-Fed allowlist and the multi-RP-cleanup Won't-have.

2. **New path `/{tid}/wsfed/signout` (or `/logout`)** — Obvious “sign-out URL.” **Rejected:** FederationMetadata already advertises `PassiveRequestorEndpoint` = `/{tid}/wsfed` (US-01). A second path would miss the unmodified library.

3. **New WS-Fed-only session cookie** — Isolate WS-Fed from OIDC/SAML. **Rejected:** US-03 requires the shared emulator session to end so the next `wsignin1.0` shows Pick an account. A second cookie would leave OIDC/SAML SSO intact and fake sign-out.

4. **In-process-Go-only as the stranger** — Fast, no library `SignOutWreply`. **Rejected:** SAML v0.6.0 lesson; KPI-1 is unmodified `WsFederation` `SignOut` in `e2e/wsfed`. Orchestrator locked this rejection.

5. **302 to the sign-in `wreply` (`/signin-wsfed`) without `SignOutWreply`** — Matches some DISCUSS examples. **Rejected:** spike measured GET `/signin-wsfed` without POST `wresult` fails the RP handler. Walking skeleton must register a distinct `wsfed-reply` as `SignOutWreply`.

6. **Fan out `wsignoutcleanup1.0` to other RPs** — Entra-shaped SLO. **Rejected:** spike: single-RP `SignOut` does not require it. DISCUSS D11 / story-map Release 2 keep it out.

## Consequences

### Positive

- Riskiest assumption (D12: live session mints on sign-out) is closed at the same port the library already calls.
- Maintainability: SAML/OIDC analog, not a second STS; session-end reuses `clearSession`.
- Interoperability: unmodified library `SignOut` + distinct `SignOutWreply`.
- Protocol-surface safety: same `wsfed-reply` allowlist as sign-in; errors stay on the emulator.
- Auditability: sign-out appears beside sign-in on the existing recorder.

### Negative

- `e2e/wsfed` must register two `wsfed-reply` URIs (sign-in callback + sign-out return). Operators of real RPs must set `SignOutWreply` (or equivalent) to a registered URI that is not `CallbackPath`.
- Identity’s WS-Fed adapter gains a `wa` branch (crafter owns structure). v0.8.0 freeze tests (`TestSignOutIsAdvertisedWithoutASignOutWitness` / `signOutForbiddenTrip`) are superseded when the witness exists — they must not keep forbidding the round-trip.
- OIDC front-channel logout to *other* apps is not triggered by WS-Fed sign-out in this cut (explicit Won't-have).
