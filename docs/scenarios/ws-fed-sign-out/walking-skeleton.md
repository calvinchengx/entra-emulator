# Walking skeleton — ws-fed-sign-out

> Archived copy at finalize (15 Aug 2026) from `docs/feature/ws-fed-sign-out/distill/walking-skeleton.md`.  
> Architecture SSOT: `docs/product/architecture/`. Journeys: `docs/product/journeys/`. Gherkin: `tests/acceptance/ws-fed-sign-out/`.  
> DISTILL-time “enabled / `@pending` / first scenario RED” rows are historical. All 10 DELIVER steps completed; KPI-1 stranger is `python3 e2e/run.py wsfed` including SignOut.

**Feature ID:** `ws-fed-sign-out`  
**Date:** 15 Aug 2026  
**Strategy:** C (Real local) — DWD-01

## One-liner

After Alice completes v0.8.0 WS-Fed sign-in, unmodified `Microsoft.AspNetCore.Authentication.WsFederation` `SignOut` drives `wa=wsignout1.0` to the advertised `PassiveRequestorEndpoint`. The emulator does not mint a `wresult`. The browser returns to registered `https://rp.example.test/wsfed-signed-out`. Alice's emulator session is gone. The next `wsignin1.0` shows Pick an account.

## What it proves

A developer-as-user (Priya Chen) can accomplish the job: point the same ASP.NET WS-Fed Tasks API at this emulator and complete sign-out the way she completes sign-in. It is not a layer-connectivity check.

Stories in the slice: **US-01 + US-02 + US-03**. KPI-1 (`e2e/wsfed` SignOut) is the same cut but **pending until DELIVER** extends `e2e/wsfed`. Refuse-unsafe (US-06–US-08) is Release 1 Must Have, separately demonstrable. US-04 audit and US-05 guardrails are focused scenarios.

## Scenarios

| # | Scenario | Env | Tags | Enabled? |
|---|---|---|---|---|
| 1 | Priya signs Alice out of the Tasks API on a clean emulator | clean | `@walking_skeleton @real-io @driving_adapter @driving_port` | **Yes** (first) |
| 2 | Priya signs Alice out alongside existing OIDC and SAML | with-pre-commit | same | `@pending` |
| 3 | Priya signs Alice out after registering a distinct sign-out return on a stale directory | with-stale-config | same | `@pending` |
| 4 | Priya's unmodified WsFederation middleware completes SignOut | clean + stranger | `@kpi @walking_skeleton` (KPI-1) | `@pending` until DELIVER extends `e2e/wsfed` |

Feature file: `tests/acceptance/ws-fed-sign-out/walking-skeleton.feature`

## Driving ports exercised

1. `GET /{tid}/federationmetadata/2007-06/federationmetadata.xml` — unchanged URL; `PassiveRequestorEndpoint` still `/{tid}/wsfed`
2. `GET|POST /{tid}/wsfed` `wa=wsignout1.0` — no `wresult`; 302 to registered SignOutWreply; session gone
3. Next `GET /{tid}/wsfed` `wa=wsignin1.0` — Pick an account
4. `e2e/wsfed` unmodified library SignOut (scenario 4 only — **not extended in DISTILL**)

## Stranger contract (KPI-1 — DELIVER, not DISTILL)

DISTILL does **not** edit `e2e/wsfed/Program.cs`.

When DELIVER extends the existing stranger:

- Register **two** URIs of type `wsfed-reply` for `api://tasks-api`:
  - Sign-in callback: `CallbackPath` / `Wreply` (example `https://rp.example.test/signin-wsfed`)
  - Distinct sign-out return: library `SignOutWreply` (example `https://rp.example.test/wsfed-signed-out`)
- `SignOutWreply` ≠ `CallbackPath` (spike return-URL trap, 15 Aug 2026)
- After unmodified `SignOut`, `GET /secure` is unauthenticated
- Next `wsignin1.0` is Pick an account
- v0.8.0 sign-in in the same run stays green
- Witness: `python3 e2e/run.py wsfed` exit 0 **including a SignOut step**

Go analog is skipped: `TestUnmodifiedWsFederationCompletesSignOut`.

## Adapters (real I/O)

| Adapter | How the skeleton uses it |
|---|---|
| Store (SQLite) | `newTestServer` ephemeral DB; Tasks API + two `wsfed-reply` URIs inserted through Store |
| HTTP driving adapter | `httptest` GET/POST `/{tid}/wsfed` |
| Shared SSO session | Cookie jar after sign-in; must be gone after `wsignout1.0` |
| Audit recorder | In-process ring; asserted in focused audit scenarios, not as the skeleton's Then |
| .NET stranger | Pending `e2e/wsfed` SignOut (documented here; no half-broken csproj) |

No containers. No InMemory doubles on the walking skeleton.

## First scenario RED

Go: `TestPriyaSignsAliceOutOfTheTasksAPI` in `internal/server/wsfed_sign_out_test.go`.

Hits the existing `httptest` emulator (same pattern as `wsfed_walking_skeleton_test.go`). Completes Alice's sign-in (session exists), then GET `wa=wsignout1.0` with registered SignOutWreply. Today `handleWSFed` ignores `wa` and SSO-delivers a `wresult`. That is a **business** failure (minting a token while Priya asked to sign out), not ImportError.

Want: no `wresult`; HTTP 302 to `https://rp.example.test/wsfed-signed-out`; session gone; next `wsignin1.0` is Pick an account.

Mandate 7 scaffolds are **N/A**: production packages (`internal/identity`, `internal/store`, `internal/tokens`, `internal/audit`) already exist. A `SCAFFOLD: true` panic in `handleWSFed` would break the running emulator.

## Supersede freeze

Do not keep `signOutForbiddenTrip` as the sign-out story. v0.8.0 `TestSignOutIsAdvertisedWithoutASignOutWitness` is superseded when this witness exists. DISTILL drives `wsignout1.0`. Do not edit v0.8.0 sign-in Gherkin Then steps to require sign-out.
