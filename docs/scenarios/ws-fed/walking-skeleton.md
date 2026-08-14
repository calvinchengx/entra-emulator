# Walking skeleton — ws-fed

> Archived copy at finalize (15 Aug 2026) from `docs/feature/ws-fed/distill/walking-skeleton.md`.  
> Architecture SSOT: `docs/product/architecture/`. Journeys: `docs/product/journeys/`. Gherkin: `tests/acceptance/ws-fed/`.  
> DISTILL-time “enabled / `@pending` / first scenario RED” rows are historical. All 12 DELIVER steps completed; KPI-1 stranger is `python3 e2e/run.py wsfed`.

**Feature ID:** `ws-fed`  
**Date:** 14 Aug 2026  
**Strategy:** C (Real local) — DWD-01

## One-liner

Priya points the Tasks API at the existing FederationMetadata URL; that document names `/{tid}/wsfed`; the challenge is the same Pick an account page; the registered reply receives a SAML 2.0 `wresult`; unmodified `Microsoft.AspNetCore.Authentication.WsFederation` completes sign-in.

## What it proves

A developer-as-user (Priya Chen) can accomplish the job: point an existing ASP.NET WS-Fed relying party at this emulator and complete one SP-initiated sign-in. It is not a layer-connectivity check.

Stories in the slice: **US-01 → US-05**. Refuse-unsafe (US-06–US-08) is Release 1 Must Have, separately demonstrable.

## Scenarios

| # | Scenario | Env | Tags | Enabled? |
|---|---|---|---|---|
| 1 | Priya completes Tasks API WS-Fed sign-in on a clean emulator | clean | `@walking_skeleton @real-io @driving_adapter @driving_port` | **Yes** (first) |
| 2 | Priya completes Tasks API WS-Fed sign-in alongside existing OIDC and SAML | with-pre-commit | same | `@pending` |
| 3 | Priya completes Tasks API WS-Fed sign-in after registering a reply on a stale directory | with-stale-config | same | `@pending` |
| 4 | Priya's unmodified WsFederation middleware completes sign-in | clean + stranger | `@kpi @walking_skeleton` (KPI-1) | `@pending` until DELIVER US-05 |

Feature file: `tests/acceptance/ws-fed/walking-skeleton.feature`

## Driving ports exercised

1. `GET /{tid}/federationmetadata/2007-06/federationmetadata.xml`
2. `GET|POST /{tid}/wsfed` `wa=wsignin1.0`
3. Account picker POST action `/{tid}/wsfed`
4. Browser auto-POST `wresult` to registered `wsfed-reply`
5. `e2e/wsfed` unmodified library (scenario 4 only)

## Adapters (real I/O)

| Adapter | How the skeleton uses it |
|---|---|
| Store (SQLite) | `newTestServer` ephemeral DB; Tasks API + `wsfed-reply` inserted through Store |
| Tokens / signing | Tenant cert already published on IDPSSODescriptor; WS-Fed RoleDescriptor and assertion must match |
| Audit recorder | In-process ring; challenge/success asserted in focused audit scenarios, not as the skeleton's Then |
| .NET stranger | Pending `e2e/wsfed` (documented README, no half-broken csproj) |

No containers. No InMemory doubles on the walking skeleton.

## First scenario RED

Go: `TestPriyaCompletesTasksAPIWSFedSignIn` in `internal/server/wsfed_walking_skeleton_test.go`.

Hits the existing `httptest` emulator (same pattern as `saml_sso_test.go`). Today FederationMetadata is SAML-only (`RoleDescriptor` absent) and `GET /{tid}/wsfed` is unrouted (404). That is a **business** failure (missing STS advertisement / missing challenge), not ImportError.

Mandate 7 scaffolds are **N/A**: production packages (`internal/identity`, `internal/store`, `internal/tokens`, `internal/audit`) already exist. A `SCAFFOLD: true` panic in `Register` would break the running emulator.
