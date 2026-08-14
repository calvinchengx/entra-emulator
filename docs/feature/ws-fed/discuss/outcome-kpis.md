# Outcome KPIs — ws-fed

**Feature ID:** `ws-fed`  
**Date:** 14 Aug 2026  
**JTBD:** skipped; traces to DISCOVER job: point WsFederation at the emulator (`docs/feature/ws-fed/discover/problem-validation.md`).

Handoff: DESIGN uses these as success conditions; DEVOPS/platform uses the measurement plan (no CI YAML prescribed here).

## Feature: Point a WS-Fed RP at the local STS

### Objective

By the v0.8.0 cut, a developer who already has an ASP.NET WS-Fed relying party can point `MetadataAddress` and `Wtrealm` at the emulator and complete one SP-initiated sign-in with unmodified `Microsoft.AspNetCore.Authentication.WsFederation`.

### Outcome KPIs

| # | Who | Does What | By How Much | Baseline | Measured By | Type |
|---|-----|-----------|-------------|----------|-------------|------|
| 1 | Developers with an existing WsFederation RP | Complete metadata fetch + `/wsfed` sign-in with only host/TLS changes | From 0 successful stranger runs to **1 green** CI stranger (100% of that path) | 0 (404; Q1 never-run) | Unmodified `Microsoft.AspNetCore.Authentication.WsFederation` witness pass/fail | Leading (activation) |
| 2 | Same developers | Locate `PassiveRequestorEndpoint` (+ SecurityTokenServiceEndpoint) and a matching cert on the **existing** FederationMetadata URL | From 0% (SAML-only document) to **100%** of metadata parses in that witness | SAML-only metadata | Metadata parse in the witness (H2 shape) | Leading (secondary) |
| 3 | Same developers | Reach `/{tid}/wsfed` instead of 404 on `wa=wsignin1.0` | From **100% 404** to **0% 404** on the witnessed challenge | Unrouted | Challenge HTTP status in witness / Tasks API run | Leading (secondary) |
| 4 | Developers who already use OIDC/SAML login | Complete WS-Fed interactive sign-in on the existing account picker | **0** new login pages | OIDC/SAML picker exists; WS-Fed has none | E2E: same sign-in chrome family | Leading (habit) |
| 5 | Anyone who can craft a challenge or POST | Fail to obtain a session or token bounce via unknown `wtrealm`, unregistered `wreply`, or unsolicited `wresult` | **0** POSTs to unowned URLs; **0** unsolicited sessions | No resolver today | Negative e2e (US-06–US-08) | Guardrail |

### Metric Hierarchy

- **North Star (OMTM):** KPI-1 — unmodified WsFederation completes one SP-initiated sign-in against the emulator.
- **Leading indicators:** KPI-2 (metadata), KPI-3 (no 404), KPI-4 (same picker).
- **Guardrail metrics:** KPI-5 (unsafe refuse); OIDC and SAML sign-in still pass; no SOAP surface; no `wsignout1.0` witness required for green; no SAML 1.1 minted for `api://` realms.

### Measurement Plan

| KPI | Data Source | Collection Method | Frequency | Owner |
|---|---|---|---|---|
| 1 North star | CI stranger / local Tasks API | Pass/fail of unmodified library sign-in | Every change that touches WS-Fed; release gate | Maintainer (witness) |
| 2 Metadata | Same witness metadata fetch | RoleDescriptor + both endpoints + cert match | With KPI-1 | Maintainer |
| 3 Challenge | HTTP to `/{tid}/wsfed` | Status ≠ 404; body is login HTML not `wresult` | With KPI-1 | Maintainer |
| 4 Habit | Sign-in HTML / e2e | Same picker as OIDC/SAML | Once per slice + regression | Maintainer |
| 5 Guardrail | Negative e2e | No POST to attacker/unregistered reply; unsolicited refused | With Release 1 stories | Maintainer |
| Guardrail OIDC/SAML | Existing e2e | Those suites still green | Same CI as today | Maintainer |

Instrumentation note for DEVOPS: events that matter are “metadata located TokenEndpoint”, “challenge not 404”, “wresult posted to registered wreply”, “stranger verified”, “unsafe refused”. Do not log raw `wresult` (live credential).

### Hypothesis

We believe growing the existing FederationMetadata document and adding `/{tid}/wsfed` passive sign-in (SAML 2.0 `wresult`, registered `wreply`, same account picker) for developers using `Microsoft.AspNetCore.Authentication.WsFederation` will achieve an unmodified library completing metadata fetch → challenge → account picker → POST `/signin-wsfed` with a verifiable token.

We will know this is true when that library, unmodified, completes one SP-initiated sign-in against the emulator in CI (KPI-1), with KPI-5 holding.

### Story → KPI map

| Story | Moves |
|---|---|
| US-01 | KPI-2 |
| US-02 | KPI-3 |
| US-03 | KPI-4 |
| US-04 | KPI-1 (token shape) |
| US-05 | KPI-1 (north star) |
| US-06, US-07, US-08 | KPI-5 |

### Smell tests

| Check | Result |
|---|---|
| Measurable today? | Yes — 404 and SAML-only metadata are observable; stranger is named |
| Rate not total? | KPI-1 is pass rate of the witness path (0 → 1 green); not “ship WS-Fed” |
| Outcome not output? | Completing sign-in / refusing unsafe POSTs, not “add a route” |
| Has baseline? | 404; SAML-only metadata; Q1 never-run |
| Team can influence? | Yes — protocol surface on this emulator |
| Has guardrails? | Unsafe refuse; OIDC/SAML; no SOAP; no SAML 1.1 for this witness |
