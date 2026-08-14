# Definition of Ready — ws-fed

**Feature ID:** `ws-fed`  
**Wave:** DISCUSS  
**Date:** 14 Aug 2026  
**Stories:** US-01 … US-08 in `user-stories.md`

## Peer review

**Approved.** `nw-product-owner-reviewer` (Eclipse), 2026-08-14. Zero critical/high issues. DoR 8/8 on all eight stories. Handoff to DESIGN is unblocked.

---

## Feature-level

| Item | Status | Evidence |
|---|---|---|
| Journey visual + YAML | PASS | `docs/product/journeys/ws-fed-sign-in-visual.md` (SSOT) + discuss copies |
| Shared artifacts | PASS | `shared-artifacts-registry.md` — every mockup `${variable}` sourced |
| Story map + walking skeleton | PASS | `story-map.md` — six-activity backbone; skeleton = v0.8.0 E2E |
| ≥2 release slices | PASS | WS happy path; R1 refuse-unsafe; R2 explicit Won't |
| Scope assessment | PASS | 8 stories, 1 outcome, ~8–11 days; cross-cutting not split (user locked skeleton) |
| Outcome KPIs | PASS | `outcome-kpis.md` |
| JTBD | N/A (skipped) | Stories trace to DISCOVER desired outcome; no invented job-analysis.md |
| System constraints | PASS | Top of `user-stories.md`; spike S3b / H2 locked |

---

## Definition of Ready Validation

Nine-item hard gate (problem, persona, examples, UAT, AC from UAT, size, technical notes, dependencies, outcome KPIs).

### Story: US-01

| DoR Item | Status | Evidence/Issue |
|---|---|---|
| Problem statement clear | PASS | SAML-only metadata; MetadataAddress cannot find PassiveRequestorEndpoint |
| User/persona identified | PASS | Priya Chen, existing ASP.NET WS-Fed RP |
| 3+ domain examples | PASS | Tasks API; SAML still present; no second URL |
| UAT scenarios (3-7) | PASS | 4 scenarios |
| AC derived from UAT | PASS | Endpoints, cert match, SLO advertise, SAML remains |
| Right-sized | PASS | ~1 day, one outcome (metadata advertises STS) |
| Technical notes | PASS | One URL; both endpoints; D14 entityID |
| Dependencies tracked | PASS | Existing metadata; enables US-02 |
| Outcome KPIs | PASS | KPI-2 |

### DoR Status: PASSED

### Story: US-02

| DoR Item | Status | Evidence/Issue |
|---|---|---|
| Problem statement clear | PASS | `/wsfed` 404 today |
| User/persona identified | PASS | Priya; middleware challenge |
| 3+ domain examples | PASS | Tasks API GET; omitted wctx; no token before sign-in |
| UAT scenarios (3-7) | PASS | 4 scenarios |
| AC derived from UAT | PASS | Not 404; login HTML; optional wctx; POST as well as GET |
| Right-sized | PASS | ~1 day |
| Technical notes | PASS | wa=wsignin1.0; errors in US-06/07 |
| Dependencies tracked | PASS | US-01 → US-03 |
| Outcome KPIs | PASS | KPI-3 |

### DoR Status: PASSED

### Story: US-03

| DoR Item | Status | Evidence/Issue |
|---|---|---|
| Problem statement clear | PASS | Second login UI would break habit |
| User/persona identified | PASS | Returning emulator user |
| 3+ domain examples | PASS | Alex Rivera; password mode; no second chrome |
| UAT scenarios (3-7) | PASS | 4 scenarios |
| AC derived from UAT | PASS | Same picker; params survive; badge |
| Right-sized | PASS | ~1 day |
| Technical notes | PASS | Reuse existing sign-in; no type names |
| Dependencies tracked | PASS | US-02 → US-04 |
| Outcome KPIs | PASS | KPI-4 |

### DoR Status: PASSED

### Story: US-04

| DoR Item | Status | Evidence/Issue |
|---|---|---|
| Problem statement clear | PASS | No wresult today; SAML 1.1 wrong for this witness |
| User/persona identified | PASS | Priya; registered reply |
| 3+ domain examples | PASS | Tasks POST; no wctx; SAML 1.1 out |
| UAT scenarios (3-7) | PASS | 6 scenarios |
| AC derived from UAT | PASS | POST shape, audience, issuer, wctx, SAML 2.0, cert |
| Right-sized | PASS | ~2–3 days, one outcome (token at registered reply) |
| Technical notes | PASS | S3b; registered POST target |
| Dependencies tracked | PASS | US-03 → US-05 |
| Outcome KPIs | PASS | KPI-1 token shape |

### DoR Status: PASSED

### Story: US-05

| DoR Item | Status | Evidence/Issue |
|---|---|---|
| Problem statement clear | PASS | Own tests without stranger are not enough |
| User/persona identified | PASS | Priya + CI stranger |
| 3+ domain examples | PASS | Session; host/TLS only; no gallery |
| UAT scenarios (3-7) | PASS | 4 scenarios |
| AC derived from UAT | PASS | Unmodified library; knobs; witness; OIDC/SAML guardrail |
| Right-sized | PASS | ~2 days, one outcome (stranger completes) |
| Technical notes | PASS | Harness layout is DESIGN |
| Dependencies tracked | PASS | US-01–US-04 |
| Outcome KPIs | PASS | North star KPI-1 |

### DoR Status: PASSED

### Story: US-06

| DoR Item | Status | Evidence/Issue |
|---|---|---|
| Problem statement clear | PASS | Unknown realm + attacker wreply |
| User/persona identified | PASS | Priya / URL crafter |
| 3+ domain examples | PASS | Known; unknown+attacker; empty |
| UAT scenarios (3-7) | PASS | 3 scenarios |
| AC derived from UAT | PASS | No POST to caller wreply; known realm ok |
| Right-sized | PASS | ~1 day, 3 scenarios |
| Technical notes | PASS | Status/body is DESIGN; no bounce |
| Dependencies tracked | PASS | US-02; independently demonstrable |
| Outcome KPIs | PASS | KPI-5 |

### DoR Status: PASSED

### Story: US-07

| DoR Item | Status | Evidence/Issue |
|---|---|---|
| Problem statement clear | PASS | wreply must be registered (ACS analog) |
| User/persona identified | PASS | Priya configuring reply URLs |
| 3+ domain examples | PASS | Registered; unregistered; omitted |
| UAT scenarios (3-7) | PASS | 4 scenarios including cross-app |
| AC derived from UAT | PASS | Unregistered/missing/cross-app refused; registered works |
| Right-sized | PASS | ~1 day |
| Technical notes | PASS | Storage type is DESIGN |
| Dependencies tracked | PASS | US-02 |
| Outcome KPIs | PASS | KPI-5 |

### DoR Status: PASSED

### Story: US-08

| DoR Item | Status | Evidence/Issue |
|---|---|---|
| Problem statement clear | PASS | Unsolicited off by default on locked stranger |
| User/persona identified | PASS | Priya relying on SP-initiated |
| 3+ domain examples | PASS | SP-initiated; forged POST; no flag |
| UAT scenarios (3-7) | PASS | 3 scenarios |
| AC derived from UAT | PASS | Unsolicited refused; happy path; no v0.8.0 flag |
| Right-sized | PASS | ~1 day |
| Technical notes | PASS | Correlation mechanism is DESIGN |
| Dependencies tracked | PASS | US-02/US-04 to distinguish solicited |
| Outcome KPIs | PASS | KPI-5 |

### DoR Status: PASSED

---

## Anti-pattern scan (self)

| Anti-pattern | Result |
|---|---|
| Implement-X | Remediated — stories start from 404 / SAML-only / unsafe bounce |
| Generic data | Remediated — Priya Chen, Alex Rivera, `api://tasks-api`, `https://rp.example.test/signin-wsfed` |
| Technical AC | Protocol names kept as domain language; Go/CI not prescribed |
| Technical scenario titles | Titles are user-observable (find endpoint, not 404, same picker, receive token, middleware completes, refuse unsafe) |
| Oversized | 8 stories, 3–6 scenarios each; skeleton not one blob |
| Abstract requirements | Each story has 3 domain examples |

## Feature DoR: PASSED (self) — BLOCKED on peer review

Self-validation passed all 9 items on all 8 stories. **Handoff to DESIGN is not opened** until `nw-product-owner-reviewer` approves.
