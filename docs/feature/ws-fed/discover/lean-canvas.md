# Lean Canvas — ws-fed

**Feature ID:** `ws-fed`
**Wave:** DISCOVER / Phase 4 (updated after maintainer interview #1)
**Adaptation:** not a SaaS business. Canvas records product-boundary viability.

**Status:** first-pass canvas updated. G4 still not passed (A3 unspiked; A1 not usage-validated; G1 interview count unmet).

---

## Canvas

| | | |
|---|---|---|
| **Problem** | **Solution** | **Unique value proposition** |
| 1. A WS-Fed RP pointed at this emulator gets **404** on `/wsfed`. | 1. `GET\|POST /{tenant}/wsfed` passive sign-in (`wa=wsignin1.0` → POST `wresult`). | The emulator already does this job for OIDC and SAML 2.0. WS-Fed is the remaining browser-federation sibling on the same signing key, witnessed by unmodified `Microsoft.AspNetCore.Authentication.WsFederation`. |
| 2. FederationMetadata is **SAML-only**, so `MetadataAddress` cannot find `PassiveRequestorEndpoint`. | 2. Grow that **same** document with a WS-Fed `RoleDescriptor` (same cert); advertise sign-out URL, do not witness SLO. | |
| 3. Downstream currently workaround or skip (interview #1 Q2; requester unnamed). | 3. One stranger-witnessed parity row (v0.8.0-shaped). SOAP out. | |
| **Customer segments** (by job) | **Channels** | **Unfair advantage** |
| JTBD: point the WS-Fed RP I already have at a local STS. **v0.8.0 segment locked:** ASP.NET Core `AddWsFederation` (Q3). SharePoint on-prem and BC pre-v22 remain published RPs, not this cut's witness. Demand class: third-party / downstream (Q2); maintainer is not a past consumer (Q1). | Same as the emulator: GitHub, parity table, release notes. | Tenant RSA + SAML cert derivation + login UI already exist (v0.6.0). |
| **Existing alternatives** | **Revenue streams** | **Cost structure** |
| Real Entra tenant; ADFS; skip WS-Fed tests (Q2: they workaround or skip); wait for the RP to migrate to OIDC (BC v22 did). | None. Success = green parity row with a named stranger. | Maintainer time; a .NET e2e harness; **SAML 1.1 builder only if the A3 spike lands on 1.1**; ongoing metadata compatibility. |
| **Key metrics** | | |
| WsFederation sign-in pass in CI; metadata contains RoleDescriptor + matching certs; `/wsfed` is not 404 for `wsignin1.0`; parity row WS-Federation → 🟢 with that witness in `docs/witnesses.json`. Non-metrics: SLO e2e, SOAP, gallery, CA/MFA. | | |

---

## Four big risks

| Risk | Question | Status | Evidence |
|---|---|---|---|
| **Value** | Will emulator users want this? | **Yellow** | Q2: third-party / downstream request; they workaround or skip. Q1: maintainer has never run a WS-Fed RP — **not usage-validated**. Requester unnamed. BC dropped WS-Fed in v22. ASP.NET docs still current 2026. Was red; demand class moved it off red, not onto green. |
| **Usability** | Can WsFederation use it with host-only config change? | **Yellow** | D3 describes config. H2 untested. Spike includes metadata parse. |
| **Feasibility** | Can we mint a token that library verifies? | **Yellow** | Signing path exists. Envelope is new. A3 (1.1 vs 2.0) still conflicted; now scoped to this stranger. Spike is the test. |
| **Viability** | Does this stay a dev-loop emulator? | **Green** | Same boundary as SAML. Q5 SOAP out. Q4 SLO advertise-only. Not MFA/CA/B2C. Roadmap still lists WS-Fed as a non-goal — documentation lag if we later ship, not a character change. |

---

## Unit economics (translated)

| Question | Answer |
|---|---|
| Is the protocol decaying? | Mixed. BC: yes. ASP.NET Core middleware: docs still shipped for .NET 10/11 (2026) — **this is the locked witness**. |
| Is one stranger enough? | Product bar (SAML: `node-saml`). Q3 locked the analog. |
| What would kill viability? | Spike shows the library needs CA/MFA, or TokenType cannot be determined, or Q2 demand evaporates when named. |

---

## Stakeholder sign-off

| Stakeholder | Sign-off |
|---|---|
| Maintainer (this user) | **Partial.** Q3–Q5 lock witness, SLO, SOAP. Q1–Q2 do not sign off "I have run this." Third party unnamed. |
| Legal / finance / ops | N/A |

---

## Gate G4

| Metric | Target | Result |
|---|---|---|
| Four big risks | All green/yellow | **Yellow/green** — no remaining red. Feasibility yellow until the spike. |
| Channel | 1+ viable | Existing GitHub/parity channel. |
| Unit economics | Translated | Cost looks like SAML if A3 is 2.0; higher if 1.1 needs a second assertion builder. |
| Stakeholder sign-off | Required | **Partial only.** |

**G4: FAIL** (incomplete). Risks are no longer red, but A3 is unaddressed and G1's interview bar is unmet. Not a go to build. Not a go to DISCUSS.

---

## Go / no-go (this canvas)

**Blocked on A3 spike**, not on repeating Mom Test Q1–Q5. Not kill. Not go.
