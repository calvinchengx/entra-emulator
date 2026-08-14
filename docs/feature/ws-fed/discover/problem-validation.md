# Problem validation — ws-fed

**Feature ID:** `ws-fed`
**Wave:** DISCOVER / Phase 1 (updated after maintainer interview #1)
**Evidence standard:** past behavior (documentary + one Mom Test). Not future intent.
**Date:** 14 Aug 2026 (second pass)

---

## Classification (from Microsoft docs, not taste)

WS-Fed on Entra is a **protocol surface** feature.

| Surface | Is this it? | Evidence |
|---|---|---|
| STS protocol (login host) | **Yes** | Entra publishes `/{tid}/wsfed` and `/common/wsfed` as `fed:PassiveRequestorEndpoint` in federation metadata ([federation-metadata](https://learn.microsoft.com/en-us/entra/identity-platform/federation-metadata)). |
| Federation metadata (same document as SAML) | **Yes — extension, not a second URL** | WS-Federation 1.2 extends SAML 2.0 metadata. ASP.NET `MetadataAddress` is that one path ([ASP.NET WsFederation](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/ws-federation)). |
| Admin portal / Enterprise app gallery UX | No | Gallery templates configure WS-Fed; the emulator's job is the wire. |
| Microsoft Graph | No | No Graph resource is the WS-Fed sign-in or metadata document. |
| Policy engine (MFA / CA / B2C) | No | Same boundary test SAML already passed (`docs/parity.md` scope-boundary). |

---

## Desired outcome (job, not a solution)

When a developer points **Microsoft.AspNetCore.Authentication.WsFederation** at this emulator instead of `login.microsoftonline.com`, the middleware completes metadata fetch + `/wsfed` sign-in using the same `MetadataAddress` / `Wtrealm` it already uses against Entra, and the unmodified library verifies the token.

Sign-out is advertised in metadata (SAML v0.6.0 pattern) and is **not** the v0.8.0 witness.

Witness locked by maintainer interview #1 Q3 — a **chosen** stranger, not a past run (Q1 = never).

---

## Problem in consumer language

Documentary (Microsoft), unchanged:

> ASP.NET Core apps set `MetadataAddress` to the Federation Metadata document and `Wtrealm` to the Application ID URI (`api://...`).
> — [Authenticate with WS-Federation](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/ws-federation)

Maintainer interview #1 (customer-of-this-product words):

> "Never — this is a ledger gap, not a consumer I have run."
> "Yes — a third-party / downstream request; they workaround or skip."

This emulator today: that metadata URL returns a SAML-only document; that `/wsfed` URL is unrouted (404). Downstream currently workaround or skip. Requester, date, and workaround were **not named**.

SharePoint's SAML 1.1 instruction still proves `/saml2` ≠ `/wsfed`. It does **not** pick the v0.8.0 token version (A3 is now a spike against the ASP.NET stranger).

---

## JTBD map (developer pointing ASP.NET WsFederation at the emulator)

| Step | Goal | What happens today | Outcome statement |
|---|---|---|---|
| Define | Identify the STS the RP already knows | Entra's host + tenant | Minimize time to name the emulator as the same STS shape |
| Locate | Fetch federation metadata | Path exists; document has only `IDPSSODescriptor` | Minimize time to obtain `PassiveRequestorEndpoint` and signing certs |
| Prepare | Register realm (`wtrealm` / App ID URI) and reply URL | Apps have `appIdUri` + `saml-acs`; no WS-Fed-specific reply type | Minimize likelihood of missing a registered realm/reply |
| Confirm | Metadata cert === token-signing key | Cert published only in SAML section | Minimize likelihood of verifying against the wrong key |
| Execute | Browser hits `/wsfed?wa=wsignin1.0&wtrealm=...` | **404** | Minimize time from challenge to posted `wresult` |
| Monitor | Middleware validates RSTR + assertion | No token is issued | Minimize uncertainty that WsFederation accepted the token |
| Modify | Fix reply URL / realm mismatch | No WS-Fed error path | Minimize effort to correct a rejected `wreply`/`wtrealm` |
| Conclude | Session at the RP; SLO advertised, not witnessed | Never reached | Minimize time from sign-in POST to RP session |

Job-step coverage: 8/8 described; 0/8 observed with WsFederation against this emulator (Q1 = never).

---

## What is validated vs assumed

### Validated (documentary + interview #1 scope locks)

| Claim | Confidence | Evidence |
|---|---|---|
| Entra serves WS-Fed on `/{tid}/wsfed` in the **same** FederationMetadata document as SAML | High | D2 |
| ASP.NET WsFederation configures via that metadata URL + `Wtrealm` | High | D3 |
| This emulator does not implement `/wsfed` and does not emit the WS-Fed RoleDescriptor | High | D1 |
| WS-Fed does not require a policy engine | High | `docs/parity.md` scope-boundary |
| v0.8.0 stranger is `Microsoft.AspNetCore.Authentication.WsFederation` | High **as a decision** | Interview #1 Q3. **Not** a past run (Q1). |
| Sign-out is advertise-in-metadata only; not a v0.8.0 witness | High **as a decision** | Interview #1 Q4; SAML analog D8 |
| Passive profile only; SOAP / active WS-Trust out | High | Interview #1 Q5 + D3–D6 |
| Unsolicited logins out of first cut | High | D3 default; stranger is now that middleware |

### Not usage-validated / still open

| ID | Claim | Status after interview #1 |
|---|---|---|
| A1 | Someone needs WS-Fed **on this emulator** | **Demand class, not usage.** Q2: third-party / downstream request; they workaround or skip. Q1: maintainer has never run a WS-Fed RP. Requester, date, workaround **unnamed**. Do not upgrade to "validated by usage." |
| A3 | Token on `/wsfed` is SAML 1.1 (not 2.0) | **Still conflicted.** No longer SharePoint-first. Spike against the locked ASP.NET stranger + an Entra capture. D7 (app-reg-shaped capture) is SAML 2.0; D5 is SAML 1.1 for a witness we are **not** using. |

---

## Gate G1

| Metric | Target | Result |
|---|---|---|
| Interviews | 5+ | **1** (maintainer). Documentary sources do not count as interviews. |
| Problem confirmation | >60% of 5 | Cannot compute a 5-person rate. The one interview: Q2 confirms a demand class; Q1 is a skeptic signal (never run). Protocol gap is independently confirmed by this repo (404). |
| Frequency | Weekly+ | **Unknown.** No last-attempt date (Q2 gap). |
| Current spending / workarounds | >$0 | "They workaround or skip" — workaround **not described**. Not quantified. |
| Customer words | Required | Maintainer: "ledger gap"; "third-party / downstream request; they workaround or skip." |

**G1: FAIL** on the 5-interview rule. Explicitly: **one interview is not five.**

What changed: A1 is no longer pure intent. It is a **named demand class** with a recorded gap (unnamed requester). That is not enough to pass G1, and it is enough to stop asking the same five Mom Test questions.

---

## Assumption tracker (re-scored after interview #1)

Score = (Impact × 3) + (Uncertainty × 2) + (Ease × 1). Test first if >12.

| ID | Assumption | Category | I | U | E | Score | Action |
|---|---|---|---|---|---|---|---|
| A3 | `/wsfed` `wresult` assertion version for **WsFederation** is knowable (1.1 vs 2.0) | Feasibility | 3 | 2 | 1 | **14** | **Test first** — Entra capture + that library. U dropped from 3→2: witness locked; D7 is app-reg-shaped (SAML 2.0), D5 is a different RP. |
| A1 | Someone needs WS-Fed on this emulator | Value | 3 | 2 | 1 | **14** | **Not usage-validated.** U dropped 3→2: Q2 demand class. Still test-first if we required a named requester; recommended path is not more interviews as a gate — see go/no-go. |
| A4 | Metadata must grow a RoleDescriptor; a second URL breaks `MetadataAddress` | Feasibility | 3 | 1 | 1 | **12** | Provisionally true (D2+D3). Stranger parse is part of the A3 spike (H2). |
| A5 | ASP.NET WsFederation is the v0.8.0 stranger | Usability | 2 | 1 | 1 | **9** | **Locked** (Q3). Chosen witness, not a past run. |
| A2 | Passive only; SOAP/active out | Value | 2 | 1 | 1 | **9** | **Locked** (Q5). |
| A7 | Unsolicited logins out | Value | 2 | 1 | 1 | **9** | Locked by D3 + chosen stranger. |
| A6 | Sign-out in v0.8.0 | Value | 1 | 1 | 1 | **6** | **Locked advertise-only** (Q4). Do not witness SLO. |
| A8 | Same login UI + tenant RSA as SAML | Feasibility | 1 | 1 | 1 | **6** | Analog; not yet executed for WS-Fed. |

---

## Clarification — answered

Interview #1 Q1–Q5 are answered (`interview-log.md`). Remaining **optional** (does not gate the recommended spike):

- Name of the third-party / downstream requester, when they last tried, what they did instead.

That would raise A1 confidence. It would **not** resolve A3.

---

## Decision

**G1 still fails the 5-interview rule.** Protocol shape is documented. Demand is a class without a named requester. The remaining protocol unknown is **A3**.

Recommended next step is a **spike**, not DISCUSS and not a hard block on naming the third party. See `wave-decisions.md`.
