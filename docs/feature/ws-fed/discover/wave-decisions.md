# Wave decisions — ws-fed (DISCOVER)

**Feature ID:** `ws-fed`
**Wave:** DISCOVER (second pass — maintainer interview #1)
**Date:** 14 Aug 2026
**Interactive / evidence standard:** high / past_behavior
**Classification (from Microsoft docs):** **protocol surface** (STS `/wsfed` + FederationMetadata WS-Fed RoleDescriptor). Not portal. Not Graph. Not a policy engine.

Skills: `[SKILL LOADED] nw-interviewing-techniques`, `[SKILL LOADED] nw-opportunity-mapping`, `[SKILL LOADED] nw-discovery-workflow`, `[SKILL MISSING] nw-product-discoverer` (agent spec used).

Peer review: **not invoked.** G1–G4 have not all passed. Handoff to product-owner (DISCUSS) is **not** opened.

---

## Go / no-go

**A3 closed** (see `docs/feature/ws-fed/spike/findings.md` follow-up capture). TokenType for an app-registration `Wtrealm` is SAML 2.0. DISCUSS is unblocked on the protocol unknown.

G1 still **fails** the 5-interview rule (count = 1). That is stated, not waived.

**Recommended next command: `/nw-discuss`.**

Do **not** change `docs/parity.md` or `docs/17-roadmap.md` in DISCOVER. Spike findings override D8.

---

## Decisions

[D1] WS-Fed is a protocol-surface feature, not portal or Graph: Entra publishes `/{tid}/wsfed` inside FederationMetadata as `fed:PassiveRequestorEndpoint` (see: https://learn.microsoft.com/en-us/entra/identity-platform/federation-metadata, https://learn.microsoft.com/en-us/aspnet/core/security/authentication/ws-federation).

[D2] Discovery evidence mixes documentary sources with **one** maintainer Mom Test; inventing four more interviews would fake G1 (see: `interview-log.md`).

[D3] G1 fails the 5-interview rule after interview #1: count = 1 (see: `problem-validation.md` Gate G1).

[D4] Sign-in `wa` is `wsignin1.0`, not `wsignin1.1`: OASIS WS-Federation 1.2 §13.2.1 (see: https://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html).

[D5] Passive (browser) profile is the v0.8.0 shape; SOAP/active WS-Trust is out: interview #1 Q5 plus published RPs (see: interview-log Q5; OASIS §13; ASP.NET middleware).

[D6] Metadata must be extended on the existing FederationMetadata URL, not a second path: ASP.NET `MetadataAddress` is that document (see: federation-metadata Learn, ASP.NET WsFederation docs). Provisional until H2 runs in the spike.

[D7] `/saml2` is not an alias of `/wsfed`: SharePoint operators must rewrite the path (see: https://learn.microsoft.com/en-us/entra/identity/saas-apps/sharepoint-on-premises-tutorial). Still true; SharePoint is **not** the v0.8.0 witness.

[D8] Token version inside `wresult` for the ASP.NET `Wtrealm=api://…` witness is **SAML 2.0**: this team's capture 14 Aug 2026 (see: `docs/feature/ws-fed/spike/findings.md`). SharePoint's SAML 1.1 instruction remains a different RP class, out of v0.8.0.

[D9] Unsolicited / IdP-initiated login is out of a v0.8.0-shaped first cut: WsFederation disables it by default (see: ASP.NET WsFederation docs).

[D10] If the feature proceeds after the spike, the solution pattern is the SAML analog (new `/wsfed` handler, reuse login UI via `Kind`, same tenant RSA) (see: `internal/identity/samlsso.go`, `docs/release-notes/v0.6.0.md`).

[D11] v0.8.0 stranger **is** `Microsoft.AspNetCore.Authentication.WsFederation`: interview #1 Q3. Chosen witness, not a past run (Q1 = never) (see: `interview-log.md`).

[D12] Sign-out is advertise-in-metadata only; do not witness SLO in v0.8.0: interview #1 Q4 copies the SAML v0.6.0 pattern (see: `saml.go` SingleLogoutService; interview-log Q4).

[D13] `/common/wsfed` is not in the first cut: locked stranger uses tenant-specific `MetadataAddress` in the Entra tutorial (see: ASP.NET docs; D13 prior).

[D14] EntityID stays the emulator's login origin (`samlEntityID`), not borrowed `sts.windows.net`, unless the spike's metadata parse hard-requires Entra's issuer host (see: `saml.go` `samlEntityID`).

[D15] Mom Test Q1–Q5 are answered; further Microsoft-doc reading is not the blocker (see: `interview-log.md` interview #1).

[D16] A1 is a **named demand class** (third-party / downstream request; they workaround or skip) **without** a named requester, last-attempt date, or described workaround: interview #1 Q2. Q1 is zero maintainer usage. Do not upgrade A1 to validated-by-usage (see: `interview-log.md` Q1–Q2).

[D17] Recommended next command is spike, not DISCUSS and not a hard block on naming the third party (see: this file Go/no-go; `solution-testing.md` Recommended next experiment).

---

## Constraints

- Artifacts live only under `docs/feature/ws-fed/discover/` (this wave).
- Do not invent customer quotes or pad to five interviews.
- Do not write requirements (DISCUSS / product-owner) in this pass.
- Do not write production code, parity.md, or roadmap edits.
- v0.8.0 shape if later approved: real protocol + WsFederation stranger + one parity row. SLO advertised, not witnessed. SOAP out. Not a policy engine. Not MFA/CA/B2C.
- Token encryption is out (ASP.NET middleware does not support it).
- Boundary test unchanged.

---

## Assumption table (re-scored)

Score = (Impact × 3) + (Uncertainty × 2) + (Ease × 1).

### Locked / validated (with confidence)

| ID | Assumption | Confidence | Score | Basis |
|---|---|---|---|---|
| A5 | Stranger = `Microsoft.AspNetCore.Authentication.WsFederation` | **High as a decision** (not a past run) | 9 | Interview #1 Q3; Q1 = never |
| A2 | Passive only; SOAP/active out even if it exists somewhere | **High** | 9 | Interview #1 Q5 + D3–D6 |
| A6 | Advertise `wsignout` in metadata; do not witness SLO | **High as a decision** | 6 | Interview #1 Q4; SAML analog |
| A7 | Unsolicited logins out | **High** | 9 | D3 + locked stranger |
| A4 | Grow existing metadata URL | **High (provisional)** | 12 | D2+D3; H2 in spike |
| A8 | Same login UI + tenant RSA as SAML | **High (analog)** | 6 | `samlsso.go`; not executed for WS-Fed |
| Classification | Protocol surface | **High** | — | D1 |

### Highest remaining risk

| ID | Assumption | Score | Status |
|---|---|---|---|
| A3 | `wresult` assertion version for **this** stranger (SAML 1.1 vs 2.0) | **14** | Conflicted. Spike. Leading hypothesis S3b (SAML 2.0) from D7's app-reg-shaped capture — unproven. |
| A1 | Someone needs WS-Fed **on this emulator** | **14** | Demand class (Q2), not usage (Q1). Requester unnamed. |

### Invalidated / conflicted

| ID | Assumption | Status | Evidence |
|---|---|---|---|
| A3 as SharePoint-first "always SAML 1.1" | Token on `/wsfed` is SAML 1.1 because SharePoint says so | **Not the decision rule** | Witness is WsFederation (Q3), not SharePoint. D5 still true for that RP. |
| Wizard `wsignin1.1` as a `wa` value | — | **Invalidated** | OASIS: `wsignin1.0`. |

---

## Gate summary

| Gate | Result | What changed | Remediation |
|---|---|---|---|
| G1 Problem | **FAIL** (5-interview rule) | 0 → **1** interview. A1 = demand class, not usage. | Do not invent interviews. Optional: name the third party (parallel, not a spike gate). |
| G2 Opportunity | **Partial** | A5/A6/A2 locked. OST top 3 still O1/O2/O3. O7 dropped to score 7. | Spike A3 before writing stories. |
| G3 Solution | **FAIL** | 0 users, 0% tasks. H5 locked by decision. | Run the spike in `solution-testing.md`. |
| G4 Viability | **FAIL** (incomplete) | Value red → **yellow**. Feasibility still yellow (A3). Maintainer partial sign-off. | Spike A3; then re-evaluate go to DISCUSS. |

---

## Next command

**Spike** (not `/nw-discuss`, not more interviews as a gate):

1. Point `Microsoft.AspNetCore.Authentication.WsFederation` at **real Entra**; save FederationMetadata.xml + one `wresult`; record TokenType / assertion namespace.
2. Run that library's metadata reader against the live document (and note whether `SecurityTokenServiceEndpoint` / document signature / `sts.windows.net` entityID are required).
3. Return TokenType so DISCUSS can lock S3b vs S3a without guessing.

Optional parallel (does not gate the spike): name the Q2 third party, last-attempt date, and workaround.

---

## Artifacts in this folder

- `docs/feature/ws-fed/discover/problem-validation.md`
- `docs/feature/ws-fed/discover/opportunity-tree.md`
- `docs/feature/ws-fed/discover/solution-testing.md`
- `docs/feature/ws-fed/discover/lean-canvas.md`
- `docs/feature/ws-fed/discover/interview-log.md`
- `docs/feature/ws-fed/discover/wave-decisions.md`
