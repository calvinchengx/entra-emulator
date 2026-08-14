# Wave decisions — ws-fed (DISCUSS)

**Feature ID:** `ws-fed`  
**Wave:** DISCUSS (product-owner / Luna)  
**Date:** 14 Aug 2026  
**Mode:** Subagent execute (`*journey` → `*story-map` → `*gather-requirements`). Interactive questions replaced by parent locked decisions. JTBD skipped.

Peer review: **approved** (`nw-product-owner-reviewer`, 2026-08-14). DESIGN is unblocked, not started.

---

## Decisions

[D1] Canonical product SSOT for this repo is bootstrapped under `docs/product/` (vision, jobs, journeys). DISCUSS copies under `docs/feature/ws-fed/discuss/` point at that SSOT. There was no prior `docs/product/**`, `docs/project-brief.md`, or `docs/stakeholders.yaml`.

[D2] JTBD analysis is skipped (no DIVERGE). Every story traces to the DISCOVER desired outcome: point `Microsoft.AspNetCore.Authentication.WsFederation` at the emulator (`docs/feature/ws-fed/discover/problem-validation.md`). No second job-analysis.md.

[D3] Walking skeleton **is** the v0.8.0 E2E slice (user override Yes): existing FederationMetadata grows a WS-Fed RoleDescriptor → `GET|POST /{tid}/wsfed` answers `wa=wsignin1.0` → same sign-in as OIDC/SAML → POST `wresult` (SAML 2.0) to a registered `wreply` with echoed `wctx` → unmodified WsFederation completes sign-in. Sign-out URL advertised; `wsignout1.0` not witnessed.

[D4] Spike overrides DISCOVER where they conflict. **S3b locked:** `wresult` TokenType is SAML 2.0 (`…#SAMLV2.0`, assertion `Version="2.0"`). SharePoint SAML 1.1 is out of v0.8.0. See `docs/feature/ws-fed/spike/findings.md`.

[D5] H2 WORKS: stranger maps `PassiveRequestorEndpoint` → `TokenEndpoint` = `/{tid}/wsfed` and also reads `SecurityTokenServiceEndpoint`. Metadata stories require **both**. EntityID may stay emulator login origin (DISCOVER D14) if assertion Issuer matches metadata entityID. Hostname `sts.windows.net` is not required.

[D6] `wreply` must be a registered reply URL (SAML ACS analog). Do not trust the query string. How registration is stored is DESIGN.

[D7] Unsolicited `wresult` refused. IdP-initiated / AllowUnsolicitedLogins out of v0.8.0.

[D8] Persona is developer-as-user **Priya Chen** (Tasks API, `Wtrealm=api://tasks-api`, reply `https://rp.example.test/signin-wsfed`). Directory user **Alex Rivera**. No real tenant, org, email, or capture-domain names. `{tid}` only.

[D9] Eight right-sized stories: US-01–US-05 walking skeleton; US-06–US-08 Release 1 refuse-unsafe (still v0.8.0 Must Have, separately demonstrable). Release 2 maps Won't-haves so DESIGN does not grow SOAP, `/common/wsfed`, SAML 1.1, witnessed SLO, gallery, Graph, MFA/CA/B2C, encryption.

[D10] Scope assessment PASS: 8 stories, one user outcome, estimated 8–11 days. Cross-cutting (STS + metadata + login reuse + e2e) is inherent; not split into separate features.

[D11] DISCOVER files, `docs/parity.md`, and `docs/17-roadmap.md` are not edited in this wave.

[D12] Recommended next wave after peer review: DESIGN (solution-architect) — SAML-analog protocol surface: grow existing FederationMetadata; add `/{tid}/wsfed` passive sign-in; reuse existing sign-in; mint SAML 2.0 RSTR; witness with unmodified WsFederation.

---

## Changed Assumptions (Upstream)

DISCOVER `wave-decisions.md` assumption table still lists **A3 as conflicted / spike** (score 14). That row is stale relative to SPIKE.

| ID | DISCOVER table | SPIKE / DISCUSS |
|---|---|---|
| A3 | Open — SAML 1.1 vs 2.0 | **Closed — SAML 2.0 (S3b).** Do not edit DISCOVER; this line is the pointer. |
| A4 / H2 | Provisional grow existing URL | **WORKS** — both endpoints; `sts.windows.net` not required |
| A1 | Demand class, not usage | Unchanged — G1 still fails 5-interview rule; walking skeleton proceeds on protocol gap + locked witness |

---

## Constraints

- Artifacts: `docs/feature/ws-fed/discuss/*` and bootstrap `docs/product/**` only.
- No application code, no parity/roadmap edits, no DESIGN architecture docs.
- Protocol names are domain language; Go packages / CI YAML are not.
- Peer review required before DESIGN handoff.

---

## Risks surfaced (not managed here)

| Risk | P | I | Note |
|---|---|---|---|
| A1 still not usage-validated (unnamed third party) | M | M | Ledger gap + demand class; stranger is chosen not past-run |
| Reply URL registration shape undecided | L | M | DESIGN; requirement is registered-for-that-app |
| G1 interview count = 1 | H | L | Stated; not padded |
| Unsigned / SAML-only document not parsed in spike | L | M | US-01 is the emulator document; H2 used Entra + serializer |

---

## Artifacts in this folder

- `journey-ws-fed-sign-in-visual.md` (copy; SSOT `docs/product/journeys/`)
- `journey-ws-fed-sign-in.yaml` (copy; Gherkin embedded per step)
- `shared-artifacts-registry.md`
- `story-map.md`
- `prioritization.md`
- `user-stories.md`
- `outcome-kpis.md`
- `dor-validation.md`
- `wave-decisions.md` (this file)

Product SSOT:

- `docs/product/vision.md`
- `docs/product/jobs.yaml`
- `docs/product/journeys/ws-fed-sign-in.yaml`
- `docs/product/journeys/ws-fed-sign-in-visual.md`
