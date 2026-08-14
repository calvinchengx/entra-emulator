# Interview log — ws-fed

**Status:** second pass (maintainer interview #1 folded in). Documentary signals remain; they are **not** customer interviews.

entra-emulator's "customers" are developers pointing relying parties at a local STS. No quotes below were invented. Gate G1's "5+ interviews" is **still not met** (count = 1). See `problem-validation.md` and `wave-decisions.md`.

Skills loaded for this update: `nw-interviewing-techniques`, `nw-opportunity-mapping`, `nw-discovery-workflow`. `nw-product-discoverer/SKILL.md` was missing on disk; the agent spec was used instead.

---

## What this log is allowed to count as

| Counts as | Does not count as |
|---|---|
| Published protocol that Entra actually serves | "Would be nice to have WS-Fed" |
| A relying party product that documents hitting `/wsfed` | Future intent ("I would use the emulator") |
| This repo's current 404 / SAML-only metadata | Compliments about SAML shipping |
| A captured Entra WS-Fed POST (named, dated) | Fabricated developer quotes |
| Maintainer Mom Test answers (past behavior + commitment class) | Upgrading A1 to "validated by usage" when Q1 is never |

---

## Maintainer interview #1

| Field | Value |
|---|---|
| **#** | 1 |
| **Date** | 14 Aug 2026 |
| **Person** | Maintainer of entra-emulator (this user) |
| **Role** | Product owner / implementer — not an external RP consumer |
| **Method** | Mom Test Q1–Q5, answered as option labels via the parent agent |
| **Label** | **Maintainer interview #1.** Still the only interview. Not five. |

Answers are recorded **verbatim** as given. Gaps are labelled. Nothing is invented to fill them.

### Q1 — When last pointed a WS-Fed RP at Entra or this emulator?

> **Never — this is a ledger gap, not a consumer I have run**

- **Past behavior:** zero WS-Fed RP runs by this maintainer, against Entra or against this emulator.
- **Must not be read as:** usage validation of A1. The maintainer has not hit the 404 themselves.

### Q2 — Anyone blocked waiting on `/wsfed` on this emulator?

> **Yes — a third-party / downstream request; they workaround or skip**

- **What this is:** a **commitment / demand signal**. Someone downstream asked; they currently workaround or skip. A1 moves from "pure intent (thread start)" to "named demand class: third-party / downstream request."
- **What this is not:** a protocol observation, a named requester, a dated last attempt, or a described workaround.
- **Recorded gap:** third party **not named**. Date of request / last attempt **not given**. Workaround **not described**. Do not invent a name.

### Q3 — Which consumer should witness a v0.8.0-shaped green row?

> **Microsoft.AspNetCore.Authentication.WsFederation (SAML's node-saml analog)**

- **Locks A5:** the stranger is that library.
- **Not a past run:** Q1 is never. This is a **chosen witness**, not "when I last ran it against real Entra."

### Q4 — Sign-out?

> **Advertise wsignout in metadata like SAML did; do not witness SLO yet**

- **Locks A6** as advertise-only (SAML v0.6.0 pattern: `SingleLogoutService` in metadata, sign-in witnessed).

### Q5 — SOAP / active WS-Trust?

> **Active profile stays out even if it exists somewhere**

- **Locks A2:** passive (browser) only. SOAP / active WS-Trust is an explicit non-goal even if some client somewhere uses it.

---

## Documentary signals (not interviews)

Unchanged from the first pass. Summaries kept so this file remains the evidence index.

### D1 — Emulator surface today (this checkout, tagged v0.7.0)

- **When observed:** 14 Aug 2026, branch `main`.
- **Past behavior:** no `/{tenant}/wsfed` route (404). FederationMetadata is `IDPSSODescriptor` only. Login reuse via `Kind: "saml"` already exists for SAML.
- **Source:** this repo.

### D2 — Microsoft Entra federation metadata

- **URL:** https://learn.microsoft.com/en-us/entra/identity-platform/federation-metadata
- Entra publishes WS-Fed `RoleDescriptor` + `fed:PassiveRequestorEndpoint` = `/{tid}/wsfed` (and `/common/wsfed`) **in the same document** as SAML. Certs in both sections must match.

### D3 — Microsoft.AspNetCore.Authentication.WsFederation

- **URL:** https://learn.microsoft.com/en-us/aspnet/core/security/authentication/ws-federation
- `MetadataAddress` + `Wtrealm` (`api://...` for Entra). Default callback `/signin-wsfed`. Unsolicited logins off by default. **Now the locked v0.8.0 stranger** (interview #1 Q3).

### D4 — Dynamics 365 Business Central

- **URL:** https://learn.microsoft.com/en-us/dynamics365/business-central/dev-itpro/administration/authenticating-users-with-azure-active-directory
- Documents `/wsfed?wa=wsignin1.0&wtrealm=...&wreply=...`. WS-Fed removed in BC v22 (2023) in favour of OIDC. **Not** the chosen witness.

### D5 — SharePoint on-premises

- **URL:** https://learn.microsoft.com/en-us/entra/identity/saas-apps/sharepoint-on-premises-tutorial
- Operators must replace `/saml2` with `/wsfed` so Entra issues **SAML 1.1**. Proves the paths are not aliases. **Not** the chosen witness — A3 is no longer SharePoint-first.

### D6 — OASIS WS-Federation 1.2

- **URL:** https://docs.oasis-open.org/wsfed/federation/v1.2/os/ws-federation-1.2-spec-os.html
- Passive profile; `wa` MUST be `wsignin1.0`; `wresult` carries RSTR; sign-out `wsignout1.0` / `wsignoutcleanup1.0`.

### D7 — Independent capture of a live Entra WS-Fed POST (Scott Brady, Dec 2023)

- **URL:** https://www.scottbrady.io/ws-federation/understanding-ws-federation
- Captured `wresult` is a **SAML 2.0** assertion in an RSTR for an app-registration-style realm (`spn:...`). Closer to the ASP.NET `Wtrealm` job than to SharePoint. Still not a capture **this team** made against the locked stranger.

### D8 — SAML analog (v0.6.0)

- Real protocol + `@node-saml/node-saml` stranger. SLO advertised in metadata; sign-in witnessed. Interview #1 Q4 copies that pattern for WS-Fed.

### D9 — Inbound federation (Entra as RP)

- Adjacent. Entra-as-RP expects SAML 1.1 in an RSTR. Out of scope; do not mix with D7 or with the locked ASP.NET witness.

---

## Customer / maintainer interviews

| # | Date | Person | Role | Result |
|---|---|---|---|---|
| 1 | 14 Aug 2026 | Maintainer (this user) | Product owner | Q1 never-run (ledger gap). Q2 demand class: unnamed third-party / downstream; workaround or skip (name, date, workaround **not given**). Q3 locks ASP.NET WsFederation as witness (chosen, not a past run). Q4 advertise-only SLO. Q5 SOAP out. |
| 2–5 | — | — | — | **Not conducted.** |

---

## Signal count (honest)

| Kind | Count | Use |
|---|---|---|
| Independent documentary sources describing Entra's WS-Fed protocol surface | 5+ (D2–D7) | Protocol shape, classification |
| Published RPs that still document `/wsfed` | 3 | Consumer *candidates*; Q3 picked (a) |
| Mom Test interviews | **1** | G1 interview threshold **fails** (need 5+) |
| Commitment signals | **1 class** | Third-party / downstream request; requester unnamed |
| Maintainer past runs of a WS-Fed RP | **0** | A1 is not usage-validated |
