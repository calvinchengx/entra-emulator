# DESIGN Decisions — ws-fed

**Feature ID:** `ws-fed`  
**Wave:** DESIGN (solution-architect / Morgan)  
**Date:** 14 Aug 2026  
**Mode:** Guide (all questions answered by parent; no clarification wait)  
**Scope:** Application / components only (`## Application Architecture`)

Peer review: **approved** (`nw-solution-architect-reviewer` Atlas, iteration 1, 0 critical / 0 high). YAML and low-item revisions: `docs/feature/ws-fed/design/review.md`. DISTILL is unblocked.

---

## Prior-wave reading checklist

| Status | Artifact |
|---|---|
| ⊘ | `docs/product/architecture/brief.md` (did not exist — DESIGN bootstrapped `docs/product/architecture/`) |
| ⊘ | `docs/product/architecture/adr-*.md` (none prior) |
| ✓ | `docs/product/journeys/ws-fed-sign-in.yaml` |
| ✓ | `docs/feature/ws-fed/discuss/wave-decisions.md` |
| ✓ | `docs/feature/ws-fed/discuss/user-stories.md` |
| ✓ | `docs/feature/ws-fed/discuss/story-map.md` |
| ✓ | `docs/feature/ws-fed/discuss/outcome-kpis.md` |
| ✓ | `docs/feature/ws-fed/spike/findings.md` |

**Migration:** `docs/product/` exists (DISCUSS bootstrapped vision/jobs/journeys). First architecture — created `docs/product/architecture/`. Not an old-model migration.

**Contradictions with DISCUSS/SPIKE:** none. Walking skeleton is v0.8.0; SAML 2.0 in `wresult` (S3b); grow existing FederationMetadata; both PassiveRequestorEndpoint and SecurityTokenServiceEndpoint = `/{tid}/wsfed`; same signing cert; registered `wreply`; unsolicited refused; same account picker; no SOAP, `/common/wsfed`, SAML 1.1, witnessed SLO.

---

## Key Decisions

- [D1] Pattern: modular monolith + ports-and-adapters as already exists. One process, one Identity STS package. No new deployable or datastore. (see: `docs/product/architecture/brief.md`)
- [D2] Grow existing FederationMetadata with WS-Fed RoleDescriptor; both endpoints `/{tid}/wsfed`; same cert; metadata audit flow stays `saml-metadata`. (see: `docs/product/architecture/adr-001-grow-existing-federationmetadata.md`)
- [D3] New redirect type `wsfed-reply` on `app_redirect_uris`. `wtrealm` → existing Application ID URI lookup. Do not reuse `saml-acs` or OIDC URIs. Do not use type-blind `HasRedirectURI`. (see: `docs/product/architecture/adr-002-wsfed-reply-redirect-type.md`)
- [D4] Reuse existing account picker via signed state Kind (e.g. `"wsfed"`) posting back to `/{tid}/wsfed`. No second login UI. Kind is also unsolicited-login correlation. (see: `docs/product/architecture/adr-003-reuse-account-picker-kind.md`)
- [D5] Auditability ranked #1: wrap `GET|POST /{tid}/wsfed` with `audited("wsfed")`; `ClientID` = `wtrealm`; subject after picker; concrete `Reason` on US-06/07/08; never persist `wresult`. KPI-1 stranger still required. Graph/Admin project the same recorder. (see: `docs/product/architecture/adr-004-audit-existing-recorder.md`)
- [D6] Witness is new `e2e/wsfed` (unmodified `Microsoft.AspNetCore.Authentication.WsFederation`). Do not extend `e2e/dotnet`. Do not ship in-process-Go-only as the stranger. (see: `docs/product/architecture/adr-005-e2e-wsfed-sibling.md`)
- [D7] Paradigm: Go, OOP-native, match existing Identity handlers. Project `CLAUDE.md` not edited.
- [D8] Token: RSTR wrapping SAML 2.0 (`…#SAMLV2.0`, `Version="2.0"`); Audience = `wtrealm`; Issuer = metadata entityID; NameID format persistent (spike). Sign-out advertised; `wsignout1.0` not witnessed.

## Architecture Summary

- Pattern: modular monolith with ports-and-adapters (HTTP driving; Store / Tokens / Audit driven)
- Paradigm: OOP (Go)
- Key components: Identity STS adapter (metadata + new `/wsfed`), Store (`wsfed-reply`), Tokens (same tenant cert), Audit recorder (`Flow=wsfed`), Graph/Admin projection, `e2e/wsfed` witness

## Technology Stack

- Go + stdlib XML: existing Identity / FederationMetadata stack
- Existing `goxmldsig` / `etree` (Apache-2.0 / BSD-2): assertion signature analog
- Existing `modernc.org/sqlite` (BSD-3): `app_redirect_uris` type `wsfed-reply`
- Unmodified `Microsoft.AspNetCore.Authentication.WsFederation` (Apache-2.0): KPI-1 witness only

## Constraints Established

- Single-process emulator; scale out of scope
- No SOAP listener, `/common/wsfed`, SAML 1.1, witnessed SLO, encryption, second metadata URL, second login UI
- Tenant-agnostic examples only (`{tid}`, `api://tasks-api`, `https://rp.example.test/signin-wsfed`)
- Enforcement: existing Go tests + e2e stranger; package-boundary discipline (identity vs store vs tokens vs audit); no ArchUnit
- External contract: `e2e/wsfed` is the consumer-driven contract for the WsFederation library; Pact not required

## Upstream Changes

None. DESIGN locked `wreply` storage (`wsfed-reply`), which DISCUSS D6 explicitly deferred. Auditability ranking is a DESIGN quality-attribute order; it does not change KPI-1 or user stories. No `docs/feature/ws-fed/design/upstream-changes.md`.

## Quality gates (self)

- [x] Requirements traced to components
- [x] Component boundaries with responsibilities
- [x] Technology choices in ADRs with ≥2 alternatives
- [x] Quality attributes addressed (auditability, interop, maintainability, security; scale out of scope)
- [x] Dependency inversion (HTTP adapter; Store/Tokens/Audit driven)
- [x] C4 L1 + L2 + compact L3 (Mermaid)
- [x] Integration patterns specified
- [x] OSS preference validated
- [x] AC behavioral (ports, not method signatures)
- [x] External integrations annotated (WsFederation → e2e/wsfed)
- [x] Architectural enforcement recommended
- [x] Peer review completed (approved, iteration 1; lows documented and applied)
