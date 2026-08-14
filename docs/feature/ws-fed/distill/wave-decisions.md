# Wave decisions — ws-fed (DISTILL)

**Feature ID:** `ws-fed`  
**Wave:** DISTILL (acceptance-designer / Quinn)  
**Date:** 14 Aug 2026  
**Command:** `*create-acceptance-tests` (all 4 phases)

---

## Prior-wave reading checklist

| Status | Artifact |
|---|---|
| ✓ | `docs/product/journeys/ws-fed-sign-in.yaml` |
| ✓ | `docs/product/architecture/brief.md` — DISTILL handoff is **§ Handoff — DISTILL** (no `## For Acceptance Designer` heading) |
| ✓ | `docs/product/architecture/adr-001` through `adr-005` |
| ⊘ | `docs/product/kpi-contracts.yaml` (not found) |
| ✓ | `docs/feature/ws-fed/discuss/user-stories.md` |
| ✓ | `docs/feature/ws-fed/discuss/story-map.md` |
| ✓ | `docs/feature/ws-fed/discuss/wave-decisions.md` |
| ✓ | `docs/feature/ws-fed/discuss/outcome-kpis.md` |
| ✓ | `docs/feature/ws-fed/spike/findings.md` |
| ✓ | `docs/feature/ws-fed/design/wave-decisions.md` |
| ⊘ | `docs/feature/ws-fed/devops/wave-decisions.md` (not found) |
| ✓ | Analog tests: `internal/server/saml_sso_test.go`, `saml_metadata_test.go`, `signin_logs_test.go`, `e2e/saml/suite.mjs` |

**Migration:** `docs/product/` exists. Not an old-model fallback.

---

## Warnings (graceful degradation)

- **DEVOPS artifacts missing -- using default environment matrix** (`clean` | `with-pre-commit` | `with-stale-config`). Do not block.
- **KPI contracts missing** (`docs/product/kpi-contracts.yaml`). Proceed. KPI source is `docs/feature/ws-fed/discuss/outcome-kpis.md`. Tag KPI-1 and KPI-5 scenarios `@kpi`.

---

## Reconciliation

Checked DISCUSS D1–D12 against DESIGN D1–D8 and SPIKE S3b / H2.

- DESIGN locked redirect type `wsfed-reply`. DISCUSS D6 deferred storage shape to DESIGN. **Not a contradiction.**
- DESIGN ranked auditability #1. That ranking does not change US-01–US-08. **Not a contradiction.**
- TokenType SAML 2.0 (S3b), grow existing FederationMetadata (H2), both endpoints `/{tid}/wsfed`, same cert, registered `wreply`, unsolicited refused, same picker, no SOAP / `/common/wsfed` / SAML 1.1 / witnessed SLO: **aligned**.

**Reconciliation passed -- 0 contradictions**

---

## Decisions

- [DWD-01] Walking skeleton strategy **C (Real local)**: real SQLite, real HTTP (`httptest.Server` / local emulator), real .NET stranger subprocess. **No containers.** WS scenarios tagged `@walking_skeleton @real-io @driving_adapter @driving_port`.
- [DWD-02] Mandate 7 (RED scaffolds) is **N/A for new packages**. Production packages exist. Missing `/{tid}/wsfed` route is HTTP 404; missing RoleDescriptor is SAML-only metadata. That is RED (assertion failure), not BROKEN (ImportError). Do **not** add `SCAFFOLD: true` panic handlers into `internal/identity` (would break `Register`).
- [DWD-03] Runner is Go `testing` + `httptest` in `internal/server/*_test.go` (SAML analog). Gherkin under `tests/acceptance/ws-fed/` is the nWave SSOT for DELIVER `test_file` / `scenario_name`. No pytest-bdd / godog.
- [DWD-04] KPI-1 stranger (`e2e/wsfed`) is a documented `@pending` scenario plus `e2e/wsfed/README.md`. No half-broken .csproj in DISTILL.
- [DWD-05] Protocol names are domain language: `wa`, `wtrealm`, `wreply`, `wresult`, `wctx`, FederationMetadata, `wsignin1.0`. HTTP paths appear in `@driving_port` comments, not as scenario titles.
- [DWD-06] Tenant-agnostic examples only: `{tid}`, `api://tasks-api`, `https://rp.example.test/signin-wsfed`.
- [DWD-07] Do not invent disk-full / permission-denied infrastructure-failure theater. Driven adapters are covered via `@real-io` on WS / refuse / audit scenarios (SAML analog).
- [DWD-08] Out of scope (no scenarios that require production behavior): SOAP, `/common/wsfed`, SAML 1.1 minting, witnessed `wsignout1.0`, IdP-initiated, encryption, MFA/CA, portal/Graph as sign-in.
- [DWD-09] Default environment matrix applied on walking skeletons: clean (enabled), with-pre-commit (`@pending`), with-stale-config (`@pending`).
- [DWD-10] One-at-a-time: only the first walking-skeleton scenario is enabled. All other Gherkin scenarios are `@pending`; matching Go tests call `t.Skip`.

---

## Adapter coverage (Mandate 6 / Strategy C)

Driven adapters from DESIGN component boundaries. No new datastore.

| Adapter | @real-io scenario | Covered by |
|---|---|---|
| Store (SQLite) | YES | WS clean (`registerTasksAPI` + real `AddRedirectURI` type `wsfed-reply`); refuse US-07 type filter |
| Tokens / signing (tenant cert) | YES | WS clean (RoleDescriptor cert must match IDPSSODescriptor; assertion signature) |
| Audit recorder (in-process) | YES | `audit-observability.feature` challenge / success / refuse + no token body |

No disk-full / permission-denied rows: SAML tests do not have them; DWD-07.

---

## Driving adapter verification

| DESIGN entry point | HTTP/protocol scenario |
|---|---|
| FederationMetadata GET existing URL | WS-1 + `metadata-and-challenge.feature` |
| `GET\|POST /{tid}/wsfed` `wa=wsignin1.0` | WS-1 + POST focused US-02 |
| Account picker | WS-1 + `account-picker.feature` |
| Browser auto-POST `wresult` | WS-1 + `wresult-token.feature` |
| Admin `GET /admin/api/audit` | `audit-observability.feature` |
| Graph `GET /{tid}/v1.0/auditLogs/signIns` | `audit-observability.feature` (compat path `/graph/v1.0/auditLogs/signIns` in Go tests, same as `signin_logs_test.go`) |
| Stranger `e2e/wsfed` | WS-4 `@kpi @pending` |
| Refuse-unsafe | `refuse-unsafe.feature` |
| Guardrail OIDC + `e2e/saml` | `guardrail-saml-oidc.feature` |

Zero uncovered DESIGN entry points.

---

## Mandate 4 / CM-D (Go emulator)

Business rules (realm lookup, typed `wsfed-reply`, unsolicited correlation, RSTR shape) live in production Identity handlers, not in test fixtures. Fixture parametrization is the thin HTTP adapter (`newTestServer` ephemeral SQLite). Environment matrix is Given preconditions on walking skeletons, not a pytest fixture matrix. Pure-function extraction is DELIVER inner-loop work (existing SAML analog).

---

## Peer review

Iteration 1: **approved** (`nw-acceptance-designer-reviewer` Sentinel, 2026-08-14). 0 critical / 0 high. Informational only: error-path ratio exactly 40%. YAML: `docs/feature/ws-fed/distill/acceptance-review.md`. Iteration 2 not required.

## Out of DISTILL (locked)

- No production WS-Fed handlers
- No edits to `docs/parity.md`, `docs/17-roadmap.md`, DESIGN ADRs, or `CLAUDE.md`
