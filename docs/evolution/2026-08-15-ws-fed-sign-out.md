# Evolution — ws-fed-sign-out

**Feature:** `ws-fed-sign-out`  
**Dates:** 15 Aug 2026 (waves + DELIVER + finalize)  
**Branch:** `feat/ws-fed-sign-out`  
**Shape:** witness advertised WS-Federation **passive** sign-out (`wa=wsignout1.0`) on the same `/{tid}/wsfed` as v0.8.0 sign-in

---

## Feature summary

Priya Chen (developer-as-user) already pointed an existing ASP.NET Tasks API at the emulator for v0.8.0 sign-in. FederationMetadata already advertised sign-out on `PassiveRequestorEndpoint` = `/{tid}/wsfed`. This cut **witnesses** that URL.

`GET|POST /{tid}/wsfed` dispatches on `wa` **before** mint. `wa=wsignout1.0` never mints `wresult`. The emulator 302s to an **exact** registered `wsfed-reply`. The shared session ends (`clearSession` + ForgetSessionApps). The next `wsignin1.0` is Pick an account. Walking skeleton `SignOutWreply` is distinct from `CallbackPath`. Unmodified `Microsoft.AspNetCore.Authentication.WsFederation` completes SignOut (`e2e/wsfed`).

**Quality #1:** auditability — wrap `/{tid}/wsfed` with flow `wsfed`; `ClientID` is `wtrealm`; never persist or log `wresult`.

**North star (KPI-1):** `python3 e2e/run.py wsfed` green **including SignOut**.

**Job:** same `point-ws-fed-rp-at-local-sts` (no second JTBD).

**Parity:** `docs/parity.md` WS-Federation row stays 🟢 Real. Do not revert.

**Out of this cut:** SOAP / active WS-Trust, `/common/wsfed`, SAML 1.1, multi-RP `wsignoutcleanup1.0`, MFA/CA, SOAP SLO.

---

## Business context

v0.8.0 grew FederationMetadata and answered `wa=wsignin1.0`. Sign-out was advertised and **frozen** (`TestSignOutIsAdvertisedWithoutASignOutWitness` / `signOutForbiddenTrip`). `handleWSFed` did not branch on `wa`, so a live session on `wsignout1.0` could SSO-deliver a `wresult`.

DISCOVER and DIVERGE were skipped (same as v0.8.0: protocol gap + locked stranger, G1 interview count = 1). JTBD skipped — this extends the existing job.

---

## Key decisions

Extracted from wave-decisions. Architecture SSOT is **`docs/product/architecture/`** (not `docs/adrs/` or `docs/architecture/ws-fed-sign-out/`). Journeys SSOT is **`docs/product/journeys/`**.

| Wave | Decision |
|---|---|
| DISCOVER / DIVERGE | **Skipped.** Same locked stranger as v0.8.0. Risk recorded, not padded. |
| SPIKE | Library `SignOut` GET-redirects `wa=wsignout1.0` with **no `wresult`**. Multi-RP cleanup is the opposite direction and is not required for single-RP SignOut. **Return-URL trap:** unset `SignOutWreply` sends `wreply` = `CallbackPath`; GET `/signin-wsfed` without POST `wresult` fails the RP handler. |
| DISCUSS | Brownfield walking skeleton. Eight stories US-01–US-08. Same job `point-ws-fed-rp-at-local-sts`. **D12:** dispatch on `wa` before mint; never mint on sign-out. DEVOPS skipped later (existing CI already runs `wsfed`). |
| DESIGN | Extend existing `handleWSFed`. Reuse `clearSession` + typed `wsfed-reply`. Distinct `SignOutWreply`. ADR-006 supersedes ADR-001 witness freeze; metadata URL decision stands. Rejected: OIDC logout alias, new `/wsfed/signout` path, new cookie, Go-only stranger. |
| DISTILL | Strategy C (real local, no containers). Gherkin under `tests/acceptance/ws-fed-sign-out/` (do not mix `@pending` into green `tests/acceptance/ws-fed/`). DEVOPS artifacts missing → default env matrix. |
| DELIVER | 10/10 steps COMMIT EXECUTED. Integrity CLI passed. Adversarial review **APPROVED** (zero testing theater). L1–L4 refactor `ed0d7b2`. |
| Mutation | **SKIPPED** (Go; nWave mutators are cosmic-ray / PIT / Stryker). Report lived in the feature workspace; summary is this document. |
| DEVOPS | **Skipped** — existing CI already runs `python3 e2e/run.py … wsfed`. No new pipeline or deployable. |

Rejected simpler/heavier alternatives (DESIGN): alias onto OIDC `/{tid}/oauth2/v2.0/logout`; new `/{tid}/wsfed/signout` path; new WS-Fed-only cookie; in-process-Go-only as the stranger; 302 to `/signin-wsfed` without `SignOutWreply`; multi-RP `wsignoutcleanup1.0` fan-out.

---

## Steps completed

Roadmap was 10 steps in 4 phases (workspace still on disk pending Phase C approval). Execution log: every step had PREPARE → RED_ACCEPTANCE → RED_UNIT (SKIPPED NOT_APPLICABLE — HTTP driving-port tests pin the contract) → GREEN → COMMIT, all `EXECUTED` / `PASS`.

| Step | Name | Commit | COMMIT (UTC) |
|---|---|---|---|
| 01-01 | Enable WS-1 clean sign-out | `813b7bd` | 2026-08-15T14:44:17Z |
| 01-02 | FederationMetadata guardrail | `f671163` | 2026-08-15T14:46:48Z |
| 01-03 | Dispatch without minting (unknown `wa`) | `0700789` | 2026-08-15T14:49:48Z |
| 01-04 | Picker still lists Alice | `1a51497` | 2026-08-15T14:52:06Z |
| 02-01 | Audit | `17dcc47` | 2026-08-15T14:54:57Z |
| 03-01 | Unknown/empty `wtrealm` | `b5fbfa0` | 2026-08-15T14:59:24Z |
| 03-02 | Allowlist return (omitted `wreply` → registered `wsfed-reply`) | `fda2ed5` | 2026-08-15T15:03:18Z |
| 03-03 | Unsolicited + SOAP stay refused | `a6b53fd` | 2026-08-15T15:05:16Z |
| 04-01 | OIDC/SAML + stale directory | `978737d` | 2026-08-15T15:08:14Z |
| 04-02 | Witness unmodified library SignOut | `2d1c125` | 2026-08-15T15:13:31Z |

Post-roadmap: L1–L4 refactor `ed0d7b2` (2026-08-15T15:22:01Z). Post-merge gate PASS (`go test ./internal/server/ ./internal/identity/`; `python3 e2e/run.py wsfed` including SignOut).

---

## Lessons learned

1. **Return-URL trap:** `SignOutWreply` ≠ `CallbackPath`. If the library sends the sign-in callback as `wreply`, GET `/signin-wsfed` without POST `wresult` fails the RP handler. Walking skeleton registers two `wsfed-reply` URIs.
2. **DISCUSS D12 — dispatch before mint.** A live session on `wsignout1.0` must not SSO-deliver a token. The branch belongs in the existing adapter, before RSTR mint.
3. **Freeze tests are superseded, not deleted as metadata advertisement.** v0.8.0 `TestSignOutIsAdvertisedWithoutASignOutWitness` / `signOutForbiddenTrip` encoded a walking-skeleton bound. Witnessing sign-out replaces the freeze; FederationMetadata still advertises the same PassiveRequestorEndpoint.
4. **Go mutation is not available** in this nWave install. Skip with a written report rather than a fake kill rate.
5. **DEVOPS is optional when CI already exists.** Existing `sdk-e2e` already runs `wsfed`; this cut extends the same suite with SignOut.
6. **This repo’s architecture SSOT is `docs/product/`.** Finalize must not invent `docs/adrs/` or `docs/architecture/ws-fed-sign-out/` copies. Journeys stay in `docs/product/journeys/`.

---

## Issues encountered

| Issue | Resolution |
|---|---|
| DISCOVER/DIVERGE skipped; G1 interview count = 1 | Stated, not padded. Feature proceeded on protocol gap + locked witness. |
| DISCUSS examples reused `/signin-wsfed` as sign-out return | Spike measured the trap. DESIGN/DISTILL use distinct `https://rp.example.test/wsfed-signed-out`. |
| DISTILL DEVOPS artifacts missing | Default environment matrix (`clean` / `with-pre-commit` / `with-stale-config`). |
| `kpi-contracts.yaml` missing | KPIs from `discuss/outcome-kpis.md`. |
| Mutation tooling is Python/Java/JS | SKIPPED for Go production surface. |
| Adversarial review | APPROVED (zero testing-theater patterns). |

---

## Permanent artifacts (already SSOT — not duplicated at finalize)

| Artifact | Path |
|---|---|
| Architecture brief | `docs/product/architecture/brief.md` |
| ADR-001 Grow existing FederationMetadata | `docs/product/architecture/adr-001-grow-existing-federationmetadata.md` (witness freeze superseded) |
| ADR-002 `wsfed-reply` redirect type | `docs/product/architecture/adr-002-wsfed-reply-redirect-type.md` |
| ADR-003 Reuse account picker Kind | `docs/product/architecture/adr-003-reuse-account-picker-kind.md` |
| ADR-004 Audit existing recorder | `docs/product/architecture/adr-004-audit-existing-recorder.md` |
| ADR-005 `e2e/wsfed` sibling | `docs/product/architecture/adr-005-e2e-wsfed-sibling.md` |
| ADR-006 Sign-out dispatch | `docs/product/architecture/adr-006-wsfed-sign-out-dispatch.md` |
| Journey | `docs/product/journeys/ws-fed-sign-out.yaml` |
| Journey visual | `docs/product/journeys/ws-fed-sign-out-visual.md` |
| Vision / jobs | `docs/product/vision.md`, `docs/product/jobs.yaml` |
| Parity | `docs/parity.md` (WS-Federation 🟢 Real; SignOut witnessed) |
| Gherkin | `tests/acceptance/ws-fed-sign-out/` |
| Stranger | `e2e/wsfed/` (extended; distinct `SignOutWreply`) |
| CI | `.github/workflows/ci.yml` (`python3 e2e/run.py … wsfed`) |

### Migrated at finalize (Phase B)

DISTILL scenario docs copied for permanence. DISTILL-time `@pending` / RED rows are historical; all 10 DELIVER steps completed.

| Source | Destination |
|---|---|
| `docs/feature/ws-fed-sign-out/distill/test-scenarios.md` | `docs/scenarios/ws-fed-sign-out/test-scenarios.md` |
| `docs/feature/ws-fed-sign-out/distill/walking-skeleton.md` | `docs/scenarios/ws-fed-sign-out/walking-skeleton.md` |

**Not migrated (would duplicate SSOT):** DESIGN ADRs, architecture brief, DISCUSS journey copies. Spike findings are summarized in this document.

---

## Phase C — cleanup (awaiting approval)

Do **not** delete until the user approves. Candidate list — every file still under `docs/feature/ws-fed-sign-out/`:

| Path | Why discard |
|---|---|
| `deliver/execution-log.json` | Audit trail captured in this evolution doc |
| `deliver/roadmap.json` | Step plan — superseded by this document + git history |
| `deliver/.develop-progress.json` | Resume state — temporary |
| `deliver/implementation-review.md` | Verdict captured above (APPROVED) |
| `deliver/mutation/mutation-report.md` | Skip captured above |
| `design/wave-decisions.md` | Decisions extracted above |
| `design/upstream-changes.md` | Return-URL trap captured in ADR-006 + this document |
| `distill/acceptance-review.md` | Tests remain in `tests/acceptance/ws-fed-sign-out/` |
| `distill/test-scenarios.md` | Copied to `docs/scenarios/ws-fed-sign-out/` |
| `distill/walking-skeleton.md` | Copied to `docs/scenarios/ws-fed-sign-out/` |
| `distill/wave-decisions.md` | Decisions extracted above |
| `discuss/wave-decisions.md` | Decisions extracted above |
| `discuss/dor-validation.md` | Process gate |
| `discuss/shared-artifacts-registry.md` | Process scaffolding |
| `discuss/outcome-kpis.md` | KPIs summarized above |
| `discuss/user-stories.md` | Stories executed; git history remains |
| `discuss/story-map.md` | Superseded by roadmap execution |
| `discuss/journey-ws-fed-sign-out.yaml` | Canonical copy is `docs/product/journeys/ws-fed-sign-out.yaml` |
| `discuss/journey-ws-fed-sign-out-visual.md` | Canonical copy is `docs/product/journeys/ws-fed-sign-out-visual.md` |
| `spike/findings.md` | Return-URL trap and SignOut wire captured in ADR-006 + this document |

On approval: `rm -rf docs/feature/ws-fed-sign-out/`. If `docs/feature/` is then empty, remove it too. Lasting truth stays under `docs/product/`, `docs/evolution/`, `docs/scenarios/ws-fed-sign-out/`, `tests/acceptance/ws-fed-sign-out/`, and `e2e/wsfed/`.

---

## Finalize status

| Phase | Status |
|---|---|
| A Evolution document | **Done** — this file |
| B Migrate lasting artifacts | **Done** — scenario copies only; architecture/journeys already permanent |
| C Cleanup workspace | **Awaiting approval** — list above; workspace left on disk |
| D Commit | Evolution + scenario copies + product SSOT + parity. No push. No cleanup commit. |
