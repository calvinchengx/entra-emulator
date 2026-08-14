# Test scenarios — ws-fed

**Feature ID:** `ws-fed`  
**Date:** 14 Aug 2026  
**Gherkin SSOT:** `tests/acceptance/ws-fed/`  
**Go analog:** `internal/server/wsfed_walking_skeleton_test.go` (package `server`)

KPI source: `docs/feature/ws-fed/discuss/outcome-kpis.md` (`kpi-contracts.yaml` missing).  
Scope boundary: US-01–US-08 in `docs/feature/ws-fed/discuss/user-stories.md`.

## Counts

| Category | Count |
|---|---|
| Total scenarios | 35 |
| Walking skeletons | 4 (1 enabled, 3 `@pending`) |
| Focused | 31 |
| Error / unsafe-refuse / boundary | 14 |
| Error-path ratio | **40%** (14/35) |
| `@kpi` | KPI-1 (WS-4) + KPI-5 (refuse-unsafe feature) |
| Enabled now | 1 |

Edge extras counted with happy/focused (omitted `wctx`, POST challenge) are not in the 14.

## One-at-a-time sequence (DELIVER)

Enable in this order. Only step 1 is unskipped today.

1. WS-1 clean E2E (US-01–US-04 in-process) — **RED now**
2. US-01 remaining (certs, sign-out advertised, IDPSSODescriptor, `saml-metadata` flow, no second URL)
3. US-02 POST challenge + omitted `wctx`
4. US-03 password chrome + parameter survival + disabled user
5. US-04 remaining token fields (Audience, Issuer, `wctx` echo/omit, SAML 2.0, NameID)
6. Audit Admin + Graph (challenge, success+user, refuse+Reason, no token body, URI identity, interactive)
7. Guardrail `e2e/saml` + existing OIDC
8. US-06 unknown / empty `wtrealm` + no Location to unowned URL
9. US-07 missing / unregistered / `saml-acs`-only / `web`-only / cross-app `wreply`
10. US-08 unsolicited `wresult` + no allow flag
11. WS-2 with-pre-commit, WS-3 with-stale-config
12. WS-4 KPI-1 `e2e/wsfed` stranger (US-05)

## Gherkin ↔ Go map

Comments in Go tests name the Gherkin scenario. Step methods are Go helpers in package `server` (no Python `steps/`).

### walking-skeleton.feature

| Scenario | Go test | Status |
|---|---|---|
| Priya completes Tasks API WS-Fed sign-in on a clean emulator | `TestPriyaCompletesTasksAPIWSFedSignIn` | **enabled / RED** |
| Priya completes Tasks API WS-Fed sign-in alongside existing OIDC and SAML | `TestPriyaCompletesWSFedSignInAlongsideOIDCAndSAML` | `t.Skip` |
| Priya completes Tasks API WS-Fed sign-in after registering a reply on a stale directory | `TestPriyaCompletesWSFedSignInAfterRegisteringReplyOnStaleDirectory` | `t.Skip` |
| Priya's unmodified WsFederation middleware completes sign-in | `TestUnmodifiedWsFederationCompletesSignIn` | `t.Skip` (see `e2e/wsfed/README.md`) |

### metadata-and-challenge.feature

| Scenario | Go test | Status |
|---|---|---|
| Signing certificates in both sections match | covered by WS-1 assertions once RoleDescriptor exists; dedicated unskip not required | `@pending` |
| Sign-out is advertised without a sign-out witness | DELIVER: `TestSignOutIsAdvertisedWithoutASignOutWitness` | `@pending` |
| SAML apps still see their descriptor | `TestExistingSAMLSignInStillCompletesAfterWSFedMetadataGrowth` (IDPSSODescriptor) | `t.Skip` |
| Metadata fetch stays a saml-metadata audit flow | DELIVER: `TestMetadataFetchStaysSamlMetadataAuditFlow` | `@pending` |
| Priya is not sent to a second metadata URL | DELIVER: `TestPriyaIsNotSentToASecondMetadataURL` | `@pending` |
| POST as well as GET can start sign-in | `TestPOSTAsWellAsGETCanStartSignIn` | `t.Skip` |
| Optional context is accepted on the challenge | DELIVER: `TestOptionalContextIsAcceptedOnTheChallenge` | `@pending` |

### account-picker.feature

| Scenario | Go test | Status |
|---|---|---|
| Password-required mode stays the existing form | `TestPasswordRequiredModeStaysTheExistingForm` | `t.Skip` |
| Challenge parameters survive account choice | covered by WS-1 `wctx` echo | `@pending` |
| Disabled user is not listed as selectable | DELIVER: `TestDisabledUserIsNotListedAsSelectable` | `@pending` |

### wresult-token.feature

| Scenario | Go test | Status |
|---|---|---|
| Token audience matches the application ID URI | WS-1 Audience assertion | `@pending` (focused) |
| Issuer matches federation metadata | DELIVER: `TestIssuerMatchesFederationMetadata` | `@pending` |
| Context is echoed unchanged | WS-1 `wctx` assertion | `@pending` (focused) |
| Omitted context stays omitted | DELIVER: `TestOmittedContextStaysOmitted` | `@pending` |
| Assertion version is SAML 2.0 for this witness | WS-1 SAMLV2.0 / Version 2.0 | `@pending` (focused) |
| NameID format is persistent | DELIVER: `TestNameIDFormatIsPersistent` | `@pending` |

### refuse-unsafe.feature

| Scenario | Go test | Status |
|---|---|---|
| Unknown application ID URI does not issue a token to the caller reply | `TestUnknownWtrealmDoesNotIssueAToken` | `t.Skip` |
| Empty realm is refused | `TestEmptyRealmIsRefused` | `t.Skip` |
| Unknown realm never redirects to an unowned URL | same as unknown `wtrealm` (`Location` check) | `@pending` |
| Unregistered reply URL does not receive a token | `TestUnregisteredWreplyDoesNotReceiveAToken` | `t.Skip` |
| Missing reply URL does not receive a token | `TestMissingWreplyDoesNotReceiveAToken` | `t.Skip` |
| Reply registered only as saml-acs is refused | `TestSAMLACSOnlyReplyIsRefused` | `t.Skip` |
| Reply registered only as web is refused | `TestWebOnlyReplyIsRefused` | `t.Skip` |
| Another app's reply is not accepted | `TestAnotherAppsReplyIsNotAccepted` | `t.Skip` |
| A token POST that did not start at this STS is refused | `TestUnsolicitedWresultIsRefused` | `t.Skip` |
| Unsolicited login is not offered as a setting | documentation + US-08 refuse (no flag to implement) | `@pending` |

### audit-observability.feature

| Scenario | Go test | Status |
|---|---|---|
| Challenge and successful sign-in are recorded without a token body | `TestWSFedChallengeAndSuccessAppearInAudit` | `t.Skip` |
| A refused challenge is recorded with a concrete reason | `TestRefusedChallengeIsRecordedWithReason` | `t.Skip` |
| Graph sign-ins identify the Tasks API and mark the exchange interactive | same audit test; Graph path `/graph/v1.0/auditLogs/signIns` (DESIGN name `GET /{tid}/v1.0/auditLogs/signIns`) | `t.Skip` |

### guardrail-saml-oidc.feature

| Scenario | Go test | Status |
|---|---|---|
| Existing SAML sign-in still completes after WS-Fed metadata growth | `TestExistingSAMLSignInStillCompletesAfterWSFedMetadataGrowth` | `t.Skip` |
| Existing OIDC sign-in still completes | `TestExistingOIDCSignInStillCompletes` | `t.Skip` |

## Story coverage

| Story | Scenarios |
|---|---|
| US-01 | WS-1, certs, sign-out, IDPSSODescriptor, `saml-metadata` flow, no second URL |
| US-02 | WS-1, POST challenge, optional `wctx` |
| US-03 | WS-1 picker chrome, password mode, parameter survival, disabled user |
| US-04 | WS-1 `wresult` POST, Audience, Issuer, `wctx` echo/omit, SAML 2.0, NameID |
| US-05 | WS-4 KPI-1 stranger; guardrail OIDC/SAML |
| US-06 | unknown / empty `wtrealm`; no Location to unowned URL |
| US-07 | unregistered / missing / `saml-acs`-only / `web`-only / cross-app `wreply`; WS-3 stale |
| US-08 | unsolicited `wresult`; no allow flag |

## Planned unit-test locations (pyramid)

DELIVER inner loop (not written here):

- `internal/identity/` — RSTR mint, Kind `wsfed` state, refuse reasons
- `internal/store/` — typed `wsfed-reply` lookup (not `HasRedirectURI`)
- `internal/graph/` — `Flow=wsfed` URI → `appDisplayName`, interactive

Acceptance stays on driving ports in `internal/server/wsfed_*_test.go` plus `e2e/wsfed` and existing `e2e/saml` / OIDC suites.

## Mandate compliance evidence (CM-A/B/C/D)

**CM-A (driving ports):** `wsfed_walking_skeleton_test.go` imports `net/http` and `internal/store` only (store used to set **preconditions**: app + `wsfed-reply`). Exercise path is `http.Get` / `PostForm` against `httptest.Server` — FederationMetadata and `/{tid}/wsfed`. Zero imports of unexported Identity handlers.

**CM-B (business language):** Gherkin uses Priya, Tasks API, FederationMetadata, `wa`, `wtrealm`, `wreply`, `wresult`, `wctx`, `wsignin1.0` (DISCUSS domain language). HTTP paths live in comments / `@driving_port`, not scenario titles.

**CM-C (journeys):** 4 walking skeletons (user goal: complete sign-in / stranger session) + 31 focused boundary scenarios.

**CM-D:** See `wave-decisions.md` DWD / Mandate 4. Fixtures do not mint `wresult` (no Fixture Theater).
