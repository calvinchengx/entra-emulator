# Test scenarios — ws-fed-sign-out

> Archived copy at finalize (15 Aug 2026) from `docs/feature/ws-fed-sign-out/distill/test-scenarios.md`.  
> Architecture SSOT: `docs/product/architecture/`. Journeys: `docs/product/journeys/`. Gherkin: `tests/acceptance/ws-fed-sign-out/`.  
> DISTILL-time status rows (`@pending`, `t.Skip`, RED) are historical. All 10 DELIVER steps completed.  
> KPI source after cleanup: `docs/evolution/2026-08-15-ws-fed-sign-out.md` (originally `docs/feature/ws-fed-sign-out/discuss/outcome-kpis.md`). Stories: originally `docs/feature/ws-fed-sign-out/discuss/user-stories.md`.

**Feature ID:** `ws-fed-sign-out`  
**Date:** 15 Aug 2026  
**Gherkin SSOT:** `tests/acceptance/ws-fed-sign-out/`  
**Go analog:** `internal/server/wsfed_sign_out_test.go` (package `server`)

KPI source: `docs/evolution/2026-08-15-ws-fed-sign-out.md` (`kpi-contracts.yaml` was never added).  
Scope boundary: US-01–US-08 (summarized in the evolution document).  
Return URL: DESIGN `https://rp.example.test/wsfed-signed-out` (supersedes DISCUSS examples that reused the sign-in callback).

## Counts

| Category | Count |
|---|---|
| Total scenarios | 29 |
| Walking skeletons | 4 (1 enabled, 3 `@pending`) |
| Focused | 25 |
| Error / unsafe-refuse / boundary | 16 |
| Error-path ratio | **55%** (16/29) |
| `@kpi` | KPI-1 (WS-4 pending) + KPI-2 (audit) + KPI-3 (refuse-unsafe) |
| Enabled now | 1 |

Walking skeletons counted as happy-path (the "must not mint" assertion is the success of sign-out). Focused "live session does not mint" is counted as error/failure-mode coverage (journey step 3: live session treated as sign-in).

## One-at-a-time sequence (DELIVER)

Enable in this order. Only step 1 is unskipped today.

1. WS-1 clean E2E (US-01–US-03 in-process) — **RED now** (`TestPriyaSignsAliceOutOfTheTasksAPI`)
2. US-01 remaining (metadata still names PassiveRequestorEndpoint, IDPSSODescriptor, no second URL)
3. US-02 dispatch (no mint focused, POST, idempotent, unknown `wa`)
4. US-03 picker after sign-out (Alice listed; choosing Alice still signs in)
5. US-04 audit Admin + Graph (success without token body, interactive, refuse+Reason)
6. US-05 guardrail existing SAML + OIDC (and WS-Fed sign-in still green)
7. US-06 unknown / empty `wtrealm` + no Location to unowned URL
8. US-07 missing / unregistered / `saml-acs` / `web` / cross-app return
9. US-08 unsolicited `wresult`, SOAP 404, `wsignout1.0`+`wresult` body does not mint, no allow flag
10. WS-2 with-pre-commit, WS-3 with-stale-config
11. WS-4 KPI-1 `e2e/wsfed` stranger SignOut (DELIVER extends `Program.cs`; DISTILL does not)

## Gherkin ↔ Go map

Comments in Go tests name the Gherkin scenario. Step methods are Go helpers in package `server` (no Python `steps/`).

### walking-skeleton.feature

| Scenario | Go test | Status |
|---|---|---|
| Priya signs Alice out of the Tasks API on a clean emulator | `TestPriyaSignsAliceOutOfTheTasksAPI` | **enabled / RED** |
| Priya signs Alice out alongside existing OIDC and SAML | `TestPriyaSignsAliceOutAlongsideOIDCAndSAML` | `t.Skip` |
| Priya signs Alice out after registering a distinct sign-out return on a stale directory | `TestPriyaSignsAliceOutAfterRegisteringDistinctReturnOnStaleDirectory` | `t.Skip` |
| Priya's unmodified WsFederation middleware completes SignOut | `TestUnmodifiedWsFederationCompletesSignOut` | `t.Skip` (DELIVER extends `e2e/wsfed`) |

### metadata-guardrail.feature

| Scenario | Go test | Status |
|---|---|---|
| Federation metadata still names the sign-out URL on the sign-in endpoint | `TestFederationMetadataStillNamesSignOutOnTheSignInEndpoint` | `t.Skip` |
| SAML apps still see their descriptor after sign-out is witnessed | `TestSAMLAppsStillSeeTheirDescriptorAfterSignOutIsWitnessed` | `t.Skip` |
| Priya is not sent to a second metadata URL for sign-out | `TestPriyaIsNotSentToASecondMetadataURLForSignOut` | `t.Skip` |
| Existing SAML sign-in still completes | `TestExistingSAMLSignInStillCompletesAfterWSFedSignOut` | `t.Skip` |
| Existing OIDC sign-in still completes | `TestExistingOIDCSignInStillCompletesAfterWSFedSignOut` | `t.Skip` |

### sign-out-dispatch.feature

| Scenario | Go test | Status |
|---|---|---|
| Sign-out with a live session does not mint a token | `TestSignOutWithALiveSessionDoesNotMintAToken` | `t.Skip` |
| Repeating SignOut with no session still returns to the registered reply | `TestRepeatingSignOutWithNoSessionStillReturnsToRegisteredReply` | `t.Skip` |
| POST as well as GET can sign out | `TestPOSTAsWellAsGETCanSignOut` | `t.Skip` |
| After sign-out Alice is still listed | `TestAfterSignOutAliceIsStillListed` | `t.Skip` |
| Choosing Alice after sign-out still completes sign-in | `TestChoosingAliceAfterSignOutStillCompletesSignIn` | `t.Skip` |
| Unknown wa is refused on the emulator | `TestUnknownWaIsRefusedOnTheEmulator` | `t.Skip` |
| Sign-out carrying a token body does not deliver a token | `TestSignOutCarryingATokenBodyDoesNotDeliverAToken` | `t.Skip` |

### refuse-unsafe.feature

| Scenario | Go test | Status |
|---|---|---|
| Unknown application ID URI does not return the browser to the caller URL | `TestUnknownWtrealmOnSignOutDoesNotReturnToCallerURL` | `t.Skip` |
| Empty realm is refused on sign-out | `TestEmptyRealmIsRefusedOnSignOut` | `t.Skip` |
| A SAML ACS is not accepted as a sign-out return | `TestSAMLACSIsNotAcceptedAsSignOutReturn` | `t.Skip` |
| An OIDC web callback is not accepted as a sign-out return | `TestWebCallbackIsNotAcceptedAsSignOutReturn` | `t.Skip` |
| Another app's reply is not accepted | `TestAnotherAppsReplyIsNotAcceptedOnSignOut` | `t.Skip` |
| Unregistered return does not receive the browser | `TestUnregisteredReturnDoesNotReceiveTheBrowserOnSignOut` | `t.Skip` |
| Missing return uses a registered wsfed-reply | `TestMissingReturnUsesARegisteredWSFedReply` | `t.Skip` |
| A token POST that did not start at this STS is still refused | `TestUnsolicitedWresultIsStillRefusedAfterSignOutCut` | `t.Skip` |
| SOAP stays absent | `TestSOAPStaysAbsent` | `t.Skip` |
| Unsolicited login is still not offered as a setting | `TestUnsolicitedLoginIsStillNotOfferedAsASetting` | `t.Skip` |

### audit-observability.feature

| Scenario | Go test | Status |
|---|---|---|
| Successful sign-out is recorded without a token body | `TestSuccessfulSignOutIsRecordedWithoutATokenBody` | `t.Skip` |
| Graph sign-ins still treat WS-Fed as interactive | `TestGraphSignInsStillTreatWSFedAsInteractiveAfterSignOut` | `t.Skip` |
| A refused sign-out is recorded with a concrete reason | `TestRefusedSignOutIsRecordedWithAConcreteReason` | `t.Skip` |

## Story coverage

| Story | Scenarios |
|---|---|
| US-01 | WS-1; metadata still names PassiveRequestorEndpoint; IDPSSODescriptor; no second URL |
| US-02 | WS-1; live session does not mint; POST; idempotent; unknown `wa` |
| US-03 | WS-1 next picker; Alice listed; choosing Alice still signs in |
| US-04 | Successful sign-out audit; Graph interactive; refused+Reason |
| US-05 | WS-2; WS-4 KPI-1; existing SAML; existing OIDC |
| US-06 | unknown / empty `wtrealm`; no Location to unowned URL |
| US-07 | WS-3; `saml-acs` / `web` / cross-app / unregistered / omitted return |
| US-08 | unsolicited `wresult`; SOAP absent; `wsignout1.0`+token body; no allow flag |

## Planned unit-test locations (pyramid)

DELIVER inner loop (not written here):

- `internal/identity/` — `wa` dispatch before mint; sign-out never calls `deliverWSFedResponse`; `clearSession` reuse
- `internal/store/` — typed `wsfed-reply` lookup for SignOutWreply (not `HasRedirectURI`)
- `internal/audit/` — sign-out event shape (`Flow=wsfed`, `ClientID=wtrealm`, no raw `wresult`)

Acceptance stays on driving ports in `internal/server/wsfed_sign_out_test.go` plus pending `e2e/wsfed` SignOut. Keep `tests/acceptance/ws-fed/` sign-in Gherkin green.

## Mandate compliance evidence (CM-A/B/C/D)

**CM-A (driving ports):** `wsfed_sign_out_test.go` imports `net/http`, `net/url`, `reflect`, `strings`, `testing`, and `internal/store` (store used to set **preconditions**: app + two `wsfed-reply` URIs). Exercise path is `http.Get` / `PostForm` against `httptest.Server` — FederationMetadata, `/{tid}/wsfed`, Admin audit, Graph sign-ins. Zero imports of unexported Identity handlers (`handleWSFed`, `clearSession`).

**CM-B (business language):** Gherkin uses Priya, Alice, Tasks API, FederationMetadata, `wa`, `wtrealm`, `wreply`, `wresult`, `wsignout1.0`, `wsignin1.0` (DISCUSS domain language). HTTP paths live in comments / `@driving_port`, not scenario titles.

**CM-C (journeys):** 4 walking skeletons (user goal: complete SignOut / stranger session gone) + 25 focused boundary scenarios.

**CM-D (pure functions / adapters):** Strategy C — fixture parametrization is the three environment Givens on walking skeletons only. Business dispatch (`wa` branch, reply allowlist) is production Identity code; DISTILL does not extract it. Impure I/O is SQLite + HTTP behind existing adapters. Mandate 7 scaffolds N/A (DWD-03).

## Error / edge inventory (16)

1. Priya is not sent to a second metadata URL (404)
2. Sign-out with a live session does not mint a token
3. Repeating SignOut with no session still returns
4. Unknown `wa` is refused
5. Sign-out carrying a token body does not deliver a token
6. Unknown application ID URI — no Location to attacker
7. Empty realm refused
8. SAML ACS not accepted as sign-out return
9. OIDC web callback not accepted
10. Another app's reply not accepted
11. Unregistered return does not receive the browser
12. Missing return uses a registered `wsfed-reply` (not `saml-acs`/`web`)
13. Unsolicited token POST still refused
14. SOAP stays absent
15. Unsolicited login not offered as a setting
16. Refused sign-out recorded with a concrete reason
