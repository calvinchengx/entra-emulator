# Story Map: Point a WS-Fed RP at the local STS

## User: Priya Chen (backend engineer; already has an ASP.NET Core WS-Fed relying party)

## Goal: Point `MetadataAddress` + `Wtrealm` at the emulator so unmodified `Microsoft.AspNetCore.Authentication.WsFederation` completes sign-in

**JTBD:** skipped; traces to DISCOVER job: point WsFederation at the emulator (`docs/feature/ws-fed/discover/problem-validation.md` desired outcome).

**Emotional arc:** Frustrated (404 / SAML-only metadata) → hopeful → familiar → relieved → satisfied.

---

## Backbone

User activities, left to right (chronological). Ribs are tasks. Top of each column is essential.

| Point the RP | Discover the STS | Challenge `/wsfed` | Sign in | Receive `wresult` | Session at the RP |
|---|---|---|---|---|---|
| Set MetadataAddress to the existing FederationMetadata URL | Fetch FederationMetadata | GET `wa=wsignin1.0` reaches `/{tid}/wsfed` (not 404) | Same Pick an account page as OIDC/SAML | POST RSTR wrapping SAML 2.0 to registered `wreply` | Unmodified WsFederation verifies the token |
| Set Wtrealm to Application ID URI `api://tasks-api` | Find PassiveRequestorEndpoint | Login HTML, not a premature `wresult` | Challenge parameters survive picker | Audience equals `wtrealm`; `wctx` echoed; Issuer = entityID | Host and TLS knobs only |
| Register reply URL `https://rp.example.test/signin-wsfed` | Find SecurityTokenServiceEndpoint | | | | |
| | Same signing cert as IDPSSODescriptor | Unknown `wtrealm` refused | | Missing / unregistered `wreply` refused | Unsolicited `wresult` refused |
| | Advertise sign-out on the same PassiveRequestorEndpoint | | | | |
| | | | | | *(out)* Witness `wsignout1.0` |
| | | | | | *(out)* `/common/wsfed` |
| | | | | | *(out)* SOAP / SAML 1.1 / IdP-initiated |

```
Point the RP    Discover the STS    Challenge /wsfed    Sign in    Receive wresult    Session at the RP
------------    ----------------    ----------------    -------    ---------------    -----------------
US-01 config    US-01 metadata      US-02 no 404        US-03      US-04 SAML 2.0     US-05 stranger
  + register      + certs + SLO       login HTML         picker      POST + echo         verifies
  realm/reply     advertise           ..............     .......     ...............     ...............
                                      US-06 unknown                  US-07 bad wreply    US-08 unsolicited
                                      wtrealm
                                      ---------------- later / won't ----------------
                                      /common  SOAP  SAML 1.1  witnessed SLO  gallery
```

---

### Walking Skeleton

**v0.8.0 slice (user locked Yes):** Priya points the Tasks API at the emulator and the unmodified library completes one SP-initiated sign-in.

| Activity | Skeleton task | Story |
|---|---|---|
| Point the RP | MetadataAddress + Wtrealm + registered reply | US-01 (precondition) |
| Discover the STS | RoleDescriptor on the **existing** URL: PassiveRequestorEndpoint + SecurityTokenServiceEndpoint + same cert; sign-out advertised | US-01 |
| Challenge `/wsfed` | `wa=wsignin1.0` is not 404; unauthenticated GET is login HTML | US-02 |
| Sign in | Same account picker as OIDC and SAML | US-03 |
| Receive `wresult` | POST SAML 2.0 RSTR to registered `wreply`; Audience = wtrealm; `wctx` echoed | US-04 |
| Session at the RP | Unmodified WsFederation completes sign-in | US-05 |

Happy-path `wreply` is registered (US-04). Explicit refuse-unsafe stories are Release 1, still Must Have for v0.8.0 (SAML shipped ACS refusal with sign-in).

**Walking skeleton one-liner:** FederationMetadata on the existing URL names `/{tid}/wsfed`; that route answers `wa=wsignin1.0`; the existing account picker runs; the RP receives a SAML 2.0 `wresult` at a registered `wreply`; unmodified WsFederation completes sign-in.

---

### Release 1: Priya can trust the STS will not bounce to an attacker

**Outcome:** Developers who misconfigure realm or reply (or who POST a token they did not start) do not get an open redirect or an unsolicited session.

| Task | Story | KPI |
|---|---|---|
| Unknown `wtrealm` refused | US-06 | Guardrail: no bounce to caller-supplied URL |
| Missing / unregistered `wreply` refused | US-07 | Same (SAML ACS analog) |
| Unsolicited `wresult` refused | US-08 | Locked stranger default |

Still **v0.8.0 Must Have** (locked decisions 5–6). Separately demonstrable from the happy path.

---

### Release 2: Later protocol siblings (explicit Won't Have for v0.8.0)

Named so DESIGN does not grow them. Not stories.

| Task | Status | Why |
|---|---|---|
| `/common/wsfed` | Won't — v0.8.0 | Locked stranger uses tenant-specific MetadataAddress |
| Witness `wsignout1.0` | Won't — v0.8.0 | Advertise-only (SAML v0.6.0 analog) |
| SOAP / active WS-Trust | Won't | Interview Q5 |
| SharePoint / SAML 1.1 | Won't | Spike locked S3b; different RP class |
| IdP-initiated / AllowUnsolicitedLogins | Won't | Stranger default off |
| Portal gallery, Graph, MFA/CA/B2C, token encryption | Won't | Product boundary |

---

## Priority Rationale

Order is outcome impact and dependency, not “easy metadata first” as a substitute for end-to-end value.

1. **Walking skeleton (US-01 → US-05)** — Validates H1 (stranger completes sign-in). Without this, O1–O3 are not delivered. Metadata alone is not a demo Priya can feel. Tie-break: walking skeleton first (Patton).
2. **Release 1 refuse-unsafe (US-06 → US-08)** — O4 and O6. Riskiest remaining product assumption after A3 closed: `wreply` trusted from the query string would ship an open redirect. Must Have in the same version as sign-in; second slice because it is separately demonstrable.
3. **Release 2 siblings** — Explicit non-goals. Mapping them prevents scope creep; they do not compete for v0.8.0 capacity.

Value × Urgency / Effort (1–5; higher score first among same band):

| Story | Value | Urgency | Effort | Score | Band |
|---|---|---|---|---|---|
| US-01 Metadata RoleDescriptor | 5 | 5 | 2 | 12.5 | Skeleton |
| US-02 `/wsfed` answers challenge | 5 | 5 | 2 | 12.5 | Skeleton |
| US-03 Same sign-in | 4 | 4 | 2 | 8 | Skeleton (habit / H4) |
| US-04 SAML 2.0 `wresult` POST | 5 | 5 | 3 | 8.3 | Skeleton (A3 locked) |
| US-05 Unmodified stranger | 5 | 5 | 3 | 8.3 | Skeleton (H1) |
| US-07 Unregistered `wreply` | 5 | 5 | 2 | 12.5 | R1 (open redirect) |
| US-06 Unknown `wtrealm` | 4 | 4 | 2 | 8 | R1 |
| US-08 Unsolicited `wresult` | 4 | 5 | 2 | 10 | R1 (stranger default) |

US-01 and US-02 score high but **must not ship without US-04/US-05** — that would be feature-first slicing. Sequence inside the skeleton is dependency order: metadata → route → picker → token → stranger.

---

## Scope Assessment: PASS — 8 stories, 1 user outcome, estimated 8–11 days

Elephant Carpaccio check:

| Signal | This feature | Oversized? |
|---|---|---|
| >10 user stories | 8 | No |
| >3 bounded contexts | Protocol surface is **cross-cutting** (STS + FederationMetadata + login reuse + e2e) — four touchpoints, **one** user outcome | Flagged, not split |
| Walking skeleton >5 integration points | Six activities; one thin E2E (user locked Yes) | Inherent to federation |
| Estimated effort >2 weeks | ~8–11 days if refuse-unsafe ships with v0.8.0 | No |
| Multiple independent outcomes | One: point existing WS-Fed RP at local STS | No |

**Why not split features:** Metadata without `/wsfed` cannot complete WsFederation. `/wsfed` without metadata is unreachable from the locked stranger. Login reuse and the CI stranger are the same slice Priya demos in one session.

**Not a second feature:** SharePoint/SAML 1.1, SOAP, `/common/wsfed`, witnessed SLO — those are independent outcomes and are **out**, not a split of this walking skeleton.

System constraints and stories: `user-stories.md`. Prioritization table: `prioritization.md`.
