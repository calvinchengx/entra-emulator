# Architecture brief — entra-emulator

**SSOT:** `docs/product/architecture/`  
**Bootstrapped:** 14 Aug 2026 (DESIGN wave, feature `ws-fed`)  
**Extended:** 15 Aug 2026 (DESIGN wave, feature `ws-fed-sign-out` — application architecture only)  
**Scope of this file:** Application architecture for WS-Federation passive sign-in **and** advertised sign-out. No System Architecture or Domain Model sections — those architects did not run.

This is a **local Entra emulator**: one process, one Identity STS surface, one SQLite directory. Success is an unmodified stranger completing the same wire conversation it completes against Entra, with only host and TLS knobs changed. It is not an identity-provider product, not a portal, and not a policy engine.

---

## Application Architecture

Feature: **`ws-fed`** (v0.8.0 walking skeleton) **plus `ws-fed-sign-out`** (witness advertised `wsignout1.0`). Job: point an existing ASP.NET WS-Fed relying party at the local STS (`docs/product/jobs.yaml`, journeys `docs/product/journeys/ws-fed-sign-in.yaml` and `docs/product/journeys/ws-fed-sign-out.yaml`).

### Problem

**Before v0.8.0:** FederationMetadata was SAML-only (`IDPSSODescriptor`) and `GET|POST /{tid}/wsfed` was unrouted (404). `Microsoft.AspNetCore.Authentication.WsFederation` could not locate a `PassiveRequestorEndpoint` or complete sign-in. Priya Chen’s Tasks API already uses that library against Entra (`Wtrealm=api://tasks-api`, reply `https://rp.example.test/signin-wsfed`).

**Before this cut (after v0.8.0):** FederationMetadata already advertised sign-out on `/{tid}/wsfed`, but `handleWSFed` did not branch on `wa`. A live session on `wa=wsignout1.0` could SSO-deliver a `wresult`. Unmodified library `SignOut` was not witnessed.

### Quality-attribute ranking (locked 14 Aug 2026)

| Rank | Attribute | Architectural implication |
|---|---|---|
| 1 | **Auditability** | Every WS-Fed exchange on `/{tid}/wsfed` is recorded in the **existing** in-process flow recorder **before** treating stranger CI as the only success signal. KPI-1 (unmodified WsFederation green) remains required; it is not a substitute for the recorder. |
| 2 | Interoperability | Unmodified `Microsoft.AspNetCore.Authentication.WsFederation` verifies metadata + `wresult`. |
| 3 | Maintainability | SAML analog: extend existing Identity / Store / Tokens / Audit; do not fork a second STS. |
| 4 | Security of the protocol surface | Registered `wreply` of type `wsfed-reply` (sign-in POST **and** sign-out 302); unknown `wtrealm` refused; unsolicited `wresult` refused; errors stay on the emulator (never bounce to an unowned URL). |
| 5 | Scale | Out of scope. Single-process emulator; no new deployable, no shard, no queue. |

ISO 25010 mapping: auditability → Security (accountability / non-repudiation) plus Maintainability (analyzability); interop → Compatibility; protocol-surface safety → Security (authorization of POST targets); scale is explicitly not a driver.

### Constraints

| Constraint | Impact |
|---|---|
| Solo maintainer, one Identity STS package | Conway: one process. Microservices would be 100% org-mismatch. |
| Walking skeleton **is** v0.8.0 (DISCUSS D3) | Metadata + `/wsfed` + picker + SAML 2.0 `wresult` + stranger in one cut; refuse-unsafe (US-06–08) still Must Have. |
| Spike S3b | `wresult` TokenType is SAML 2.0 (`…#SAMLV2.0`, assertion `Version="2.0"`). SharePoint / SAML 1.1 is out. |
| Spike H2 | Grow **existing** FederationMetadata URL; both `PassiveRequestorEndpoint` and `SecurityTokenServiceEndpoint` = `/{tid}/wsfed`. Hostname `sts.windows.net` is not required if assertion Issuer equals metadata entityID. |
| Existing `HasRedirectURI` ignores type | Must **not** be the WS-Fed reply check. |
| No SOAP, `/common/wsfed`, encryption, MFA/CA/Graph-as-sign-in, portal gallery, multi-RP `wsignoutcleanup1.0` fan-out, SOAP SLO | Explicit Won't-haves. **Witnessed `wsignout1.0` is now in** (`ws-fed-sign-out` / ADR-006). |
| Tenant-agnostic examples | `{tid}`, `api://tasks-api`, `https://rp.example.test/signin-wsfed` only. |
| Paradigm | Go, OOP-native, match existing Identity handlers. Project `CLAUDE.md` is not edited (locked for `ws-fed-sign-out`). |
| Sign-out on the same process | DISCUSS NFR: sign-out answers on the same process as sign-in. Session-end latency follows existing OIDC/SAML `logout.go`; no new availability target. |

### Constraint and priority analysis

- **Largest bottleneck (Q1):** the protocol surface is missing (`/wsfed` 404 + SAML-only metadata). Scale is 0% of the problem. A new log store would address 0% extra auditability versus wrapping the existing recorder.
- **Constraint-free path:** extend Identity (SAML analog), Store type `wsfed-reply`, Tokens signing cert already used by SAML, Audit `audited` wrapper already used by `saml-sso`.
- **Primary focus:** Identity STS adapter + audit wrap of `/{tid}/wsfed`. Secondary: Store type filter, Graph projection so WS-Fed events remain identifiable, `e2e/wsfed` witness.
- **Do not invert:** shipping metadata alone (US-01 without US-04/US-05) or a green stranger without recorder events would invert the ranked drivers.
- **`ws-fed-sign-out` bottleneck (Q1, pre-cut):** `handleWSFed` ignored `wa`, so a live session could mint on `wsignout1.0` (DISCUSS D12). That was ~100% of this cut’s protocol gap. Scale remains 0%. A second logout URL or cookie addresses 0% of the locked stranger’s GET to `TokenEndpoint`.
- **`ws-fed-sign-out` constraint-free path:** branch inside the existing WS-Fed adapter; reuse `clearSession` / forget session-app rows; reuse `wsfed-reply` allowlist; extend `e2e/wsfed` with `SignOutWreply`. Spike (15 Aug 2026) measured no need for multi-RP cleanup.

### Existing system analysis (reuse vs new)

Searched `internal/identity`, `internal/store`, `internal/tokens`, `internal/audit`, `internal/graph`, `e2e/`. **No new process, datastore, login UI, or SOAP listener.** Every new piece is justified by “no existing alternative that is safe to reuse.”

| Existing | Role today | WS-Fed decision |
|---|---|---|
| `Identity.Register` — `GET /{tenant}/federationmetadata/2007-06/federationmetadata.xml` wrapped `audited("saml-metadata", …)` | SAML-only EntityDescriptor + IDPSSODescriptor | **Grow this document** with WS-Fed `RoleDescriptor`. **Do not** add a second metadata URL. **Do not** rename the metadata audit flow (`saml-metadata` stays). |
| `GET\|POST /{tenant}/saml2` wrapped `audited("saml-sso", …)` | SAML SSO | **Not an alias.** New `GET\|POST /{tid}/wsfed` with its own audit flow name. |
| Signed picker state `Kind: "saml"` posting back to `/{tid}/saml2` | Same account picker as OIDC | New Kind (e.g. `"wsfed"`) posting back to `/{tid}/wsfed`. Same chrome (`renderAccountPicker` / password form). |
| Redirect type `saml-acs` (filtered in resolve; **not** `HasRedirectURI`) | SAML ACS allowlist | New type **`wsfed-reply`**. A SAML ACS must not accept a WS-Fed POST; an OIDC `web`/`spa` callback must not become a WS-Fed reply. |
| `GetAppByIDURI` | App lookup by Application ID URI | **Reuse** for `wtrealm`. |
| `HasRedirectURI` | Exact URI, **ignores type** | **Do not use** for WS-Fed. |
| `app_redirect_uris.type` (no DB CHECK; UNIQUE `(app_id, uri)`) | `web\|spa\|native` in comments; `saml-acs` already stored | Add allowed type `wsfed-reply`. Same URI cannot be two types on one app (existing uniqueness). Seed/docs in DELIVER. |
| Tenant RSA / X.509 (`tokens` SAML certificate, same key as JWKS) | IDPSSODescriptor + SAML assertion signature | **Same cert** on WS-Fed RoleDescriptor and assertion signature. No second key. |
| In-process audit ring buffer + `audited` wrapper | OIDC + SAML metadata/SSO | Wrap `GET\|POST /{tid}/wsfed`. Map `wtrealm` into `Event.ClientID` (documented). After picker, record the subject. Never persist raw `wresult`. |
| Graph `GET …/auditLogs/signIns` and Admin `GET /admin/api/audit` | Project the same recorder | WS-Fed events **must appear** here. No second log store. Projection must identify the app when `ClientID` holds an Application ID URI, and treat WS-Fed browser exchanges as interactive. |
| `e2e/saml` (Node `@node-saml/node-saml`) | SAML stranger | Analog only. New **`e2e/wsfed`**. |
| `e2e/dotnet` (MSAL.NET + Wilson OIDC) | OIDC/MSAL | **Do not extend.** Wrong protocol. |
| `handleWSFed` (`internal/identity/wsfed.go`) | **Before this cut:** answered `GET\|POST /{tid}/wsfed` without reading `wa`; a live session could SSO-deliver `wresult` on `wsignout1.0` | **Extend:** dispatch on `wa` before any mint (ADR-006). `wsignout1.0` never mints. Sign-in path unchanged. |
| `clearSession` + `ForgetSessionApps` (`internal/identity/logout.go` / `identity.go`) | OIDC `/{tid}/oauth2/v2.0/logout` ends the shared cookie | **Reuse** session-end only. Do **not** alias onto that URL. Do **not** render front-channel iframes (`SessionLogoutURIs`) for this cut. |
| `resolveWSFedRelyingParty` + `HasRedirectURIOfType` (`wsfed-reply`) | Sign-in `wreply` allowlist | **Reuse** for sign-out return. Prefer library-sent `wreply`; if omitted, a registered `wsfed-reply` for that app. **Never** `HasRedirectURI`. |
| `HasRedirectURI` (type-blind) | OIDC post-logout redirect | **Do not use** for WS-Fed sign-out (same hole as sign-in). |
| `e2e/wsfed` (`Program.cs`) | **Before this cut:** unmodified WsFederation sign-in; one `wsfed-reply` (`/signin-wsfed`); no `SignOutWreply` | **Extend this project.** Register a **distinct** `wsfed-reply` and set `SignOutWreply`. Keep sign-in green. |
| OIDC `end_session_endpoint` | `GET /{tid}/oauth2/v2.0/logout` | **Not an alias.** Library SignOut hits `/{tid}/wsfed`. |
| Front-channel `SessionLogoutURIs` | OIDC iframe SLO to session apps | **Do not** use as WS-Fed `wsignoutcleanup1.0` fan-out (Won't-have; spike: not required for single-RP SignOut). |

**New (no existing alternative) — v0.8.0:** (1) WS-Fed RoleDescriptor on the existing metadata document; (2) `/{tid}/wsfed` passive sign-in adapter; (3) redirect type `wsfed-reply`; (4) signed-state Kind for WS-Fed; (5) RSTR envelope wrapping a SAML 2.0 assertion (SAML SSO posts `SAMLResponse`, not `wresult`); (6) `e2e/wsfed` .NET witness.

**New (no existing alternative) — `ws-fed-sign-out`:** none as a component. The only gap is a `wa` dispatch inside the existing WS-Fed adapter plus a second registered `wsfed-reply` on the existing stranger. Justified: no existing `wa` branch; OIDC logout is the wrong URL and the wrong allowlist.

### Pattern

**Modular monolith with dependency inversion, as it already exists.** HTTP is the driving adapter; Store, Tokens, and Audit are driven ports. Default for a solo maintainer and a protocol sibling of SAML. Rejected simpler/heavier alternatives:

1. **Alias `/wsfed` onto `/saml2`** — rejected (DISCOVER D7 / DISCUSS): different binding and envelope; SharePoint rewrite exists because they are not aliases.
2. **New metadata URL** — rejected (H2 WORKS): stranger `MetadataAddress` is the existing FederationMetadata path.
3. **Second login UI** — rejected (US-03 / H4).
4. **New process or datastore** — rejected: scale out of scope; Conway mismatch; 0% of the bottleneck.
5. **In-process-Go-only stranger** — rejected: SAML v0.6.0 lesson; KPI-1 is the unmodified library.

**`ws-fed-sign-out` option (Propose, locked):** extend existing `handleWSFed` / Identity package (same modular monolith). **Rejected:** alias onto OIDC logout URL; new `/wsfed/signout` path; new cookie; in-process-Go-only as the stranger. See [ADR-006](adr-006-wsfed-sign-out-dispatch.md).

### Component boundaries

| Component | Responsibility | Depends on (inward) | Must not |
|---|---|---|---|
| **Identity STS (driving HTTP adapter)** | Serve FederationMetadata; answer `wa=wsignin1.0` **and** `wa=wsignout1.0` on `/{tid}/wsfed`; reuse picker; mint RSTR **only on sign-in**; clear shared session on sign-out; refuse unsafe; wrap exchanges in audit | Store, Tokens, Audit | SOAP listener; `/common/wsfed`; second login chrome; trusting query-string `wreply`; minting on `wsignout1.0`; aliasing onto OIDC logout |
| **Store (driven)** | Apps by Application ID URI; redirect URIs including type `wsfed-reply` | SQLite | Protocol XML; signing |
| **Tokens / signing (driven)** | Same tenant RSA + derived X.509 used by SAML | Store keys | A second WS-Fed key |
| **Audit recorder (driven)** | In-process ring buffer of flow events | none (memory) | Raw `wresult` / assertion body |
| **Graph + Admin (driving HTTP, existing)** | Project recorder to `auditLogs/signIns` and `/admin/api/audit` | Audit, Store | A second audit table |
| **`e2e/wsfed` (CI witness, not runtime)** | Unmodified `Microsoft.AspNetCore.Authentication.WsFederation` completes metadata + sign-in | Emulator HTTP | Live in the emulator process; extending `e2e/dotnet` |

#### Ports (observable, not Go signatures)

**Driving (HTTP):**

| Port | Observable contract |
|---|---|
| FederationMetadata | `GET /{tid}/federationmetadata/2007-06/federationmetadata.xml` — EntityDescriptor grows `RoleDescriptor` `xsi:type="fed:SecurityTokenServiceType"` (WS-Federation). `IDPSSODescriptor` unchanged. Both `PassiveRequestorEndpoint` and `SecurityTokenServiceEndpoint` = `{login_origin}/{tid}/wsfed`. Sign-out advertised on the same PassiveRequestorEndpoint. Same signing cert bytes as IDPSSODescriptor. entityID remains emulator login origin + `/{tid}/`. Audit flow name stays `saml-metadata`. |
| WS-Fed passive STS | `GET\|POST /{tid}/wsfed`. **Sign-in** (`wa=wsignin1.0` or empty `wa`): unauthenticated valid challenge → HTTP 200 login HTML, **not** 302, **not** a `wresult`. After sign-in → HTTP 200 auto-POST HTML to **registered** `wreply`. **Sign-out** (`wa=wsignout1.0`): never a `wresult`; end shared session; **HTTP 302** to a registered `wsfed-reply` (library-sent `wreply` if valid, else a registered `wsfed-reply` for that app). Other non-empty `wa` → refuse on emulator. Refuse-unsafe → 4xx (or emulator error page), **no** `Location` to an unowned URL. Same `audited("wsfed")` wrap. |
| Account picker | Same LOCAL EMULATOR / Pick an account (or existing password form). Signed state Kind distinguishes WS-Fed from SAML/OIDC; POST action is `/{tid}/wsfed`. |
| Admin audit | `GET /admin/api/audit` includes WS-Fed events. |
| Graph sign-ins | `GET /{tid}/v1.0/auditLogs/signIns` includes the same events. |

**Driven:**

| Port | Observable contract |
|---|---|
| App by ID URI | `wtrealm` → existing Application ID URI lookup. Miss → US-06 refuse. |
| Reply URIs by type | Accept sign-in `wreply` and sign-out return only if that app has an **exact** URI of type `wsfed-reply`. Missing / wrong type / other app’s URI → US-07 refuse. Sign-out omit: a registered `wsfed-reply` for that app, not another type. |
| Signing material | RoleDescriptor KeyDescriptor and assertion signature use the tenant cert already published on IDPSSODescriptor. |
| Recorder | Append events; list newest-first. No token body field. |

### Integration patterns and protocol contracts

Synchronous HTTP only. No message bus. Browser is the WS-Federation passive requestor.

**Happy path (US-01–US-05)**

1. RP fetches existing FederationMetadata as `MetadataAddress`.
2. Library maps `PassiveRequestorEndpoint` → TokenEndpoint = `/{tid}/wsfed` (also reads `SecurityTokenServiceEndpoint`).
3. Browser `GET` or `POST` `/{tid}/wsfed?wa=wsignin1.0&wtrealm=api://tasks-api&wreply=https://rp.example.test/signin-wsfed&wctx=…` ( `wctx` optional).
4. Emulator records a **challenge** event; returns login HTML.
5. Priya chooses Alex Rivera on the existing picker; challenge parameters survive.
6. Browser auto-POSTs to registered `wreply`: `wa=wsignin1.0`, `wresult` = RequestSecurityTokenResponse wrapping SAML 2.0 assertion, `wctx` echoed unchanged when present and omitted when the RP never sent it.
7. Unmodified WsFederation verifies; session at the Tasks API.
8. Emulator records a **success** event with the signed-in subject.

**Token shape (spike S3b, tenant-agnostic)**

| Field | Contract |
|---|---|
| TokenType | `http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0` (OASIS *profile* 1.1; assertion is SAML **2.0**) |
| Inner assertion | `Version="2.0"` `xmlns="urn:oasis:names:tc:SAML:2.0:assertion"` |
| Audience | equals `wtrealm` (`api://tasks-api`) |
| Issuer | equals metadata entityID (emulator login origin; `sts.windows.net` not required) |
| NameID Format | `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent` (observed) |
| Signature | Verifiable with FederationMetadata signing cert (same as SAML) |

**Refuse-unsafe (US-06–US-08)** — errors stay on the emulator:

| Condition | Observable |
|---|---|
| Unknown or empty `wtrealm` | No `wresult` POST to caller `wreply`; recorded failure with concrete reason |
| Missing `wreply`, unregistered `wreply`, or `wreply` registered only as `saml-acs` / `web` / `spa` / other app | No `wresult` POST there; recorded failure with concrete reason |
| `wresult` without a prior challenge this STS issued (unsolicited / IdP-initiated) | Refused; no session via this STS; recorded failure. No v0.8.0 flag to allow it. |

**Unsolicited correlation (WHAT):** the STS delivers a `wresult` only after a challenge it issued (signed picker state Kind for WS-Fed). A token-shaped POST to `/{tid}/wsfed` that did not start here is refused. The locked stranger also defaults unsolicited logins off at the RP.

**Auditability contracts (rank 1)**

| Event | `Event.Flow` | `Event.ClientID` | Subject | `OK` / status | Body |
|---|---|---|---|---|---|
| Unauthenticated challenge (200 login HTML) | `wsfed` | `wtrealm` (Application ID URI) | empty | recorded; HTTP 200 is still a challenge event | **never** store HTML or `wresult` |
| Success after picker | `wsfed` | same | user id + UPN (`noteAuditSubject`) | success | **never** persist raw `wresult` |
| US-06 / US-07 / US-08 refuse | `wsfed` | attempted `wtrealm` when present | empty unless a user was already resolved | failure; **concrete `Reason`** | no token |

`Event.Flow` is already an open string in practice (`token`, `authorize`, `saml-sso`, `saml-metadata`). Document `wsfed` alongside those. Metadata GETs remain `saml-metadata`.

Graph `auditLogs/signIns` today resolves `appDisplayName` via app-GUID lookup on `ClientID` and marks interactive only when `Flow == "authorize"`. For WS-Fed, the projection must still identify the Tasks API when `ClientID` is an Application ID URI, and browser WS-Fed exchanges must appear as interactive. DISTILL asserts admin and Graph lists contain challenge, success, and refuse-unsafe events **without** logging the token body.

**Guardrails:** OIDC and SAML sign-in keep working. Growing FederationMetadata must not remove `IDPSSODescriptor`. Witnessing `wsignout1.0` must not move `PassiveRequestorEndpoint`, must not revert WS-Fed parity to red, and must leave v0.8.0 sign-in in `e2e/wsfed` green.

### WS-Fed passive sign-out (`ws-fed-sign-out`)

Chosen option: **extend existing `handleWSFed` / Identity package** (same modular monolith as v0.8.0). See [ADR-006](adr-006-wsfed-sign-out-dispatch.md).

**Happy path (sign-out US-01–US-05)**

1. Priya already completed v0.8.0 sign-in. FederationMetadata is unchanged (US-01): `PassiveRequestorEndpoint` remains `{login_origin}/{tid}/wsfed`.
2. Unmodified library `SignOut` **GET-redirects** to that URL with `wa=wsignout1.0`, `wtrealm=api://tasks-api`, and `wreply` = library `SignOutWreply` (distinct registered `wsfed-reply`, example `https://rp.example.test/wsfed-signed-out`). No `wresult` on the wire (spike).
3. Adapter dispatches on `wa` **before** session SSO / RSTR mint. Does **not** POST a `wresult`.
4. Ends the shared OIDC/SAML/WS-Fed session (`clearSession` + forget session-app rows). Does **not** fan out `wsignoutcleanup1.0` or OIDC front-channel iframes.
5. **HTTP 302** to the registered `wsfed-reply`. The RP (library) clears its own cookie; `GET /secure` is unauthenticated.
6. Next `wa=wsignin1.0` from that browser is HTTP 200 Pick an account (Alice listed), not silent SSO.
7. Recorder: `Flow=wsfed`, `ClientID=api://tasks-api`, subject = Alice when a session was ended; **never** a token body.

**Return URL trap (spike — walking skeleton must not ignore this)**

If `SignOutWreply` is unset, the library sends the sign-in callback as `wreply`. GET `/signin-wsfed` without POST `wresult` fails the RP handler. `e2e/wsfed` must register **two** `wsfed-reply` URIs and set `SignOutWreply` to the distinct one. DISCUSS examples that used `https://rp.example.test/signin-wsfed` as the sign-out return are superseded for the walking skeleton (see [ADR-006](adr-006-wsfed-sign-out-dispatch.md) Decision 5).

**Sign-out refuse-unsafe** — errors stay on the emulator:

| Condition | Observable |
|---|---|
| Unknown or empty `wtrealm` on `wsignout1.0` | No `Location` to caller `wreply`; no `wresult`; recorded failure with concrete reason |
| `wreply` present but not an exact `wsfed-reply` for that app (`saml-acs`, `web`, other app, unregistered) | Same: stay on emulator |
| `wa=wsignout1.0` plus unsolicited `wresult` body (no signed Kind this STS issued) | Not treated as token delivery; sign-out branch still wins (no mint) |
| Repeat `SignOut` with no emulator session | Idempotent: 302 to valid registered return, or stay on emulator if unsafe; no bounce to unowned URL |
| Other non-empty `wa` (not `wsignin1.0` / `wsignout1.0`) | Refuse on emulator; no token |

**Auditability (sign-out)**

| Event | `Event.Flow` | `Event.ClientID` | Subject | `OK` / status | Body |
|---|---|---|---|---|---|
| Successful `wsignout1.0` (session ended) | `wsfed` | `wtrealm` | user id + UPN of the ended session | success | **never** persist `wresult` (none on this path) |
| Successful `wsignout1.0` (already signed out) | `wsfed` | `wtrealm` | empty | success (idempotent) | none |
| Sign-out refuse (unknown realm / bad return) | `wsfed` | attempted `wtrealm` when present | empty unless a user was already resolved | failure; **concrete `Reason`** | no token |

Metadata GETs remain `saml-metadata`. No second log store. Graph `auditLogs/signIns` already treats `Flow=wsfed` as interactive (ADR-004) — no new Graph route.

### C4 — System Context (L1)

```mermaid
C4Context
  title System Context — WS-Fed sign-in and advertised sign-out
  Person(priya, "Priya Chen", "Backend engineer; Tasks API already uses AddWsFederation")
  System(emu, "Entra Emulator", "Local STS: FederationMetadata + /{tid}/wsfed + existing account picker + shared session + audit recorder")
  System_Ext(rp, "Tasks API RP", "ASP.NET Core app with unmodified Microsoft.AspNetCore.Authentication.WsFederation")
  Rel(priya, rp, "Points MetadataAddress and Wtrealm at")
  Rel(rp, emu, "Fetches FederationMetadata from")
  Rel(priya, emu, "Chooses Alice on")
  Rel(emu, rp, "Browser-POSTs wresult to registered wreply on")
  Rel(rp, emu, "Verifies signature and audience using metadata from")
  Rel(rp, emu, "GET-redirects wa=wsignout1.0 to")
  Rel(emu, rp, "302s to registered SignOutWreply on")
```

### C4 — Container (L2)

Single OS process except the CI witness and the SQLite file.

```mermaid
C4Container
  title Container Diagram — Entra Emulator (modular monolith)
  Person(priya, "Priya Chen")
  System_Ext(rp, "Tasks API", "Unmodified WsFederation")
  System_Ext(witness, "e2e/wsfed", "CI stranger; same library as the RP")
  Container_Boundary(emu, "Entra Emulator process") {
    Container(identity, "Identity STS", "Go HTTP", "OIDC, SAML, WS-Fed passive sign-in and sign-out; account picker; audited wrappers; shared session cookie")
    Container(graph, "Graph", "Go HTTP", "Projects recorder to auditLogs/signIns")
    Container(admin, "Admin API", "Go HTTP", "App registration + GET /admin/api/audit")
    Container(tokens, "Tokens", "Go", "Tenant RSA, JWKS, SAML/WS-Fed X.509")
    Container(audit, "Audit recorder", "In-memory ring", "Flow events; no token bodies")
  }
  ContainerDb(sqlite, "SQLite", "modernc.org/sqlite", "Directory, apps, app_redirect_uris")
  Rel(priya, identity, "Signs in via")
  Rel(rp, identity, "GETs metadata and challenges /wsfed on")
  Rel(identity, rp, "Auto-POSTs wresult to")
  Rel(rp, identity, "GET-redirects wsignout1.0 to /wsfed on")
  Rel(identity, rp, "302s to registered wsfed-reply on")
  Rel(witness, identity, "Runs metadata + sign-in + SignOut against")
  Rel(identity, tokens, "Signs assertions with")
  Rel(identity, sqlite, "Looks up wtrealm and wsfed-reply in")
  Rel(identity, audit, "Records WS-Fed exchanges in")
  Rel(graph, audit, "Lists sign-ins from")
  Rel(admin, audit, "Lists raw events from")
  Rel(graph, sqlite, "Resolves app display name from")
  Rel(admin, sqlite, "Registers wsfed-reply URIs in")
  Rel(tokens, sqlite, "Loads active signing key from")
```

### C4 — Component (L3) — Identity STS (compact)

```mermaid
C4Component
  title Component Diagram — Identity STS (WS-Fed slice)
  Container_Boundary(identity, "Identity STS") {
    Component(meta, "FederationMetadata adapter", "Existing", "Grows WS-Fed RoleDescriptor; audit flow saml-metadata")
    Component(wsfed, "WS-Fed passive adapter", "Existing + wa dispatch", "GET|POST /{tid}/wsfed; Kind wsfed; RSTR on sign-in only; clearSession on wsignout1.0; audited wsfed")
    Component(picker, "Account picker", "Existing", "OIDC/SAML/WS-Fed chrome; Kind discriminates")
    Component(session, "SSO session cookie", "Existing", "Shared OIDC/SAML/WS-Fed; ended via clearSession")
    Component(saml, "SAML SSO adapter", "Existing", "Unchanged /saml2; saml-acs; Kind saml")
  }
  Component(store, "Store", "Driven", "GetAppByIDURI; typed redirect URIs")
  Component(tok, "Tokens", "Driven", "Same cert as IDPSSODescriptor")
  Component(rec, "Audit recorder", "Driven", "Event.Flow wsfed; ClientID=wtrealm")
  Rel(meta, tok, "Publishes signing cert from")
  Rel(wsfed, picker, "Sends unauthenticated challenge to")
  Rel(picker, wsfed, "POSTs signed Kind wsfed back to")
  Rel(wsfed, session, "Clears on wsignout1.0 via")
  Rel(wsfed, store, "Resolves wtrealm and wsfed-reply via")
  Rel(wsfed, tok, "Signs SAML 2.0 assertion with")
  Rel(wsfed, rec, "Records challenge, success, refuse in")
  Rel(saml, store, "Resolves Issuer and saml-acs via")
  Rel(meta, rec, "Records metadata fetch in")
```

### Technology stack (OSS first)

| Choice | License | Role | Rationale | Rejected |
|---|---|---|---|---|
| Go (existing 1.25) | BSD-style | Runtime language | OOP-native Identity handlers already exist | New service in another language |
| `encoding/xml` (stdlib) | BSD-style | FederationMetadata / RoleDescriptor | Same stack as current EntityDescriptor | New XML framework |
| Existing `goxmldsig` + `etree` | Apache-2.0 / BSD-2 | Assertion signature (SAML analog) | Already signs SAML 2.0 assertions this stranger’s handler can verify | Second signing stack |
| `modernc.org/sqlite` (existing) | BSD-3 | Directory + `app_redirect_uris` | No new datastore | Extra DB for WS-Fed |
| In-process audit ring (existing) | project / Go | Auditability #1 | Zero license cost; Graph already projects it | Second log store, SIEM product |
| `Microsoft.AspNetCore.Authentication.WsFederation` **unmodified** (witness only) | Apache-2.0 (MIT for some ASP.NET bits) | KPI-1 stranger | Locked witness; CI already installs .NET 8; `SignOut` + `SignOutWreply` for `ws-fed-sign-out` | Fork the library; in-process Go-only; extend `e2e/dotnet` (OIDC/MSAL) |

No proprietary runtime. Seed of `wsfed-reply` and CI suite wiring are DELIVER/DEVOPS, not new licensed components.

### Architecture enforcement

**Style:** Modular monolith + ports-and-adapters (existing).  
**Language:** Go.  
**Tool:** No ArchUnit. Do **not** add a Java-style architecture test framework. Prefer the package-boundary discipline already used, plus existing Go tests and the `e2e/wsfed` stranger.

**Rules to keep (review + tests, optional `go-arch-lint` later — not required for v0.8.0):**

- Identity (HTTP adapter) may depend on Store, Tokens, Audit; Store must not import Identity.
- Tokens must not import Identity.
- Audit recorder stays payload-agnostic (no `wresult` field).
- WS-Fed reply checks filter on type `wsfed-reply`; they must not call type-blind `HasRedirectURI`.
- **`wa` dispatch:** `wsignout1.0` must not call the RSTR mint path. Enforce with driving-port tests (no `wresult` in the sign-out response), not a new architecture-test framework.
- **Compliance gate:** no new top-level module, OS process, or datastore for WS-Fed. Extend Identity / Store type / Tokens cert / existing recorder only.

### Quality-attribute strategies

| Attribute | Strategy | Measurable |
|---|---|---|
| Auditability | `audited("wsfed")` on `/{tid}/wsfed`; `wtrealm` → `ClientID`; subject after picker **and** after session-ending sign-out; concrete `Reason` on refuse; never persist `wresult` | Admin + Graph lists show challenge, success, sign-out, US-06/07/08 |
| Interoperability | H2 metadata shape + S3b SAML 2.0 RSTR + same cert + Issuer = entityID; unmodified `SignOut` GET `wsignout1.0` + distinct `SignOutWreply` | `e2e/wsfed` green including SignOut (KPI-1) |
| Maintainability | SAML analog: grow metadata, new Kind, new redirect type, same picker; sign-out is a `wa` branch + `clearSession`, not a second STS | OIDC/SAML e2e stay green; one metadata URL; one `/wsfed` route |
| Security | Type-filtered registered `wreply`; unknown realm refused; unsolicited refused; fail on emulator; never mint on sign-out | KPI-3 / sign-out refuse tests; no `Location` to attacker URL; no `wresult` on `wsignout1.0` |
| Reliability | Unauthenticated GET is 200 HTML (spike: Entra does this), not a hang or premature token; sign-out is idempotent 302 | US-02 sign-in; sign-out US-02 repeat |
| Performance / scale | Single-process; no extra hop; sign-out on the same process as sign-in | Out of scope |

**STRIDE (protocol surface, not a full product threat model):**

| Threat | Mitigation |
|---|---|
| Spoofing (forged realm) | `wtrealm` must match a registered Application ID URI |
| Tampering | Signed picker state; assertion signed with published cert |
| Repudiation | Recorder + Graph/Admin projection (primary driver) |
| Info disclosure | Never persist raw `wresult`; error pages stay on emulator |
| Elevation (open redirect token POST **or** sign-out 302) | Exact `wsfed-reply` allowlist; cross-app reply refused |
| DoS | Scale out of scope; do not inflate unsolicited token XML as a success path |
| Sign-out spoofed as sign-in (D12) | Dispatch on `wa` before mint; `wsignout1.0` never produces `wresult` |

### Deployment architecture

Unchanged: one emulator binary, one SQLite file, existing TLS. `e2e/wsfed` runs as a CI sibling of `e2e/saml` (see DEVOPS handoff). No new container or port.

### Story → component traceability

| Story | Components | Port |
|---|---|---|
| US-01 | Identity metadata adapter, Tokens | FederationMetadata GET |
| US-02 | WS-Fed adapter, Audit | `/{tid}/wsfed` challenge |
| US-03 | Account picker, signed Kind | Same login HTML family |
| US-04 | WS-Fed adapter, Store `wsfed-reply`, Tokens | Auto-POST `wresult` |
| US-05 | `e2e/wsfed` witness | Stranger session |
| US-06 | WS-Fed adapter, Store `GetAppByIDURI`, Audit | Refuse unknown realm |
| US-07 | WS-Fed adapter, typed redirect lookup, Audit | Refuse bad `wreply` |
| US-08 | WS-Fed adapter (challenge correlation), Audit | Refuse unsolicited |

**`ws-fed-sign-out` stories** (same components; new `wa` branch):

| Story | Components | Port |
|---|---|---|
| US-01 | Identity metadata adapter (unchanged URL) | FederationMetadata GET |
| US-02 | WS-Fed adapter `wa` dispatch, Store `wsfed-reply`, Audit | `GET\|POST /{tid}/wsfed` `wa=wsignout1.0` → 302; no `wresult` |
| US-03 | Shared session (`clearSession`), picker | Next `wsignin1.0` is Pick an account |
| US-04 | Audit recorder, Graph + Admin | Existing lists include sign-out `Flow=wsfed` |
| US-05 | `e2e/wsfed` + SAML/OIDC suites | Sign-in still green; SignOut step added |
| US-06 | WS-Fed adapter, `GetAppByIDURI`, Audit | Refuse unknown/empty realm on sign-out |
| US-07 | WS-Fed adapter, typed redirect lookup, Audit | Sign-out return is `wsfed-reply` only |
| US-08 | WS-Fed adapter, Audit | Unsolicited still refused; SOAP still 404; `wsignout1.0`+`wresult` is not a mint |

### ADRs

| ADR | Decision |
|---|---|
| [ADR-001](adr-001-grow-existing-federationmetadata.md) | Grow existing FederationMetadata; no second URL |
| [ADR-002](adr-002-wsfed-reply-redirect-type.md) | New redirect type `wsfed-reply` |
| [ADR-003](adr-003-reuse-account-picker-kind.md) | Reuse picker via signed state Kind |
| [ADR-004](adr-004-audit-existing-recorder.md) | Audit WS-Fed through existing recorder; never log `wresult` |
| [ADR-005](adr-005-e2e-wsfed-sibling.md) | New `e2e/wsfed` sibling; do not extend `e2e/dotnet` |
| [ADR-006](adr-006-wsfed-sign-out-dispatch.md) | Dispatch `wa=wsignout1.0` on existing `/{tid}/wsfed`; never mint; 302 to registered `SignOutWreply`; reuse `clearSession` |

### Handoff — DISTILL (acceptance-designer)

Acceptance on **ports**, not private structure:

1. **Metadata GET** — existing URL includes WS-Fed RoleDescriptor; both endpoints `/{tid}/wsfed`; cert matches IDPSSODescriptor; `IDPSSODescriptor` remains; audit flow name `saml-metadata`. Sign-out remains advertised on `PassiveRequestorEndpoint` (do not move the URL).
2. **Challenge** — `GET|POST /{tid}/wsfed` `wa=wsignin1.0` with registered realm/reply → HTTP 200 login HTML, not 404, not `wresult`.
3. **Picker** — same chrome as OIDC/SAML; `wtrealm` / `wreply` / `wctx` survive.
4. **`wresult` POST** — to registered `wsfed-reply` only; SAML 2.0 RSTR; Audience = `wtrealm`; Issuer = entityID; `wctx` echo rules; NameID format persistent.
5. **Audit list** — Admin `/admin/api/audit` and Graph `auditLogs/signIns` contain WS-Fed challenge, success, **sign-out**, and refuse-unsafe (with `Reason`); **no** token body in events. For `Flow=wsfed`, Graph identifies the app when `ClientID` is Application ID URI `api://tasks-api` (`appDisplayName` not blank) and marks the exchange interactive.
6. **Stranger** — unmodified WsFederation in `e2e/wsfed` completes sign-in **then SignOut** (KPI-1). Distinct registered `wsfed-reply` as `SignOutWreply` (not `/signin-wsfed`). v0.8.0 sign-in assertions in the same suite still pass.
7. **Refuse** — unknown `wtrealm`, missing/unregistered/`saml-acs`-only/`web`-only `wreply`, unsolicited `wresult`; no bounce to unowned URL. Same refuse on `wa=wsignout1.0`.
8. **Guardrail** — existing OIDC e2e and **`e2e/saml` still pass**. `IDPSSODescriptor` remains. SOAP still 404. WS-Fed parity stays 🟢 Real.
9. **Sign-out (this feature)** — `wa=wsignout1.0` never includes `wresult`; shared session ended (next `wsignin1.0` is Pick an account); HTTP 302 to registered SignOutWreply; freeze tests that forbid driving `wsignout1.0` are superseded.

Examples stay tenant-agnostic: `{tid}`, `api://tasks-api`, `https://rp.example.test/signin-wsfed` (sign-in), `https://rp.example.test/wsfed-signed-out` (sign-out return).

## For Acceptance Designer

Driving ports for `ws-fed-sign-out` (observable HTTP; no private handler names):

| Port | Contract |
|---|---|
| **WS-Fed STS** | `GET\|POST /{tid}/wsfed` with `wa=wsignout1.0` — **same route as sign-in**. Never mint `wresult`. Clear shared session. 302 to registered `wsfed-reply`. Unknown realm / wrong-type return stay on emulator. |
| **FederationMetadata** | Unchanged URL `GET /{tid}/federationmetadata/2007-06/federationmetadata.xml`. `PassiveRequestorEndpoint` still `/{tid}/wsfed`. `GET /{tid}/wsfed/metadata` still 404. |
| **`e2e/wsfed`** | **DELIVER** extends this project (same Admin `POST /admin/api/apps` as v0.8.0). Register **two** `wsfed-reply` URIs: sign-in callback (`CallbackPath` / `Wreply`) **and** a distinct SignOut return. Set library `SignOutWreply` to the distinct URI (not `CallbackPath`). After unmodified `SignOut`, `GET /secure` is unauthenticated; next `wsignin1.0` is Pick an account. DISTILL asserts this; does not seed a second suite. |
| **Admin / Graph audit** | Existing `GET /admin/api/audit` and `GET /{tid}/v1.0/auditLogs/signIns`. Sign-out is `Flow=wsfed`, `ClientID=wtrealm`, no raw `wresult`. |

**North star:** KPI-1 — `python3 e2e/run.py wsfed` exit 0 including a SignOut step.

**Environment matrix (DEVOPS skipped):** DISTILL defaults to the same matrix as v0.8.0 when platform artifacts are absent: `clean` / `with-pre-commit` / `with-stale-config`. Existing CI already runs `python3 e2e/run.py … wsfed`. Do not design a new pipeline.

**External integrations:** `Microsoft.AspNetCore.Authentication.WsFederation` SignOut wire (GET `wsignout1.0`, no `wresult`, `SignOutWreply`) — the extended `e2e/wsfed` stranger remains the consumer-driven contract. Pact is not required.

### Handoff — DEVOPS (platform-architect)

**Skipped for `ws-fed-sign-out`** (DISCUSS D6). Existing CI already runs `python3 e2e/run.py … wsfed`. Do not add a pipeline, deployable, port, secret store, or datastore. DELIVER extends the existing `e2e/wsfed` job with a SignOut step. Do not log `wresult` in CI artifacts.

v0.8.0 notes (still true):

- `e2e/wsfed` is a sibling of `e2e/saml` (do **not** fold into `e2e/dotnet`).
- Graph URI/interactive mapping is **application** work, not a new CI job.

**External integrations requiring contract tests:**

- `Microsoft.AspNetCore.Authentication.WsFederation` (metadata parse + `wresult` verification + **SignOut GET `wsignout1.0`**): the **`e2e/wsfed` stranger is the consumer-driven contract**. Pact is not required — the consumer is a CI library, not a separately deployed team API.

### Out of this cut (do not design)

SOAP / active WS-Trust; `/common/wsfed`; SharePoint / SAML 1.1 minting; IdP-initiated flag; token encryption; MFA / Conditional Access / B2C / portal gallery; **multi-RP `wsignoutcleanup1.0` fan-out**; SOAP SLO.

Witnessed `wsignout1.0` on the advertised `PassiveRequestorEndpoint` is **in** (`ws-fed-sign-out`). The v0.8.0 freeze (“advertise; do not witness”) is superseded by ADR-006.
