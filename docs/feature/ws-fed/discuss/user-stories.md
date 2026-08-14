<!-- markdownlint-disable MD024 -->
# User stories — ws-fed

**Feature ID:** `ws-fed`  
**Date:** 14 Aug 2026  
**JTBD:** skipped; every story traces to DISCOVER job: point WsFederation at the emulator (`docs/feature/ws-fed/discover/problem-validation.md` desired outcome). No second job analysis.

Persona: **Priya Chen**, backend engineer. She already has an ASP.NET Core Tasks API using `Microsoft.AspNetCore.Authentication.WsFederation`. She wants `MetadataAddress` + `Wtrealm` to work against the emulator the way they work against Entra.

---

## System Constraints

Cross-cutting. DESIGN owns how they are implemented; stories must not violate them.

1. **SAML 2.0 in `wresult`.** Spike locked S3b: TokenType `…#SAMLV2.0`, assertion `Version="2.0"`. SharePoint SAML 1.1 is out of v0.8.0.
2. **Existing FederationMetadata URL only.** Grow that document. Do not invent a second metadata path.
3. **Both endpoints.** RoleDescriptor includes `PassiveRequestorEndpoint` and `SecurityTokenServiceEndpoint`, both `/{tid}/wsfed`. Sign-out is advertised on the same PassiveRequestorEndpoint; do **not** witness `wsignout1.0`.
4. **Same signing cert** as `IDPSSODescriptor`. Do not mint a second key.
5. **`wreply` is registered**, not trusted from the query string (SAML ACS analog). Audience equals `wtrealm`.
6. **Unsolicited logins refused.** SP-initiated only.
7. **Same sign-in** the emulator already uses for OIDC and SAML. No second login UI.
8. **EntityID** may stay the emulator login origin (D14) if assertion Issuer matches metadata entityID. Hostname `sts.windows.net` is not required.
9. **Out of v0.8.0:** SOAP / active WS-Trust, `/common/wsfed`, IdP-initiated, SharePoint / SAML 1.1, portal gallery, Graph, MFA/CA/B2C, token encryption.
10. **Agnostic examples:** `{tid}`, `api://tasks-api`, `https://rp.example.test/signin-wsfed`. No real tenant, org, or capture-domain names.
11. **Solution-neutral:** no Go package layout, file names, or CI YAML in stories. Protocol names (`wa`, `wtrealm`, `wresult`, FederationMetadata) are domain language.

**NFR:** Unauthenticated `GET /{tid}/wsfed` returns login HTML (not a hang, not a `wresult`). Errors that fail realm/reply checks stay on the emulator — never bounce to an unowned URL. OIDC and SAML sign-in keep working (guardrail).

---

## US-01: FederationMetadata advertises the WS-Fed STS

### Problem

Priya Chen is a backend engineer who already points `MetadataAddress` at Entra's FederationMetadata document. She finds it blocking to point that same URL at the emulator because today's document is SAML-only, so `Microsoft.AspNetCore.Authentication.WsFederation` cannot find a `PassiveRequestorEndpoint`.

### Who

- Developer with an existing ASP.NET WS-Fed RP | Switching `MetadataAddress` host to the emulator | Needs the document she already configured to name `/{tid}/wsfed` and a signing cert

### Solution

The **existing** FederationMetadata URL grows a WS-Fed RoleDescriptor: `PassiveRequestorEndpoint` and `SecurityTokenServiceEndpoint` both `/{tid}/wsfed`, the same signing certificate as `IDPSSODescriptor`, and the sign-out URL advertised on that same PassiveRequestorEndpoint.

### Domain Examples

#### 1: Happy path — Tasks API metadata

Priya's Tasks API uses `MetadataAddress = {login_origin}/{tid}/federationmetadata/2007-06/federationmetadata.xml` and `Wtrealm = api://tasks-api`. The document's WS-Fed section names `{login_origin}/{tid}/wsfed` twice (passive + security token service) and repeats the SAML signing cert.

#### 2: Edge — SAML still present

Jordan Blake's SAML app still fetches the same URL. `IDPSSODescriptor` is unchanged. Adding the WS-Fed section does not remove SAML endpoints.

#### 3: Error/boundary — no second URL

Priya must not be told to set `MetadataAddress` to `/wsfed/metadata`. If only a new path existed, her Entra-shaped config would miss it.

### UAT Scenarios (BDD)

#### Scenario: Priya's relying party finds the sign-in endpoint in federation metadata

Given the emulator already serves FederationMetadata at `{login_origin}/{tid}/federationmetadata/2007-06/federationmetadata.xml`  
When Priya's Tasks API fetches that document as `MetadataAddress`  
Then the document includes a WS-Fed RoleDescriptor  
And `PassiveRequestorEndpoint` is `{login_origin}/{tid}/wsfed`  
And `SecurityTokenServiceEndpoint` is `{login_origin}/{tid}/wsfed`

#### Scenario: Signing certificates in both sections match

Given FederationMetadata includes `IDPSSODescriptor` and a WS-Fed RoleDescriptor  
When Priya compares the signing certificates  
Then the WS-Fed certificate is the same as the SAML certificate

#### Scenario: Sign-out is advertised without a sign-out witness

Given Priya fetches FederationMetadata for the Tasks API  
When she reads the WS-Fed RoleDescriptor  
Then the sign-out URL is the same PassiveRequestorEndpoint as sign-in  
And this story does not require a `wsignout1.0` round-trip

#### Scenario: SAML apps still see their descriptor

Given FederationMetadata already published `IDPSSODescriptor` for SAML  
When the WS-Fed RoleDescriptor is present  
Then `IDPSSODescriptor` remains available at the same URL

### Acceptance Criteria

- [ ] Existing FederationMetadata URL includes a WS-Fed RoleDescriptor with `PassiveRequestorEndpoint` = `/{tid}/wsfed`
- [ ] The same RoleDescriptor includes `SecurityTokenServiceEndpoint` = `/{tid}/wsfed`
- [ ] WS-Fed signing certificate matches `IDPSSODescriptor`
- [ ] Sign-out is advertised on the same PassiveRequestorEndpoint; `wsignout1.0` is not required to pass this story
- [ ] `IDPSSODescriptor` remains on that document

### Outcome KPIs

- **Who:** Developers pointing `MetadataAddress` at the emulator
- **Does what:** Locate TokenEndpoint and a signing cert from the existing metadata URL
- **By how much:** From 0% (SAML-only) to 100% of the WsFederation metadata parse used in CI
- **Measured by:** Stranger/metadata parse in the v0.8.0 witness (H2 shape)
- **Baseline:** Document has no WS-Fed RoleDescriptor

### Technical Notes

- Constraint: one metadata URL (A4 / H2 WORKS). Include both endpoints; the library maps PassiveRequestorEndpoint → TokenEndpoint and also reads SecurityTokenServiceEndpoint.
- EntityID may be the emulator login origin; do not require `sts.windows.net`.
- Depends on: existing FederationMetadata + tenant cert (shipped). Enables US-02.

---

## US-02: Sign-in challenge reaches `/wsfed` instead of a 404

### Problem

Priya Chen is a developer whose middleware, after reading metadata, challenges the browser to the TokenEndpoint. She finds it blocking that `GET /{tid}/wsfed?wa=wsignin1.0&…` is unrouted (404) on this emulator today.

### Who

- Developer with WsFederation already locating TokenEndpoint | Browser follows the challenge | Needs the URL metadata advertised to exist

### Solution

`GET` and `POST` `/{tid}/wsfed` answer `wa=wsignin1.0` with `wtrealm`, `wreply`, and optional `wctx`. Unauthenticated requests show the emulator sign-in, not a `wresult`.

### Domain Examples

#### 1: Happy path — Tasks API challenge

Browser requests `GET /{tid}/wsfed?wa=wsignin1.0&wtrealm=api://tasks-api&wreply=https://rp.example.test/signin-wsfed&wctx=tasks-return-state-7`. Response is HTTP 200 login HTML titled like other emulator sign-ins, not 404.

#### 2: Edge — `wctx` omitted

The Finance RP omits `wctx`. The challenge still reaches `/wsfed` and shows sign-in.

#### 3: Error/boundary — still no token before sign-in

A scripted GET without picking an account does not receive a `wresult` (Entra-shaped: login HTML, not a posted token).

### UAT Scenarios (BDD)

#### Scenario: Priya's sign-in challenge is not a 404

Given FederationMetadata names PassiveRequestorEndpoint as `{login_origin}/{tid}/wsfed`  
And the Tasks API app has Application ID URI `api://tasks-api`  
And reply URL `https://rp.example.test/signin-wsfed` is registered  
When the browser requests `GET /{tid}/wsfed` with `wa=wsignin1.0`, `wtrealm=api://tasks-api`, `wreply=https://rp.example.test/signin-wsfed`, and `wctx=tasks-return-state-7`  
Then the response is not 404

#### Scenario: Unauthenticated challenge shows sign-in, not a token

Given the same challenge as Priya's Tasks API  
When the request is unauthenticated  
Then the response is login HTML  
And the body is not a `wresult`

#### Scenario: Optional context is accepted on the challenge

Given the Finance RP challenges without `wctx`  
When the browser hits `/{tid}/wsfed` with `wa=wsignin1.0` and a registered realm and reply  
Then sign-in is shown  
And the later token POST (US-04) is not required to echo a `wctx` the RP never sent

#### Scenario: POST as well as GET can start sign-in

Given an RP that posts the WS-Fed parameters instead of using a query string  
When `POST /{tid}/wsfed` carries `wa=wsignin1.0`, `wtrealm=api://tasks-api`, and registered `wreply`  
Then the response is not 404  
And unauthenticated callers still see sign-in, not a `wresult`

### Acceptance Criteria

- [ ] `GET /{tid}/wsfed` with `wa=wsignin1.0` and registered `wtrealm` / `wreply` is not 404
- [ ] Unauthenticated challenge returns login HTML, not a `wresult`
- [ ] Optional `wctx` is accepted when present and may be omitted
- [ ] `POST /{tid}/wsfed` with the same `wa` / `wtrealm` / `wreply` is not 404

### Outcome KPIs

- **Who:** Developers whose middleware challenges to TokenEndpoint
- **Does what:** Reach emulator sign-in instead of 404
- **By how much:** From 100% 404 today to 0% 404 on the witnessed challenge
- **Measured by:** Challenge request in the CI stranger / manual Tasks API run
- **Baseline:** Unrouted `/wsfed`

### Technical Notes

- `wa` is `wsignin1.0` (OASIS). Unknown realm / bad `wreply` are US-06 / US-07.
- Depends on US-01 for the advertised URL. Enables US-03.

---

## US-03: Sign-in is the same account picker OIDC and SAML already use

### Problem

Priya Chen already signs into the emulator for OIDC and SAML on the “Pick an account” page with the LOCAL EMULATOR badge. She finds it costly to learn a second WS-Fed login product for the same directory.

### Who

- Returning emulator user | After a WS-Fed challenge | Wants the habit she already has

### Solution

WS-Fed sign-in reuses the same sign-in the emulator already uses for OIDC and SAML. Choosing Alex Rivera continues the WS-Fed request (realm, reply, context preserved).

### Domain Examples

#### 1: Happy path — Alex Rivera

Priya sees “Pick an account”, chooses **Alex Rivera** (`alex.rivera@workforce.example.test`), and continues the Tasks API sign-in.

#### 2: Edge — password mode already on

The lab sets the emulator to require password (the existing switch). Priya sees the same email/password form OIDC uses, not a WS-Fed-only form.

#### 3: Error/boundary — no second chrome

A WS-Fed-only “enter realm” page would fail this story even if sign-in eventually worked.

### UAT Scenarios (BDD)

#### Scenario: Priya signs in with the same account picker she already uses

Given the browser is on emulator sign-in after a WS-Fed challenge for `api://tasks-api`  
And Alex Rivera is an enabled user in the workforce tenant  
When Priya chooses Alex Rivera  
Then she sees the same Pick an account chrome the emulator uses for OIDC and SAML  
And sign-in continues with the same `wtrealm`, `wreply`, and `wctx`

#### Scenario: Password-required mode stays the existing form

Given the emulator is already in password-required mode  
When Priya hits a WS-Fed challenge  
Then she sees the same email and password form OIDC uses  
And she does not see a WS-Fed-specific login page

#### Scenario: Challenge parameters survive account choice

Given `wctx` was `tasks-return-state-7` on the challenge  
When Priya chooses Alex Rivera  
Then the completing POST (US-04) still has that `wctx`  
And `wtrealm` remains `api://tasks-api`

#### Scenario: LOCAL EMULATOR badge is present

Given Priya is looking at WS-Fed sign-in HTML  
When the page renders  
Then it is recognizably the existing emulator sign-in (LOCAL EMULATOR badge), not Entra cloud chrome pretending to be production

### Acceptance Criteria

- [ ] WS-Fed challenge uses the same Pick an account (or existing password) sign-in as OIDC and SAML
- [ ] Choosing Alex Rivera continues the same `wtrealm`, `wreply`, and `wctx`
- [ ] Password-required mode does not introduce a WS-Fed-only form
- [ ] Chrome stays the local emulator sign-in, not a second product

### Outcome KPIs

- **Who:** Developers who already use the emulator for OIDC/SAML
- **Does what:** Complete WS-Fed interactive sign-in without a new UI
- **By how much:** 0 new login pages introduced
- **Measured by:** Visual/habit check in e2e (same page family as OIDC/SAML)
- **Baseline:** N/A for WS-Fed (404); OIDC/SAML picker already exists

### Technical Notes

- Behavior: reuse existing sign-in. Do not specify signed-state type names in this story.
- Depends on US-02. Enables US-04.

---

## US-04: The RP receives a SAML 2.0 `wresult` at its registered reply

### Problem

Priya Chen needs the Tasks API `/signin-wsfed` endpoint to receive the same envelope Entra posts after sign-in. Today no token is issued, so the middleware never gets a `wresult`. A SAML 1.1 assertion (SharePoint-shaped) would also fail this witness.

### Who

- Developer with a registered reply URL | After Alex Rivera is chosen | Needs a verifiable SAML 2.0 token posted to that URL only

### Solution

After sign-in, the browser POSTs to the **registered** `wreply`: `wa=wsignin1.0`, `wresult` (RequestSecurityTokenResponse wrapping a SAML 2.0 assertion), and echoed `wctx` when the RP sent one. Audience equals `wtrealm`. Issuer equals metadata entityID. Signature uses the metadata signing cert.

### Domain Examples

#### 1: Happy path — Tasks API POST

POST `https://rp.example.test/signin-wsfed` with `wa=wsignin1.0`, `wresult` TokenType `…#SAMLV2.0` / assertion `Version="2.0"`, Audience `api://tasks-api`, `wctx=tasks-return-state-7`.

#### 2: Edge — no `wctx`

Finance RP omitted `wctx`. POST has `wa` and `wresult` and does not invent a context value.

#### 3: Error/boundary — SAML 1.1 is wrong for this RP

A SharePoint-shaped SAML 1.1 assertion in `wresult` is out of v0.8.0 and must not be what Tasks API receives.

### UAT Scenarios (BDD)

#### Scenario: The Tasks API receives a SAML 2.0 token at its registered reply URL

Given Priya chose Alex Rivera after a challenge with `wtrealm=api://tasks-api`, `wreply=https://rp.example.test/signin-wsfed`, and `wctx=tasks-return-state-7`  
When the emulator completes sign-in  
Then the browser POSTs to `https://rp.example.test/signin-wsfed`  
And the POST includes `wa=wsignin1.0`  
And `wresult` is a RequestSecurityTokenResponse wrapping a SAML 2.0 assertion

#### Scenario: Token audience matches the application ID URI

Given `wtrealm` was `api://tasks-api`  
When `wresult` is posted  
Then the assertion Audience is `api://tasks-api`

#### Scenario: Issuer matches federation metadata

Given FederationMetadata entityID is `${entity_id}`  
When `wresult` is posted  
Then the assertion Issuer equals that entityID

#### Scenario: Context is echoed unchanged

Given the challenge included `wctx=tasks-return-state-7`  
When `wresult` is posted  
Then `wctx` is `tasks-return-state-7`

#### Scenario: Omitted context stays omitted

Given the Finance RP challenge omitted `wctx`  
When `wresult` is posted  
Then the POST does not require a `wctx` field the RP never sent

#### Scenario: Assertion version is SAML 2.0 for this witness

Given the Tasks API `Wtrealm` is an app-registration Application ID URI `api://tasks-api`  
When `wresult` is issued  
Then TokenType is SAML 2.0 (`…#SAMLV2.0`)  
And the inner assertion `Version` is `2.0`  
And the assertion is not SAML 1.1

### Acceptance Criteria

- [ ] After sign-in, browser POSTs `wa=wsignin1.0` + `wresult` to the registered `wreply`
- [ ] `wresult` wraps a SAML 2.0 assertion (not SAML 1.1)
- [ ] Audience equals `wtrealm`
- [ ] Issuer equals metadata entityID
- [ ] `wctx` is echoed when present and not invented when absent
- [ ] Signature is verifiable with the FederationMetadata signing cert (same as SAML)

### Outcome KPIs

- **Who:** Developers whose RP callback expects an Entra-shaped `wresult`
- **Does what:** Receive a SAML 2.0 RSTR at the registered reply
- **By how much:** From 0 tokens issued to 100% of happy-path sign-ins in the witness
- **Measured by:** Captured POST fields in e2e (TokenType / Version / Audience / wctx) — not raw credential dumps in git
- **Baseline:** No `/wsfed` token

### Technical Notes

- Spike: `…saml-token-profile-1.1#SAMLV2.0` is SAML **2.0** (profile 1.1). Mint `Version="2.0"`.
- POST target must be registered (happy path). Refusal of bad `wreply` is US-07.
- Depends on US-03. Enables US-05.

---

## US-05: Unmodified WsFederation completes sign-in

### Problem

Priya Chen will not fork `Microsoft.AspNetCore.Authentication.WsFederation`. She finds it useless if the emulator only passes its own tests while the library she already shipped rejects metadata or the token (the SAML v0.6.0 lesson).

### Who

- Developer (and CI stranger) | After `wresult` POST | Needs the unmodified library to establish a session

### Solution

Unmodified `Microsoft.AspNetCore.Authentication.WsFederation` completes sign-in against the emulator with only host and TLS knobs changed versus Entra. No gallery, Graph, MFA, Conditional Access, or B2C.

### Domain Examples

#### 1: Happy path — Tasks API session

Priya's middleware accepts the token. She has an authenticated session at `https://rp.example.test`.

#### 2: Edge — host and TLS only

She changes `MetadataAddress` origin to the emulator, trusts the local cert (or equivalent TLS knob), and leaves library defaults. Sign-in still completes.

#### 3: Error/boundary — gallery not required

If sign-in required an Enterprise app gallery template or a cloud policy, the emulator would fail this story.

### UAT Scenarios (BDD)

#### Scenario: Priya's unmodified WsFederation middleware completes sign-in

Given Priya pointed `MetadataAddress` and `Wtrealm` at the emulator  
And she did not modify `Microsoft.AspNetCore.Authentication.WsFederation`  
When Alex Rivera completes emulator sign-in for the Tasks API  
Then the middleware accepts the token  
And Priya has an authenticated session at the Tasks API

#### Scenario: Only host and TLS knobs change versus Entra

Given Priya's Entra config used the same `Wtrealm` `api://tasks-api` and callback `/signin-wsfed`  
When she points `MetadataAddress` at the emulator login origin (and TLS trust as she already does for OIDC)  
Then sign-in completes without extra WS-Fed library options for gallery, MFA, or encryption

#### Scenario: The CI stranger is that same library

Given v0.8.0 claims WS-Fed sign-in  
When the witness runs  
Then it is unmodified `Microsoft.AspNetCore.Authentication.WsFederation`  
And a pass means that library completed metadata fetch plus sign-in

#### Scenario: OIDC and SAML sign-in still work

Given WS-Fed sign-in is available  
When Priya (or CI) runs an existing OIDC or SAML sign-in against the same emulator  
Then those flows still complete (guardrail)

### Acceptance Criteria

- [ ] Unmodified `Microsoft.AspNetCore.Authentication.WsFederation` completes sign-in
- [ ] Configuration delta versus Entra is host / TLS, not library forks or gallery/MFA features
- [ ] v0.8.0 witness is that library completing metadata + sign-in
- [ ] Existing OIDC and SAML sign-in still succeed

### Outcome KPIs

- **Who:** Developers (and CI) using the locked stranger
- **Does what:** Complete one SP-initiated WS-Fed sign-in unmodified
- **By how much:** From 0 witnessed passes to a green stranger run
- **Measured by:** CI stranger result (pass/fail), same bar as SAML `node-saml`
- **Baseline:** Never run (interview Q1); 404 today

### Technical Notes

- DESIGN owns harness layout. This story states the witness and the observable session, not YAML paths.
- Depends on US-01–US-04. Walking skeleton closes here.

---

## US-06: Unknown `wtrealm` is refused

### Problem

Priya Chen (or a typo in `Wtrealm`) might challenge with `api://unknown-app`. She finds it unsafe if the emulator still posts a token to whatever `wreply` was on the query string for an app it does not have.

### Who

- Developer / operator | Challenge with a realm that is not a registered Application ID URI | Needs a clear refusal, not a token to an attacker-controlled reply

### Solution

If `wtrealm` does not match a registered Application ID URI, sign-in does not POST `wresult` to the caller-supplied `wreply`. The error stays on the emulator.

### Domain Examples

#### 1: Happy contrast — known realm

`wtrealm=api://tasks-api` (registered) proceeds to sign-in (US-02).

#### 2: Error — unknown URI

`wtrealm=api://not-registered` with `wreply=https://attacker.example.test/steal` does not POST to the attacker.

#### 3: Boundary — empty realm

Challenge omits `wtrealm` or sends it empty. No `wresult` POST to `wreply`.

### UAT Scenarios (BDD)

#### Scenario: Unknown application ID URI does not issue a token to the caller reply

Given no app has Application ID URI `api://not-registered`  
When the browser requests `/{tid}/wsfed` with `wa=wsignin1.0`, `wtrealm=api://not-registered`, and `wreply=https://attacker.example.test/steal`  
Then the emulator does not POST `wresult` to `https://attacker.example.test/steal`

#### Scenario: Empty realm is refused

Given a challenge with `wa=wsignin1.0` and no usable `wtrealm`  
When the browser hits `/{tid}/wsfed`  
Then no `wresult` is posted to `wreply`

#### Scenario: Known Tasks API realm still signs in

Given Application ID URI `api://tasks-api` is registered  
When Priya challenges with that `wtrealm` and a registered reply  
Then sign-in can proceed (does not break US-02)

### Acceptance Criteria

- [ ] Unknown `wtrealm` never POSTs `wresult` to the query-string `wreply`
- [ ] Missing/empty `wtrealm` never POSTs `wresult` to `wreply`
- [ ] Registered `api://tasks-api` is unaffected

### Outcome KPIs

- **Who:** Developers and anyone who can craft a challenge URL
- **Does what:** Avoid open-redirect token delivery for unknown realms
- **By how much:** 0 `wresult` POSTs to unowned URLs in this class
- **Measured by:** Negative e2e — attacker `wreply` receives no POST
- **Baseline:** No WS-Fed resolver (404); must not “fix” 404 by trusting query string

### Technical Notes

- Observable refusal; DESIGN chooses status/body. Must not bounce to unowned `wreply`.
- Depends on US-02 existing. Independently demonstrable.

---

## US-07: Missing or unregistered `wreply` is refused

### Problem

Priya's SAML analog already refuses an unregistered ACS so errors are not bounced to an endpoint the app does not own. She finds it unsafe if WS-Fed honors any `wreply` on the query string.

### Who

- Developer | Challenge `wreply` missing or not registered for that app | Needs the SAML-class guarantee

### Solution

`wreply` must match a registered reply URL for the app identified by `wtrealm`. Missing or unregistered values do not receive a `wresult`. Do not trust the query string.

### Domain Examples

#### 1: Happy contrast — registered

`wreply=https://rp.example.test/signin-wsfed` is registered for Tasks API → POST allowed (US-04).

#### 2: Error — unregistered

`wreply=https://rp.example.test/not-a-callback` is not registered → no POST there.

#### 3: Error — omitted

Challenge has `wtrealm=api://tasks-api` but no `wreply` → no token POST to a guessed URL.

### UAT Scenarios (BDD)

#### Scenario: Unregistered reply URL does not receive a token

Given Tasks API is registered with reply `https://rp.example.test/signin-wsfed` only  
When the browser challenges with `wtrealm=api://tasks-api` and `wreply=https://rp.example.test/not-a-callback`  
Then the emulator does not POST `wresult` to `https://rp.example.test/not-a-callback`

#### Scenario: Missing reply URL does not receive a token

Given a challenge with `wtrealm=api://tasks-api` and no `wreply`  
When the browser hits `/{tid}/wsfed`  
Then the emulator does not POST `wresult` to an unregistered or guessed URL

#### Scenario: Registered reply still receives the token

Given `https://rp.example.test/signin-wsfed` is registered for `api://tasks-api`  
When Priya completes sign-in with that `wreply`  
Then US-04 still POSTs `wresult` there

#### Scenario: Another app's reply is not accepted

Given Tasks API owns `https://rp.example.test/signin-wsfed`  
And Finance API owns `https://finance.example.test/signin-wsfed`  
When a challenge uses `wtrealm=api://tasks-api` and Finance's reply URL  
Then Tasks API sign-in does not POST `wresult` to the Finance reply

### Acceptance Criteria

- [ ] Unregistered `wreply` never receives `wresult`
- [ ] Missing `wreply` never receives `wresult` at a guessed URL
- [ ] Registered `wreply` for that `wtrealm` still works
- [ ] A reply registered to a different app is not accepted

### Outcome KPIs

- **Who:** Developers configuring reply URLs
- **Does what:** Keep `wresult` on URLs they registered
- **By how much:** 0 POSTs to unregistered replies
- **Measured by:** Negative e2e (unregistered / cross-app `wreply`)
- **Baseline:** No WS-Fed reply check

### Technical Notes

- How reply URLs are stored (new type vs reuse) is DESIGN. Requirement is registered-for-that-app, SAML ACS analog.
- Depends on US-02. Independently demonstrable.

---

## US-08: Unsolicited `wresult` is refused

### Problem

Priya's locked stranger disables unsolicited logins by default. She finds it unsafe if anyone can POST a `wresult` to `/signin-wsfed` (or to `/{tid}/wsfed`) without starting at the RP.

### Who

- Developer relying on SP-initiated WS-Fed | IdP-initiated or forged POST | Needs refusal matching middleware default

### Solution

Refuse `wresult` that did not start as a challenge at this STS. IdP-initiated / AllowUnsolicitedLogins stays out of v0.8.0.

### Domain Examples

#### 1: Happy contrast — SP-initiated

Tasks API redirects to `/wsfed` first; after Alex Rivera, POST to `/signin-wsfed` is accepted (US-04/US-05).

#### 2: Error — POST `wresult` with no prior challenge

An actor POSTs `wa=wsignin1.0` + a `wresult` to the RP or STS without a prior `wsignin1.0` challenge from this emulator → refused; no session.

#### 3: Boundary — IdP-initiated out of scope

No emulator feature flag to allow unsolicited logins in v0.8.0.

### UAT Scenarios (BDD)

#### Scenario: A token POST that did not start at this STS is refused

Given no challenge was issued for the Tasks API  
When an actor POSTs `wa=wsignin1.0` and a `wresult` as if sign-in had completed  
Then the emulator does not treat that as a successful sign-in it initiated  
And the Tasks API does not gain a session from that unsolicited token via this STS

#### Scenario: SP-initiated sign-in still succeeds

Given Priya started at the Tasks API and the emulator issued the challenge  
When Alex Rivera completes sign-in  
Then US-04 / US-05 still succeed

#### Scenario: Unsolicited login is not offered as a setting

Given v0.8.0 WS-Fed  
When Priya looks for an allow-unsolicited-logins switch  
Then that behavior is out of this cut (no flag required to refuse)

### Acceptance Criteria

- [ ] `wresult` without a prior challenge at this STS is refused
- [ ] SP-initiated happy path still completes
- [ ] No v0.8.0 setting turns on IdP-initiated / unsolicited logins

### Outcome KPIs

- **Who:** Developers using default WsFederation (unsolicited off)
- **Does what:** Remain unable to complete IdP-initiated login against the emulator
- **By how much:** 0 unsolicited sessions in the witness
- **Measured by:** Negative e2e POSTing `wresult` without a challenge
- **Baseline:** Unsolicited not applicable (no token); must not “help” by accepting one

### Technical Notes

- How the STS correlates challenge to response is DESIGN (SAML `InResponseTo` analog). Observable: unsolicited refused.
- Depends on US-02/US-04 existing enough to distinguish solicited vs not.

---

## Traceability

| Story | DISCOVER opportunity | Spike |
|---|---|---|
| US-01 | O2, O5, O7 (advertise-only) | H2 WORKS |
| US-02 | O1 | Unauthenticated GET is login HTML |
| US-03 | A8 / H4 | — |
| US-04 | O3, O5, O6 (`wctx`) | A3 S3b SAML 2.0; Audience = wtrealm |
| US-05 | H1 | Locked stranger |
| US-06 | O4 | — |
| US-07 | O4 | — |
| US-08 | O6 | Stranger default off |
