# Journey visual — sign out of a WS-Fed RP at the local STS

**Canonical SSOT.**

**Persona:** Priya Chen, backend engineer. She already pointed the ASP.NET Core Tasks API at the emulator (`AddWsFederation`, `Wtrealm=api://tasks-api`, reply `https://rp.example.test/signin-wsfed`). v0.8.0 completed **sign-in**. FederationMetadata already advertises sign-out on the same `PassiveRequestorEndpoint`. This journey **witnesses** that URL.

**Directory user:** Alice (`alice@entraemulator.dev`). Same stranger as v0.8.0 (`e2e/wsfed`).

**Goal:** Unmodified `Microsoft.AspNetCore.Authentication.WsFederation` `SignOut` drives `wa=wsignout1.0` to `/{tid}/wsfed`. The emulator session ends. The Tasks API session is gone. A new `wa=wsignin1.0` from the same browser shows Pick an account again.

**Emotional arc (Problem Relief, lightweight):** Frustrated → hopeful → relieved → confident.

**JTBD:** skipped — extends existing job `point-ws-fed-rp-at-local-sts` in `docs/product/jobs.yaml`. No second job.

**Medium:** Protocol + existing web session. Not a new GUI. Not a CLI. Config is the C# the RP already has; sign-out is the library’s `SignOut`, not a new emulator page product.

---

## Horizontal flow

```
 [Frustrated]                         [Hopeful]                         [Relieved]
 v0.8.0 sign-in done                  Unmodified SignOut                Emulator answers
 (Alice at picker;                    sends the browser to              wa=wsignout1.0 on
  Tasks API session).                 GET|POST /{tid}/wsfed             the same /{tid}/wsfed
 Sign-out URL is                      ?wa=wsignout1.0                   as sign-in. Shared
 advertised; today a                  &wtrealm=api://tasks-api          emulator session
 live session can still               &wreply=https://rp.example.test   (OIDC/SAML/WS-Fed
 be treated as sign-in.               /signin-wsfed                     cookie) is gone.
        |                                    |                                 |
        v                                    v                                 v
 [Relieved]                           [Confident]
 Browser returns to                   Next wa=wsignin1.0
 registered wsfed-reply.              from this browser
 Tasks API session is gone.           shows Pick an account
 Audit records the exchange           (Alice must choose again).
 (Flow=wsfed, no raw wresult).        v0.8.0 sign-in still works.
```

Shared artifacts that must match across steps: `${tid}`, `${wtrealm}`, `${wreply}`, `${wsfed_url}`, `${metadata_url}`, `${account}`.

---

## Step 1 — Completed v0.8.0 sign-in (precondition)

**Feels:** Frustrated. Sign-in works. Sign-out is advertised and frozen. Priya’s RP `SignOut` is the next Entra-shaped call she already ships.

```
+-- Step 1: Tasks API session already exists ---------------------------------+
|                                                                            |
|  MetadataAddress =                                                         |
|    "${login_origin}/${tid}/federationmetadata/2007-06/federationmetadata.xml";
|  Wtrealm = "api://tasks-api"           // ${wtrealm}                       |
|  Wreply  = "https://rp.example.test/signin-wsfed"  // ${wreply}             |
|                                                                            |
|  Alice (alice@entraemulator.dev) completed Pick an account.                |
|  Unmodified WsFederation accepted wresult.                                 |
|  Priya has an authenticated session at the Tasks API.                      |
|  FederationMetadata already names PassiveRequestorEndpoint ${wsfed_url}    |
|  as the sign-out URL (v0.8.0 US-01; this journey does not move it).        |
+----------------------------------------------------------------------------+
```

**Integration checkpoint:** This journey starts **after** the sign-in journey. Do not re-prove metadata growth or SAML 2.0 `wresult` here. Do not invent a second metadata path.

---

## Step 2 — Unmodified RP SignOut reaches `/{tid}/wsfed`

**Feels:** Hopeful. The library she already ships sends the browser to the URL metadata advertised.

```
+-- Step 2: Library SignOut --------------------------------------------------+
| GET|POST ${wsfed_url}                                                       |
|     ?wa=wsignout1.0                                                         |
|     &wtrealm=api://tasks-api                                                |
|     &wreply=https://rp.example.test/signin-wsfed                            |
|                                                                             |
| Host and TLS knobs only versus Entra.                                       |
| Same stranger: Microsoft.AspNetCore.Authentication.WsFederation 8.0.19      |
| Same e2e project: e2e/wsfed (extend; do not add a second suite).            |
|                                                                             |
| Prefer the return URL the library sends; otherwise the registered ${wreply}.|
+-----------------------------------------------------------------------------+
```

**Integration checkpoint:** `wa` is `wsignout1.0`. Endpoint is the existing `PassiveRequestorEndpoint`, not a new `/logout` product. Do not extend `e2e/dotnet`.

---

## Step 3 — Emulator ends the shared session

**Feels:** Relieved. The advertised URL finally does what it says. No new login chrome. No token mint.

```
+-- Step 3: Session ends on the emulator -------------------------------------+
| ${wsfed_url} answers wa=wsignout1.0                                         |
| Shared emulator session cookie (OIDC / SAML / WS-Fed) is gone.              |
| No wresult is minted.                                                       |
| Errors (unknown realm, unregistered return) stay on the emulator            |
| (LOCAL EMULATOR page). Never Location to an unowned URL.                    |
+-----------------------------------------------------------------------------+
```

**Integration checkpoint:** After this step, a new `wa=wsignin1.0` from the same browser must not silently SSO. Multi-RP `wsignoutcleanup1.0` fan-out to *other* relying parties is **out** of this journey unless the unmodified library cannot complete **single-RP** `SignOut` without it (current evidence: it does not require that fan-out).

---

## Step 4 — Browser returns; Tasks API session is gone

**Feels:** Relieved. Priya can observe the RP the same way she observes Entra: after `SignOut`, `/secure` is not authenticated.

```
+-- Step 4: Return to registered wsfed-reply ---------------------------------+
| Return URL must be type wsfed-reply for the app identified by ${wtrealm}.   |
| Prefer library-sent return; otherwise registered                            |
|   https://rp.example.test/signin-wsfed                                      |
|                                                                             |
| Not accepted as a sign-out return:                                          |
|   saml-acs  (https://rp.example.test/acs)                                   |
|   web       (https://rp.example.test/signin-oidc)                           |
|   another app's wsfed-reply                                                 |
|   https://attacker.example.test/steal                                       |
|                                                                             |
| Do not use type-blind HasRedirectURI.                                       |
| Priya no longer has an authenticated session at the Tasks API.              |
+-----------------------------------------------------------------------------+
```

---

## Step 5 — Next sign-in shows Pick an account

**Feels:** Confident. Sign-out was real. Sign-in still works.

```
+-- Step 5: Next challenge is not silent SSO ---------------------------------+
| GET ${wsfed_url}?wa=wsignin1.0&wtrealm=api://tasks-api                      |
|     &wreply=https://rp.example.test/signin-wsfed                            |
|                                                                             |
| HTTP 200 HTML  "Pick an account"  LOCAL EMULATOR                            |
| Alice (alice@entraemulator.dev) is listed.                                  |
| Not a wresult. Not a 404.                                                   |
|                                                                             |
| Completing the picker still POSTs a SAML 2.0 wresult (v0.8.0 unchanged).    |
+-----------------------------------------------------------------------------+
```

---

## Step 6 — Audit records the sign-out exchange

**Feels:** Confident. Same operator surface as sign-in. No second log.

```
+-- Step 6: Existing recorder ------------------------------------------------+
| Flow     = wsfed                                                            |
| ClientID = ${wtrealm} = api://tasks-api                                     |
| Subject  = Alice when a session was ended                                   |
| Body     = never raw wresult (and sign-out must not mint one)               |
| Graph auditLogs/signIns already treats Flow=wsfed as interactive.           |
| Do not invent a second log store.                                           |
+-----------------------------------------------------------------------------+
```

---

## Error paths (horizontal)

| Failure | What Priya observes | Recovery |
|---|---|---|
| `wa=wsignout1.0` treated as sign-in (today) | A live session can mint another `wresult` | This journey’s step 3 — answer sign-out, do not SSO |
| Unknown / empty `wtrealm` | Error stays on the emulator; no bounce to caller `wreply` | Register Application ID URI `api://tasks-api` |
| Return URL missing, unregistered, `saml-acs`, `web`, or another app | Error stays on the emulator; no bounce | Register `https://rp.example.test/signin-wsfed` as `wsfed-reply` |
| Unsolicited `wresult` POST | Still refused (v0.8.0 freeze) | Start at the RP (SP-initiated) |
| SOAP / active WS-Trust | Still 404 | Out of this journey |
| Multi-RP `wsignoutcleanup1.0` fan-out | Not this cut | Later slice |

---

## Emotional coherence

Lightweight research: happy path plus refuse-unsafe. No new login product, no jarring “signed-out marketing page.” Confidence builds: advertised URL is reached → session actually ends → RP is logged out → next sign-in is the picker she already knows.
