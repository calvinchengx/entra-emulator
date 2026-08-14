# Journey visual — point a WS-Fed RP at the local STS

**Feature-wave copy.** Canonical SSOT: `docs/product/journeys/ws-fed-sign-in-visual.md`.

**Persona:** Priya Chen, backend engineer. She already has an ASP.NET Core Tasks API using `AddWsFederation` against Entra. She wants the same `MetadataAddress` + `Wtrealm` to work against the emulator.

**Goal:** Unmodified `Microsoft.AspNetCore.Authentication.WsFederation` completes metadata fetch and sign-in against the emulator.

**Emotional arc (Problem Relief):** Frustrated → hopeful → focused / familiar → relieved → satisfied.

**JTBD:** skipped; traces to DISCOVER job in `docs/feature/ws-fed/discover/problem-validation.md`.

**Medium:** Protocol + existing web account picker. Not a new GUI. Not a CLI. Config is C# the RP already has; login is the same “Pick an account” page OIDC and SAML already use.

---

## Horizontal flow

```
 [Frustrated]                         [Hopeful]                         [Focused]
 Point MetadataAddress                FederationMetadata                Browser hits
 + Wtrealm at emulator                grows WS-Fed                      GET /{tid}/wsfed
 (today: 404, SAML-only               RoleDescriptor                    ?wa=wsignin1.0
  metadata)                           (PassiveRequestor                 &wtrealm=api://tasks-api
                                      + SecurityTokenService            &wreply=https://rp.example.test/signin-wsfed
                                      + same cert)                      &wctx=tasks-return-state-7
        |                                    |                                 |
        v                                    v                                 v
 [Familiar]                           [Relieved]                         [Satisfied]
 Pick an account                      POST to registered                 Middleware verifies
 (LOCAL EMULATOR badge,               wreply: wa=wsignin1.0              SAML 2.0 assertion;
  same chrome as OIDC/SAML)           + wresult (RSTR)                   Priya has a session
  Alex Rivera                         + echoed wctx                      at the Tasks API RP
```

Shared artifacts that must match across steps: `${tid}`, `${wtrealm}`, `${wreply}`, `${metadata_url}`, `${wsfed_url}`, `${entity_id}`, `${signing_cert}`, `${wctx}`, `${audience}`. Registry: `docs/feature/ws-fed/discuss/shared-artifacts-registry.md`.

---

## Step 1 — Point the RP at the emulator

**Feels:** Frustrated. Priya already knows this config against Entra. Today the emulator 404s `/wsfed` and serves SAML-only metadata.

```
+-- Step 1: Point MetadataAddress + Wtrealm --------------------------------+
|                                                                            |
|  // Tasks API — only host / TLS knobs change vs Entra                      |
|  options.MetadataAddress =                                                 |
|    "${login_origin}/${tid}/federationmetadata/2007-06/federationmetadata.xml";
|  options.Wtrealm = "api://tasks-api";   // ${wtrealm}                      |
|  // Callback path stays /signin-wsfed → ${wreply}                          |
|      https://rp.example.test/signin-wsfed                                  |
|                                                                            |
|  App in the emulator directory:                                            |
|    display name  Tasks API                                                 |
|    appIdUri      api://tasks-api                                           |
|    reply URL     https://rp.example.test/signin-wsfed  (registered)        |
+----------------------------------------------------------------------------+
```

**Integration checkpoint:** `${wtrealm}` equals the app’s Application ID URI. `${wreply}` is a registered reply URL for that app. Do not invent a second metadata path.

---

## Step 2 — Fetch FederationMetadata

**Feels:** Hopeful. The document she already configured now names a WS-Fed STS, not only SAML.

```
+-- Step 2: FederationMetadata (existing URL) --------------------------------+
| GET ${metadata_url}                                                         |
| ${login_origin}/${tid}/federationmetadata/2007-06/federationmetadata.xml    |
|                                                                             |
| EntityDescriptor entityID="${entity_id}"                                    |
|   IDPSSODescriptor                          ← already shipped (SAML)        |
|     KeyDescriptor / X509Certificate = ${signing_cert}                       |
|   RoleDescriptor  (WS-Fed STS)              ← new                           |
|     KeyDescriptor / X509Certificate = ${signing_cert}   SAME bytes          |
|     PassiveRequestorEndpoint     → ${wsfed_url}   /{tid}/wsfed              |
|     SecurityTokenServiceEndpoint → ${wsfed_url}   /{tid}/wsfed              |
|     (sign-out advertised on the same PassiveRequestorEndpoint)              |
|                                                                             |
| WsFederation maps PassiveRequestorEndpoint → TokenEndpoint = ${wsfed_url}   |
+-----------------------------------------------------------------------------+
```

**Integration checkpoint:** Signing cert in the WS-Fed section equals the SAML section. Both endpoints are `/{tid}/wsfed`. `${entity_id}` is the value the assertion Issuer will use (emulator login origin is allowed; hostname `sts.windows.net` is not required).

---

## Step 3 — Challenge hits `/wsfed`

**Feels:** Focused. No 404. Unauthenticated request shows login, not a token.

```
+-- Step 3: Challenge --------------------------------------------------------+
| GET ${wsfed_url}                                                            |
|     ?wa=wsignin1.0                                                          |
|     &wtrealm=api://tasks-api                                                |
|     &wreply=https://rp.example.test/signin-wsfed                            |
|     &wctx=tasks-return-state-7                                              |
|                                                                             |
| HTTP 200  HTML  title "Sign in — Entra Emulator"                            |
| (not a wresult; not a 404; not a bounce to an unowned wreply)               |
+-----------------------------------------------------------------------------+
```

**Error forks (not this step’s happy path):** unknown `${wtrealm}`; missing or unregistered `${wreply}`; POST of `wresult` with no prior challenge (unsolicited).

---

## Step 4 — Same sign-in as OIDC and SAML

**Feels:** Familiar. Deep delight = no second UI. Chrome matches what Priya already sees for OIDC and SAML.

```
+-- Step 4: Pick an account --------------------------------------------------+
|  ┌─────────────────────────────────────────┐                                |
|  │ LOCAL EMULATOR                          │                                |
|  │                                         │                                |
|  │ Pick an account                         │                                |
|  │                                         │                                |
|  │  Alex Rivera                            │                                |
|  │  alex.rivera@workforce.example.test     │                                |
|  │                                         │                                |
|  │  Jordan Blake                           │                                |
|  │  jordan.blake@workforce.example.test    │                                |
|  │                                         │                                |
|  │ Not for production use.                 │                                |
|  │ Never enter a real password.            │                                |
|  └─────────────────────────────────────────┘                                |
|                                                                             |
| Same page the emulator already uses for OIDC and SAML.                      |
| No WS-Fed-specific chrome, no second password form.                         |
+-----------------------------------------------------------------------------+
```

**Integration checkpoint:** Choosing Alex Rivera continues the same sign-in request (wa / wtrealm / wreply / wctx preserved). Password-required mode, when the emulator is already in that mode, is the same form OIDC uses — not a new WS-Fed form.

---

## Step 5 — POST `wresult` to the registered reply

**Feels:** Relieved. The RP’s `/signin-wsfed` receives the envelope Entra would have posted.

```
+-- Step 5: Browser POST to ${wreply} ----------------------------------------+
| POST https://rp.example.test/signin-wsfed                                   |
|   wa      = wsignin1.0                                                      |
|   wresult = RequestSecurityTokenResponse                                    |
|             TokenType  …#SAMLV2.0                                           |
|             assertion  Version="2.0"  xmlns SAML 2.0                        |
|             Audience   = ${wtrealm} = api://tasks-api                       |
|             Issuer     = ${entity_id}  (matches metadata entityID)          |
|             signed with ${signing_cert}                                     |
|   wctx    = tasks-return-state-7   (echo; must match step 3)                |
|                                                                             |
| wreply was registered. Query-string wreply is not trusted.                  |
+-----------------------------------------------------------------------------+
```

**Out of this journey:** SOAP, `/common/wsfed`, IdP-initiated, SAML 1.1, `wsignout1.0` body.

---

## Step 6 — Middleware completes; session at the RP

**Feels:** Satisfied. Priya did not patch the library. Host and TLS were the only knobs.

```
+-- Step 6: Unmodified stranger ----------------------------------------------+
| Microsoft.AspNetCore.Authentication.WsFederation                            |
|   MetadataAddress → found TokenEndpoint + cert                              |
|   Validates assertion (SAML 2.0, audience, issuer, signature, lifetime)     |
|   Priya has an authenticated session at the Tasks API                       |
|                                                                             |
| CI stranger: same library, unmodified, same bar as SAML's node-saml.        |
+-----------------------------------------------------------------------------+
```

---

## Error paths (horizontal)

| Failure | What Priya observes | Recovery |
|---|---|---|
| Metadata still SAML-only | Middleware cannot locate TokenEndpoint | Not a Priya workaround — this journey’s step 2 |
| `GET /{tid}/wsfed` 404 | Challenge dies | Step 3 exists |
| Unknown `wtrealm` | Sign-in does not POST to a caller-supplied reply; error stays on the emulator | Register Application ID URI `api://tasks-api` |
| Missing / unregistered `wreply` | No bounce to an unowned URL | Register `https://rp.example.test/signin-wsfed` |
| Unsolicited `wresult` POST | Refused; no RP session | Start at the RP (SP-initiated) |
| `wsignout1.0` | URL is advertised; this journey does **not** drive sign-out | Out of v0.8.0 witness |

---

## Emotional coherence

No jarring jump from “new WS-Fed login product” back to the emulator she already knows. Confidence builds: metadata names the endpoint → familiar picker → token at the URL she registered → library she already shipped accepts it.
