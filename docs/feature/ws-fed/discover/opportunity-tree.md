# Opportunity tree — ws-fed

**Feature ID:** `ws-fed`
**Wave:** DISCOVER / Phase 2 (updated after maintainer interview #1)
**Scoring method:** Opportunity Algorithm, **documentary-derived** plus maintainer scope locks (Q3–Q5). Importance and satisfaction are still not from 5+ interviews. Labelled so they are not mistaken for interview scores.

**Formula:** Score = Importance + Max(0, Importance − Satisfaction). Each 1–10. Max 20. Pursue if >8.

**Desired outcome:** `Microsoft.AspNetCore.Authentication.WsFederation` pointed at this emulator completes the same metadata + `/wsfed` sign-in it already completes against Entra. SLO advertised in metadata, not witnessed (interview #1 Q3–Q4).

```
Desired outcome: RP completes Entra-shaped WS-Fed against the emulator
|
+-- O1  Sign-in endpoint exists and answers wa=wsignin1.0     score 20
|     (today: 404)
|
+-- O2  Federation metadata advertises PassiveRequestorEndpoint
|     and a WS-Fed RoleDescriptor on the existing URL           score 19
|
+-- O3  Token in wresult is the assertion version
|     WsFederation actually verifies (spike; not SharePoint-first)  score 18
|
+-- O4  wtrealm + wreply resolved against registered apps,
|     not taken from the query string                          score 16
|
+-- O5  Signing cert in RoleDescriptor === IDPSSODescriptor
|     === tenant RSA that signs the assertion                  score 15
|
+-- O6  wctx echoed; unsolicited POSTs refused by default      score 12
|
+-- O7  Advertise wsignout in metadata (do not witness SLO)    score  7
|
+-- O8  /common/wsfed tenant-independent endpoint              score  8
|
+-- O9  IdP-initiated / unsolicited login                      score  3
|
+-- O10 SOAP / active WS-Trust (locked out, Q5)                score  2
```

---

## Opportunity detail

### O1 — `/wsfed` answers `wa=wsignin1.0` (score 20)

| | |
|---|---|
| Importance | 10 — every documented RP's login URL is this path (D3, D4, D5). |
| Satisfaction | 0 — unrouted (D1). |
| Job steps | Execute |
| Why underserved | SAML `/saml2` does not substitute: SharePoint is told to rewrite `/saml2` → `/wsfed` (D5). Binding and token envelope differ (`SAMLRequest` vs `wa`/`wtrealm`; `SAMLResponse` vs `wresult`). |

**Solution ideas (diverse, not variants):**

- **S1a.** New `GET|POST /{tenant}/wsfed` handler, `Kind: "wsfed"` in signed state, reuse OIDC/SAML login UI (SAML analog).
- **S1b.** Alias `/wsfed` onto `/saml2` and translate parameters. **Rejected at idea level:** D5 exists specifically because the two paths are not aliases.
- **S1c.** Reverse-proxy to a real Entra tenant for WS-Fed only. **Rejected:** breaks the product job (local, deterministic, no cloud).

### O2 — Same metadata URL grows a WS-Fed RoleDescriptor (score 19)

| | |
|---|---|
| Importance | 10 — ASP.NET `MetadataAddress` is FederationMetadata; BC "WS-Federation Metadata Location" is the same path (D3, D4). |
| Satisfaction | 1 — document exists but is SAML-only (D1). |
| Job steps | Locate, Confirm |

**Solution ideas:**

- **S2a.** Extend `samlMetadataXML` / `entityDescriptor` with `RoleDescriptor xsi:type="fed:SecurityTokenServiceType"`, `fed:PassiveRequestorEndpoint` (and likely `fed:SecurityTokenServiceEndpoint` — present in D7's Entra capture, not shown in the Learn snippet). Same cert bytes as `IDPSSODescriptor`.
- **S2b.** New URL e.g. `/wsfed/metadata`. **Rejected at idea level:** would break `MetadataAddress` (A4, provisionally validated).
- **S2c.** Serve two documents at the same path via content negotiation. No RP documented as sending an Accept header that would select WS-Fed.

### O3 — Token inside `wresult` matches the chosen RP (score 18)

| | |
|---|---|
| Importance | 9 — a wrong assertion version fails verification even if the envelope is perfect. |
| Satisfaction | 0 on `/wsfed`. SAML 2.0 assertions already exist on `/saml2`, which is the **wrong envelope and possibly the wrong version**. |
| Job steps | Execute, Monitor |
| Conflict | D5: SAML 1.1 for SharePoint (**not** the witness). D7: captured Entra RSTR for an app-reg realm is SAML **2.0** (closer to ASP.NET `Wtrealm`). Interview #1 Q3 locked the stranger; A3 is a **spike**, not a SharePoint-first decision. |

**Solution ideas:**

- **S3a.** Always SAML 1.1 in the RSTR (SharePoint-shaped). **Not the default** — SharePoint is not the v0.8.0 witness.
- **S3b.** Always SAML 2.0 in the RSTR (reuse `buildAssertion`). Leading **hypothesis** because D7's Entra capture is app-reg-shaped; still unproven for this team's WsFederation run.
- **S3c.** Token version selected by registered app / gallery type / `wtrealm` pattern. More surface; out of a v0.8.0-shaped cut unless the spike shows Entra actually branches.

**Do not pick S3a/b/c in DISCOVER.** The test is an Entra `/wsfed` capture consumed by `Microsoft.AspNetCore.Authentication.WsFederation`.

### O4 — Realm and reply URL are registered, not trusted from the request (score 16)

| | |
|---|---|
| Importance | 8 — SAML already refuses an unregistered ACS (`samlsso.go`: do not bounce errors to an unowned endpoint). WS-Fed `wreply` is the same class of redirect. |
| Satisfaction | 0 — no WS-Fed resolver. Store already has `AppIDURI` (`GetAppByIDURI`) which matches Entra `Wtrealm` = Application ID URI (D3). Reply URL type (`saml-acs` vs new `wsfed-reply` vs reuse) is undecided. |

**Solution ideas:**

- **S4a.** `wtrealm` → `GetAppByIDURI`; `wreply` must match a registered redirect (new type or shared).
- **S4b.** Honor `wreply` if present, else a single registered reply. Weaker; SAML analog chose validation over trust.

### O5 — One tenant key, two metadata sections, one signature (score 15)

| | |
|---|---|
| Importance | 9 — Learn: certificates in both sections **will be the same** (D2). SAML already derives the cert from the tenant RSA (`tokens.SAMLCertificate`). |
| Satisfaction | 3 — key and SAML-section cert exist; WS-Fed section does not. |

Solution: reuse `EnsureActiveKey` + `SAMLCertificate`; do not mint a second key.

### O6 — `wctx` echo and no unsolicited logins (score 12)

Microsoft middleware disables unsolicited logins by default (D3). OASIS: `wctx` MUST be returned if passed (D6). Analog of SAML `RelayState` + `InResponseTo`.

v0.8.0-shaped: refuse POSTs with `wresult` that did not start at this STS. The locked stranger disables unsolicited logins by default (D3). No `AllowUnsolicitedLogins` emulator flag unless a later witness needs it.

### O7 — Advertise sign-out in metadata (score 7)

| | |
|---|---|
| Importance | 4 — interview #1 Q4: advertise `wsignout` like SAML did; **do not witness SLO**. |
| Satisfaction | 1 — metadata does not yet name a WS-Fed PassiveRequestorEndpoint at all. |
| Score | 4 + max(0, 4−1) = **7** (<8, do not pursue as a separate release item) |

Ride along with O2: the RoleDescriptor's PassiveRequestorEndpoint is Entra's sign-in **and** sign-out URL. Do not build or CI-witness `wsignout1.0` / `wsignoutcleanup1.0` in v0.8.0.

### O8 — `/common/wsfed` (score 8)

BC documents it (D4). Emulator SAML has no `/common/saml2`. The locked stranger (ASP.NET `MetadataAddress`) uses a tenant-specific FederationMetadata URL in the Entra tutorial. Not v0.8.0 unless a later spike shows WsFederation pointed at `common`.

### O9 — IdP-initiated / unsolicited (score 3)

Importance 3: middleware default off (D3). Deprioritize.

### O10 — Active / SOAP WS-Trust (score 2)

**Locked out** by interview #1 Q5: "Active profile stays out even if it exists somewhere." Explicit non-goal.

---

## Top 2–3 to pursue

Maintainer aligned on witness (Q3), SLO advertise-only (Q4), SOAP out (Q5). A1 is a demand class, not usage.

1. **O1** — `/wsfed` sign-in (S1a)
2. **O2** — RoleDescriptor on the existing metadata URL (S2a), including advertising the same URL for sign-out (O7 rides along)
3. **O3** — assertion version for **WsFederation** — **spike** (Entra capture + metadata parse) before locking S3b vs S3a

O4 and O5 ride along with O1/O2 the same way ACS validation and cert derivation rode along with SAML.

---

## Gate G2

| Metric | Target | Result |
|---|---|---|
| Distinct opportunities | 5+ | 10 mapped |
| Top scores | >8 | O1=20, O2=19, O3=18 |
| Job-step coverage | 80%+ | 8/8 steps have an opportunity |
| Team alignment | Confirmed | **Partial.** Witness (A5), SLO (A6), SOAP (A2) locked. Token version (A3) open. A1 is demand-class, not usage. |

**G2: partial.** OST complete; top scores >8; maintainer aligned on consumer and non-goals. Do not treat documentary scores as 5-interview importance. Do not start DISCUSS while A3 is unspiked — stories would have to guess SAML 1.1 vs 2.0.

---

## What this tree deliberately does not include

- Portal UX for "WS-Fed apps"
- Graph APIs
- MFA / Conditional Access / B2C user flows
- A policy engine
- Inventing a second metadata path
