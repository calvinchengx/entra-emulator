# Spike findings — ws-fed (A3 TokenType)

**Feature ID:** `ws-fed`
**Wave:** SPIKE
**Date:** 14 Aug 2026
**Assumption tested (ONE):** What assertion TokenType (SAML 1.1 vs SAML 2.0) does Microsoft Entra put in a WS-Fed `wresult` (RSTR) for an app-registration `Wtrealm` that `Microsoft.AspNetCore.Authentication.WsFederation` will validate?
**Performance budget:** none (mechanism / protocol fact only)
**Spike code:** `/tmp/spike_ws-fed/` (deleted after this file)

---

## Order exception

Canonical nWave is DISCUSS then SPIKE. This feature ran SPIKE immediately after DISCOVER because A3 (SAML 1.1 vs 2.0 in `wresult`) would make DISCUSS stories guess. DISCUSS artifacts do not exist and were not invented. Inputs were:

- `docs/feature/ws-fed/discover/wave-decisions.md`
- `docs/feature/ws-fed/discover/problem-validation.md`
- `docs/feature/ws-fed/discover/solution-testing.md`

---

## Verdict

| Question | Verdict |
|---|---|
| **A3 TokenType in Entra `wresult` (this team's capture)** | **WORKS — SAML 2.0** (follow-up capture, 14 Aug 2026 12:05Z) |
| Metadata parse with IdentityModel / ASP.NET WsFederation (H2) | **WORKS** |

**TokenType observed by this team:** `http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0` wrapping a SAML **2.0** assertion (`Version="2.0"`, `xmlns="urn:oasis:names:tc:SAML:2.0:assertion"`). The `1.1` in the URI is the OASIS *token profile* version, not SAML 1.1.

First-pass capture against the differential capture tenant was INCONCLUSIVE (that tenant was later deleted). Closed on a subsequent interactive sign-in against a workforce tenant. Raw `wresult` was not committed (live credential).

---

## What ran

### 1. Metadata parse (H2 / A4 bonus — not A3)

Throwaway `dotnet` console (`Microsoft.IdentityModel.Protocols.WsFederation` 8.22.0 + `Microsoft.AspNetCore.Authentication.WsFederation` 8.0.19) loaded a saved FederationMetadata document via `WsFederationMetadataSerializer.ReadMetadata` and live-fetched:

`https://login.microsoftonline.com/{tid}/federationmetadata/2007-06/federationmetadata.xml`

Both parses succeeded with the same values:

| Field | Value |
|---|---|
| `Issuer` (entityID) | `https://sts.windows.net/{tid}/` |
| `TokenEndpoint` (from `fed:PassiveRequestorEndpoint`) | `https://login.microsoftonline.com/{tid}/wsfed` |
| `ActiveTokenEndpoint` (from `fed:SecurityTokenServiceEndpoint`) | same `/wsfed` URL |
| Signing keys | **4** `X509SecurityKey` |
| Document `Signature` | present (object populated) |
| `SigningCredentials` | empty after parse (library did not attach verify credentials; parse still succeeded) |
| `TokenTypesOffered` | **absent** in XML; **not** a property on `WsFederationConfiguration` |

The library maps `PassiveRequestorEndpoint` → `TokenEndpoint`. It also reads `SecurityTokenServiceEndpoint` → `ActiveTokenEndpoint`. Entra publishes both. `TokenTypesOffered` is not in the document and the serializer has no `TokenTypesOffered` API — metadata cannot answer A3.

H2 FALSE conditions from DISCOVER: parser did **not** require a document signature to populate config; parser did **not** reject `sts.windows.net` as entityID (it becomes `Issuer`). We did not test an unsigned or SAML-only document in this spike.

### 2. Unauthenticated `/wsfed` (option a)

```
GET https://login.microsoftonline.com/{tid}/wsfed
  ?wa=wsignin1.0
  &wtrealm=api://spike-no-app
  &wreply=https://localhost:5001/signin-wsfed
```

- HTTP **200** (not 302). Body is Entra login HTML (`<title>Sign in to your account</title>`).
- No `Location` header. No `wresult`. No `RequestSecurityTokenResponse`. No TokenType markers.
- Endpoint exists and is the documented shape. This does **not** answer A3.

### 3. Live `wresult` (option b) — stopped

A TokenType in `wresult` requires an authenticated sign-in (interactive user) against a registered app (`Wtrealm` / reply URL). This checkout has no `.capture-identity.json`. `az` is logged into a **different** tenant and must not create apps/users there. Playwright against a personal account was forbidden. `az ad app create` was forbidden.

**Stopped.** No live `wresult` for this team.

### 4. Library: must the emulator pick one TokenType?

`WsFederationOptions` (8.0.19) default `TokenHandlers` (and obsolete `SecurityTokenHandlers`) are:

1. `Saml2SecurityTokenHandler`
2. `SamlSecurityTokenHandler` (SAML 1.1)
3. JWT handler

`CanReadToken` on assertion snippets: SAML 2.0 XML is readable only by the Saml2 handler; SAML 1.1 XML only by the Saml 1.1 handler. They do not overlap.

`WsFederationMessage.GetToken()` extracts the XML **inside** `RequestedSecurityToken` and **skips** the RSTR `<t:TokenType>` element. Handler selection is `CanReadToken` on that inner XML, not the TokenType URI.

**Implication:** the locked stranger will validate **either** SAML 1.1 **or** SAML 2.0 if the inner assertion matches that handler. A first-cut emulator is not forced by the library to emit only one version. Parity with Entra still needs a captured TokenType. Do not ship "either" as the Entra answer.

---

## Strongest external evidence (not this team's capture)

[Scott Brady, *Understanding WS-Federation*](https://www.scottbrady.io/ws-federation/understanding-ws-federation) (article dated 9 Apr 2024; embedded RSTR timestamps **2023-12-03T20:21:08Z**):

- `<t:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0</t:TokenType>`
- Inner assertion: `Version="2.0"` `xmlns="urn:oasis:names:tc:SAML:2.0:assertion"`
- `AppliesTo` / Audience: `spn:993d198b-c95f-4aaa-9f10-04a3fec6d1f1` (not `api://...`)
- Issuer: `https://sts.windows.net/ff191596-4ffd-4c77-93e7-6167a5756569/`
- Name claim: `user@scottbrady91.onmicrosoft.com`

This is a third-party Entra capture for an `spn:` realm. It is **not** this team's capture and **not** an `api://` app-registration `Wtrealm`. SharePoint Learn still documents `/wsfed` → SAML 1.1 for a **different** RP class (not the v0.8.0 witness).

Leading DISCOVER hypothesis remains S3b (SAML 2.0) — still a hypothesis.

---

## What was assumed wrong / still open

- Metadata would not answer A3 — **confirmed** (`TokenTypesOffered` absent).
- Unauthenticated GET would 302 to login — **wrong for this probe**: Entra returned **200** login HTML. Still no token.
- ASP.NET accepting both handlers would tell us what Entra sends — **wrong**; it only tells us the stranger can consume either.

---

## Constraints discovered

- Tenant FederationMetadata is publicly parseable; `/wsfed` is live; TokenType is behind interactive login + a registered RP.
- Emulator metadata for the stranger must include `fed:PassiveRequestorEndpoint` (maps to `TokenEndpoint`). Entra also emits `SecurityTokenServiceEndpoint`; the parser populated `ActiveTokenEndpoint` from it. Signing keys come from the STS RoleDescriptor `KeyDescriptor`s (4 on this tenant).
- `Issuer` in parsed config **is** metadata `entityID`. Token validation will use that issuer. D14 (keep emulator `samlEntityID`) is compatible **if** minted assertions use the same issuer as metadata — the library does not hard-require the hostname `sts.windows.net`.

---

## Follow-up capture (closes A3)

The differential capture tenant was deleted before a `wresult` could be taken. Capture continued against another workforce tenant with a throwaway app registration (`Wtrealm=api://{appId}`, `wreply=http://127.0.0.1:{port}/signin-wsfed`). Interactive sign-in as a user in that tenant; local listener received `POST wa=wsignin1.0`. The app registration was deleted afterwards.

Redacted facts (no tenant id, no NameID value, no signature, no assertion body):

| Field | Value |
|---|---|
| `wa` | `wsignin1.0` |
| RSTR `TokenType` | `http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0` |
| Inner assertion | `Version="2.0"` `xmlns="urn:oasis:names:tc:SAML:2.0:assertion"` |
| Issuer | `https://sts.windows.net/{tid}/` |
| Audience | `api://{appId}` (equals `wtrealm`) |
| NameID Format | `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent` |
| Wrapper | `RequestSecurityTokenResponse` present |

This matches Scott Brady’s Dec 2023 `spn:` capture on TokenType and assertion version. It does **not** match SharePoint Learn’s SAML 1.1 instruction — that RP class is not the v0.8.0 witness. Lock **S3b** (always SAML 2.0 in the RSTR for an app-registration `Wtrealm`).

## Next

A3 is closed. DISCUSS can lock SAML 2.0 for the ASP.NET `WsFederation` witness. Do not also implement SAML 1.1 unless a later consumer (SharePoint) is in scope.
