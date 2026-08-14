# SPIKE Decisions -- ws-fed

**Date:** 14 Aug 2026
**Inputs:** DISCOVER artifacts only (no DISCUSS). Order exception: SPIKE after DISCOVER because A3 would make stories guess.

## Assumption Tested

- What assertion TokenType (SAML 1.1 vs SAML 2.0) does Microsoft Entra put in a WS-Fed `wresult` (RSTR) for an app-registration `Wtrealm` that `Microsoft.AspNetCore.Authentication.WsFederation` will validate?

## Verdict

- **WORKS for A3:** this team captured a live `wresult` (14 Aug 2026 12:05Z) after an interactive sign-in against a workforce tenant. TokenType is `#SAMLV2.0`; inner assertion is SAML 2.0. The original differential capture tenant had been deleted; a substitute workforce tenant was used.
- **WORKS (H2 metadata parse):** `WsFederationMetadataSerializer` / `WsFederationConfigurationRetriever` read FederationMetadata. `PassiveRequestorEndpoint` → `TokenEndpoint` = `.../wsfed`. `TokenTypesOffered` absent (does not answer A3).

## Design Implications

- Lock **SAML 2.0** in the RSTR for an app-registration `Wtrealm` (`api://…`). That is S3b. SharePoint’s SAML 1.1 path stays out of v0.8.0.
- The URI `…saml-token-profile-1.1#SAMLV2.0` is SAML 2.0 (profile 1.1), not SAML 1.1. Mint `Version="2.0"` assertions; do not emit SAML 1.1 XML for this witness.
- Audience must equal `wtrealm`. Issuer in the assertion must equal metadata `entityID` (Entra uses `https://sts.windows.net/{tid}/`; emulator may keep its login origin per D14 if both match).
- Metadata for the stranger must grow the existing FederationMetadata URL with a WS-Fed STS `RoleDescriptor` (`PassiveRequestorEndpoint` + signing keys; Entra also emits `SecurityTokenServiceEndpoint`).
- Default `TokenHandlers` accept either version; parity still means minting **2.0**, not “either.”

## Constraints Discovered

- Unauthenticated `GET /{tid}/wsfed?wa=wsignin1.0&wtrealm=...` returns HTTP 200 login HTML, not a `wresult`.
- A `wresult` needs interactive login plus a registered RP (`identifierUris` + web `redirectUris`).
- `TokenTypesOffered` is absent from Entra metadata and from `WsFederationConfiguration`.
- SOAP/active, unsolicited login, `/common/wsfed`, and SLO witnessing stay out of v0.8.0 per DISCOVER (unchanged).
- Raw `wresult` is a live credential — record TokenType/version/namespaces only.

## Next wave

- DISCUSS is unblocked on A3. Handoff artifact: `docs/feature/ws-fed/spike/findings.md`
