# Product vision — entra-emulator

**SSOT bootstrap:** 14 Aug 2026. First nWave product SSOT in this repo. This file is thin on purpose.

## What this is

A **local Entra emulator** for developers. It speaks the protocol surfaces, crypto, and directory shape that relying parties already use against Microsoft Entra ID — OIDC, SAML, Graph-adjacent bits already shipped, and WS-Federation as the remaining browser-federation sibling.

It is **not an identity provider product**. It is not a portal, not a policy engine (MFA / Conditional Access / B2C), and not a cloud tenant. Success is an unmodified stranger completing the same wire conversation it completes against Entra, with only host and TLS knobs changed.

## Job this SSOT exists to serve

Point an existing WS-Fed relying party at a local STS. Canonical job: `docs/product/jobs.yaml`. Canonical journeys: `docs/product/journeys/ws-fed-sign-in.yaml` (v0.8.0 sign-in) and `docs/product/journeys/ws-fed-sign-out.yaml` (witness advertised `wsignout1.0`).

## Boundary (unchanged by WS-Fed except sign-out witness)

| In | Out |
|---|---|
| Protocol + crypto + directory | Admin gallery UX, Graph-as-the-sign-in, MFA/CA/B2C |
| Tenant-specific FederationMetadata and `/{tid}/wsfed` | SOAP / active WS-Trust, `/common/wsfed` in v0.8.0 |
| Advertise sign-out URL and witness `wsignout1.0` on `/{tid}/wsfed` | Multi-RP `wsignoutcleanup1.0` fan-out, SOAP SLO |
| SAML 2.0 inside WS-Fed `wresult` for app-registration `Wtrealm` | SharePoint / SAML 1.1, token encryption |
