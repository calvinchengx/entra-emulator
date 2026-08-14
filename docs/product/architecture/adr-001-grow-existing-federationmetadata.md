# ADR-001: Grow existing FederationMetadata (no second URL)

## Status

Accepted — 14 Aug 2026 (feature `ws-fed`)

## Context

`Microsoft.AspNetCore.Authentication.WsFederation` locates the STS from `MetadataAddress`. Entra publishes WS-Fed at the same document SAML already uses: `/{tid}/federationmetadata/2007-06/federationmetadata.xml`. Spike H2: the library maps `PassiveRequestorEndpoint` → `TokenEndpoint` and also reads `SecurityTokenServiceEndpoint`. The emulator document today is `IDPSSODescriptor` only. Quality drivers: interoperability (stranger parse) and maintainability (one metadata URL).

## Decision

Grow the **existing** FederationMetadata document with a WS-Fed `RoleDescriptor` (`xsi:type="fed:SecurityTokenServiceType"`). Publish **both** `PassiveRequestorEndpoint` and `SecurityTokenServiceEndpoint` as `{login_origin}/{tid}/wsfed`. Advertise sign-out on that same PassiveRequestorEndpoint; do **not** witness `wsignout1.0`. Use the **same** signing certificate as `IDPSSODescriptor`. Keep entityID as emulator login origin + `/{tid}/`. Keep the metadata audit flow name `saml-metadata`. Do not add a second metadata path.

## Alternatives considered

1. **New URL** (e.g. `/{tid}/wsfed/metadata`) — Matches a “WS-Fed-only document” instinct. **Rejected:** Priya’s Entra-shaped `MetadataAddress` would miss it (US-01 error/boundary; DISCUSS D5 / H2).
2. **SAML-only document + hard-code TokenEndpoint in the RP** — Avoids XML change. **Rejected:** the locked stranger discovers the endpoint from metadata; host/TLS-only config is the interop bar.
3. **PassiveRequestorEndpoint only** (omit SecurityTokenServiceEndpoint) — Smaller XML. **Rejected:** Entra emits both; H2 parser populated `ActiveTokenEndpoint` from the second; DISCUSS requires both.

## Consequences

### Positive

- One `MetadataAddress`; SAML apps keep `IDPSSODescriptor`; stranger parse matches H2; no `sts.windows.net` hostname requirement if assertion Issuer equals entityID.

### Negative

- Metadata builder gains WS-Fed XML. **DISTILL gate:** existing `e2e/saml` and OIDC e2e still pass after the RoleDescriptor is added (US-05 guardrail / US-01 “SAML still present”). That is the same existing suites, not a new witness. Document signature is not required for the library to parse (spike); v0.8.0 does not add a requirement to sign the metadata document itself.
