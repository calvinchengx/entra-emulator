# e2e/wsfed — unmodified WsFederation stranger (KPI-1)

**Feature:** `ws-fed`  
**Status:** wired — `python3 e2e/run.py wsfed`  
**Witness:** unmodified `Microsoft.AspNetCore.Authentication.WsFederation` 8.0.19
with `Microsoft.IdentityModel.Protocols.WsFederation` 8.22.0 (spike-pinned;
SAML handlers then read issuer and signing keys from FederationMetadata).

## Why this directory exists

KPI-1 (north star): a developer who already has an ASP.NET WS-Fed relying party
can point `MetadataAddress` and `Wtrealm` at the emulator and complete one
SP-initiated sign-in with **only host and TLS knobs** changed versus Entra.

ADR-005: this suite is a **sibling of `e2e/saml`**, not an extension of
`e2e/dotnet` (that job is MSAL.NET + Wilson **OIDC**).

The Gherkin scenario

> Priya's unmodified WsFederation middleware completes sign-in

is tagged `@kpi @walking_skeleton`. `TestUnmodifiedWsFederationCompletesSignIn`
skips with a pointer here; the green bar is this suite.

## What the suite does

A .NET 8 host (`AddAuthentication().AddWsFederation`) that:

1. Sets `MetadataAddress` to the existing FederationMetadata URL  
   `{EMU_ORIGIN}/{EMU_TENANT}/federationmetadata/2007-06/federationmetadata.xml`
2. Sets `Wtrealm` to `api://tasks-api`
3. Registers a loopback `wsfed-reply` so the TestHost can receive the `wresult` POST
   (Priya's Entra reply is `https://rp.example.test/signin-wsfed`; locally the
   host knob is `http://127.0.0.1:{port}/signin-wsfed`)
4. Drives the emulator account picker the way `e2e/saml/suite.mjs` drives SAML
5. Lets unmodified `Microsoft.AspNetCore.Authentication.WsFederation` validate
   `wresult` (signature, audience, issuer, lifetime)
6. Does **not** fork the library, require a gallery, Graph, MFA, CA, or B2C
7. Does **not** log raw `wresult` in CI artifacts

Host and TLS knobs only: `EMU_ORIGIN` / `EMU_TENANT` / `EMU_CERT` (trust the
emulator leaf, same as `e2e/dotnet`), loopback listen address, and
`CorrelationCookie.SecurePolicy = SameAsRequest` so the cookie is stored on
HTTP loopback. Signature validation stays on.

Registered in `e2e/run.py` as `wsfed` and on CI `sdk-e2e` (that job already
installs .NET 8).

## Out of this stranger

SOAP, `/common/wsfed`, SAML 1.1, witnessed `wsignout1.0`, IdP-initiated,
encryption, MFA/CA, portal/Graph as sign-in.
