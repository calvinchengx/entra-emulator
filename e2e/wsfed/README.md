# e2e/wsfed — unmodified WsFederation stranger (KPI-1)

**Feature:** `ws-fed`  
**Status:** wired — `python3 e2e/run.py wsfed`  
**Witness:** unmodified `Microsoft.AspNetCore.Authentication.WsFederation` 8.0.19
with `Microsoft.IdentityModel.Protocols.WsFederation` 8.22.0 (spike-pinned;
SAML handlers then read issuer and signing keys from FederationMetadata).

## Why this directory exists

KPI-1 (north star): a developer who already has an ASP.NET WS-Fed relying party
can point `MetadataAddress` and `Wtrealm` at the emulator and complete one
SP-initiated sign-in **and SignOut** with **only host and TLS knobs** changed
versus Entra.

ADR-005: this suite is a **sibling of `e2e/saml`**, not an extension of
`e2e/dotnet` (that job is MSAL.NET + Wilson **OIDC**).

The Gherkin scenarios

> Priya's unmodified WsFederation middleware completes sign-in
> Priya's unmodified WsFederation middleware completes SignOut

are tagged `@kpi @walking_skeleton`. `TestUnmodifiedWsFederationCompletesSignIn`
and `TestUnmodifiedWsFederationCompletesSignOut` skip with a pointer here; the
green bar is this suite (`python3 e2e/run.py wsfed`).

## What the suite does

A .NET 8 host (`AddAuthentication().AddWsFederation`) that:

1. Sets `MetadataAddress` to the existing FederationMetadata URL  
   `{EMU_ORIGIN}/{EMU_TENANT}/federationmetadata/2007-06/federationmetadata.xml`
2. Sets `Wtrealm` to `api://tasks-api`
3. Registers **two** loopback `wsfed-reply` URIs: the sign-in callback
   (`CallbackPath` / `Wreply`) **and** a distinct SignOut return
   (`SignOutWreply`, not `CallbackPath`). Priya's Entra replies are
   `https://rp.example.test/signin-wsfed` and
   `https://rp.example.test/wsfed-signed-out`; locally the host knob is
   `http://127.0.0.1:{port}/…`
4. Drives the emulator account picker the way `e2e/saml/suite.mjs` drives SAML
5. Lets unmodified `Microsoft.AspNetCore.Authentication.WsFederation` validate
   `wresult` (signature, audience, issuer, lifetime)
6. After sign-in, drives unmodified `SignOut` (cookie scheme then WsFederation).
   Follows `wa=wsignout1.0` with emulator cookies; GET `/secure` is then
   unauthenticated and the next challenge is Pick an account
7. Does **not** fork the library, require a gallery, Graph, MFA, CA, or B2C
8. Does **not** log raw `wresult` in CI artifacts

Host and TLS knobs only: `EMU_ORIGIN` / `EMU_TENANT` / `EMU_CERT` (trust the
emulator leaf, same as `e2e/dotnet`), loopback listen address, and
`CorrelationCookie.SecurePolicy = SameAsRequest` so the cookie is stored on
HTTP loopback. Signature validation stays on.

Registered in `e2e/run.py` as `wsfed` and on CI `sdk-e2e` (that job already
installs .NET 8).

## Out of this stranger

SOAP, `/common/wsfed`, SAML 1.1, IdP-initiated, encryption, MFA/CA,
portal/Graph as sign-in, multi-RP `wsignoutcleanup1.0` fan-out. Witnessed
`wsignout1.0` is **in**.
