# ADR-005: `e2e/wsfed` sibling (do not extend `e2e/dotnet`)

## Status

Accepted — 14 Aug 2026 (feature `ws-fed`)

## Context

KPI-1 / US-05: v0.8.0 is claimed only when unmodified `Microsoft.AspNetCore.Authentication.WsFederation` completes metadata fetch plus sign-in. SAML’s bar is `e2e/saml` (Node `@node-saml/node-saml`), not in-process Go. `e2e/dotnet` is MSAL.NET + Wilson **OIDC** (`docs` / README: client-credentials + JWT validation). Quality drivers: interoperability and the SAML v0.6.0 lesson (self-tests agreeing with the signer are not a stranger).

## Decision

Add a new **`e2e/wsfed`** job, sibling of `e2e/saml`. The witness is unmodified `Microsoft.AspNetCore.Authentication.WsFederation` (.NET). Do **not** extend `e2e/dotnet`. Do **not** ship in-process-Go-only as the stranger. Host and TLS knobs only versus Entra. DEVOPS may register the suite next to `saml` in the existing `sdk-e2e` job (already installs .NET 8); existing CI is enough for DISTILL to start.

## Alternatives considered

1. **Extend `e2e/dotnet`** — One .NET directory. **Rejected:** that suite is OIDC/MSAL; mixing WS-Fed would hide protocol failures inside an unrelated client-credentials job and violate the locked witness split.
2. **In-process Go tests only** — Fast, no .NET SDK. **Rejected:** they would verify with the same XML stack that minted the assertion (SAML lesson). KPI-1 is the unmodified library.
3. **Node port of a WS-Fed client** — Sibling of `e2e/saml` in Node. **Rejected:** the locked stranger is the ASP.NET library Priya already ships, not a Node substitute.

## Consequences

### Positive

- Same evidence class as SAML; CI matrix stays “one stranger per protocol”; `e2e/dotnet` remains an OIDC guardrail.

### Negative

- Another suite to wire in `e2e/run.py` / CI (DEVOPS). Requires .NET SDK in that job (already present for `e2e/dotnet`).
