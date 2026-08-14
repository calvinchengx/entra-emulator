# ADR-003: Reuse the existing account picker via signed state Kind

## Status

Accepted — 14 Aug 2026 (feature `ws-fed`)

## Context

DISCUSS D3 walking skeleton and US-03 / KPI-4: Priya must see the same Pick an account (or existing password) chrome as OIDC and SAML — **zero new login UIs**. SAML already reaches that UI by putting `Kind: "saml"` in HMAC-signed form state and posting back to `/{tid}/saml2`.

Quality drivers: **maintainability** (one login bug surface) and **habit / product constraint** (KPI-4; DISCUSS D3).

## Decision

WS-Fed unauthenticated challenges render the **existing** account picker / password form. Signed state carries a new Kind (e.g. `"wsfed"`) and the challenge parameters (`wtrealm`, registered `wreply`, optional `wctx`, tenant). The form posts back to `/{tid}/wsfed`, not `/{tid}/saml2`. After a valid Kind completion, the STS auto-POSTs `wresult` to the registered reply. No WS-Fed-specific login page.

Token delivery happens only after a challenge this STS issued (that signed Kind). That is the unsolicited-login correlation for US-08.

## Alternatives considered

1. **Second WS-Fed login UI** — Protocol-specific realm form. **Rejected:** US-03 forbids a second product; two login paths drift (SAML comment in the existing picker reuse).
2. **Skip the picker when a session cookie exists only** — Always SSO, never show HTML. **Rejected:** unauthenticated GET must be login HTML (spike + US-02), not a premature `wresult`. Existing-session SSO after a valid challenge may follow the SAML analog; it is not a second UI.
3. **Return 302 to an external IdP login** — **Rejected:** this emulator *is* the STS; Entra-shaped unauthenticated `/wsfed` is HTTP 200 HTML on this host.

## Consequences

### Positive

- 0 new login pages; password-required mode stays the existing form; challenge parameters survive in signed state; US-08 has a challenge-correlation mechanism without a new session store.

### Negative

- Identity handlers gain another Kind branch (same pattern as `saml` / `authorize` / `device`). Crafter owns the state fields; architecture forbids a second chrome.
