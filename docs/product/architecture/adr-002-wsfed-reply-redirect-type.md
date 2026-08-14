# ADR-002: Redirect type `wsfed-reply` (do not reuse `saml-acs` or OIDC URIs)

## Status

Accepted — 14 Aug 2026 (feature `ws-fed`)

## Context

DISCUSS D6: `wreply` must be a registered reply URL for the app identified by `wtrealm`; do not trust the query string. Storage shape was left to DESIGN. Existing table `app_redirect_uris` already has a `type` column (`web` / `spa` / `native` / `saml-acs`). SAML filters on `saml-acs` and does **not** use `HasRedirectURI`, which matches URI and **ignores type**. Quality driver: security of the protocol surface (open-redirect token POST).

## Decision

Add allowed type **`wsfed-reply`** on existing `app_redirect_uris`. Lookup the app with existing Application ID URI resolution (`wtrealm`). Accept `wreply` only if that app has an **exact** URI of type `wsfed-reply`.

Do **not** reuse `saml-acs` (a SAML ACS must not accept a WS-Fed POST). Do **not** reuse `web` / `spa` / `native` (OIDC callbacks must not become WS-Fed reply targets). Do **not** use `HasRedirectURI` as the WS-Fed check.

Admin/Graph app registration already passes `type` through; no new table. Existing `UNIQUE(app_id, uri)` means one URI cannot be two types on the same app — acceptable (`/acs` vs `/signin-wsfed`). Seed and operator docs are DELIVER.

## Alternatives considered

1. **Reuse `saml-acs`** — One “assertion consumer” type for both XML protocols. **Rejected:** a SAML ACS and a WS-Fed reply are different POST contracts (`SAMLResponse` vs `wresult`). Sharing the type would let a SAML-only ACS receive a WS-Fed token.
2. **Reuse `web` redirect URIs** — Tasks API might already list `/signin-wsfed` as a web callback. **Rejected:** OIDC authorize redirects must not become WS-Fed `wreply` targets; type-blind `HasRedirectURI` is exactly that hole.
3. **New table `app_wsfed_replies`** — Explicit protocol table. **Rejected:** duplicates “where may this app receive credentials”; SAML already answered that with a type on `app_redirect_uris`. Unjustified schema fork for a solo maintainer.

## Consequences

### Positive

- Same pattern as SAML ACS; cross-protocol POST mix-up is refused (US-07); no new datastore.

### Negative

- Operators must register `wsfed-reply` explicitly (not inferred from `saml-acs` or OIDC). An app that wants the same URL for SAML and WS-Fed cannot under current uniqueness — v0.8.0 witness uses `https://rp.example.test/signin-wsfed`, not the SAML ACS.
