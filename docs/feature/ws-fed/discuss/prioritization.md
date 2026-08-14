# Prioritization: ws-fed

Folded narrative lives in `story-map.md` (Priority Rationale). This file is the MoSCoW / score table for DESIGN and DISTILL.

**JTBD:** skipped; traces to DISCOVER job: point WsFederation at the emulator.

## Release Priority

| Priority | Release | Target Outcome | KPI | Rationale |
|---|---|---|---|---|
| 1 | Walking skeleton (v0.8.0 sign-in) | Priya's unmodified WsFederation completes one SP-initiated sign-in | North star: stranger sign-in pass | Validates H1; thinnest E2E across all backbone activities |
| 2 | Release 1 refuse-unsafe | Misconfigured realm/reply and unsolicited POSTs do not create a session or open redirect | Guardrail: 0 bounces to unowned `wreply`; 0 unsolicited sessions | O4/O6; Must Have in v0.8.0; separately demonstrable |
| 3 | Release 2 siblings | Explicit non-goals remain out | Guardrail: no SOAP, no SAML 1.1, no `wsignout1.0` witness | Prevents scope creep; not scheduled |

## Backlog

| Story | Release | MoSCoW | Priority | Outcome link | Dependencies |
|---|---|---|---|---|---|
| US-01 FederationMetadata advertises WS-Fed | WS | Must | P1 | KPI-1 metadata locate | None (grows existing document) |
| US-02 Challenge reaches `/wsfed` | WS | Must | P1 | KPI-1 / KPI-2 challenge | US-01 (TokenEndpoint) |
| US-03 Same sign-in as OIDC and SAML | WS | Must | P1 | KPI-3 habit | US-02 |
| US-04 SAML 2.0 `wresult` at registered reply | WS | Must | P1 | KPI-2 token shape | US-03 |
| US-05 Unmodified WsFederation completes sign-in | WS | Must | P1 | North star | US-01–US-04 |
| US-06 Unknown `wtrealm` refused | R1 | Must | P2 | Guardrail unsafe | US-02 |
| US-07 Missing or unregistered `wreply` refused | R1 | Must | P2 | Guardrail unsafe | US-02 |
| US-08 Unsolicited `wresult` refused | R1 | Must | P2 | Guardrail unsafe | US-02 |

## Won't (v0.8.0)

SOAP / active WS-Trust · `/common/wsfed` · IdP-initiated · SharePoint / SAML 1.1 · portal gallery · Graph-as-sign-in · MFA/CA/B2C · token encryption · witnessing `wsignout1.0`.
