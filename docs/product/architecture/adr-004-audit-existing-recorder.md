# ADR-004: Audit WS-Fed through the existing recorder (never log `wresult`)

## Status

Accepted — 14 Aug 2026 (feature `ws-fed`)

## Context

Auditability is the **first** quality attribute: every WS-Fed exchange on `/{tid}/wsfed` must appear in the existing flow recorder before stranger CI is treated as the only success signal. KPI-1 (unmodified WsFederation) remains required. SAML already wraps routes with `audited("saml-sso")` / `audited("saml-metadata")` even though `Event.Flow` comments still say `"token" | "authorize"`. Graph `auditLogs/signIns` and Admin `GET /admin/api/audit` project that same ring buffer. Raw `wresult` is a live credential (spike: not committed).

## Decision

Wrap `GET|POST /{tid}/wsfed` with the existing `audited` wrapper using flow name **`wsfed`**. Do not rename metadata’s `saml-metadata` flow. Map `wtrealm` into `Event.ClientID` (Application ID URI; documented — the field name is OIDC-era). After picker success, record the user (`noteAuditSubject`). Unauthenticated HTTP 200 login HTML is still a recorded **challenge** event (user empty). US-06/07/08 failures must carry a **concrete `Reason`**. **Never persist raw `wresult`** (no token body on the event; do not capture success HTML that contains the assertion).

Graph/Admin must list these events without a second store. Graph projection scope (existing Graph adapter, not a new component):

- When `Flow` is `wsfed` and `ClientID` is an Application ID URI, resolve the app by that URI so `appId` / `appDisplayName` are not blank for `api://tasks-api`.
- Treat `Flow == "wsfed"` browser exchanges as interactive (`isInteractive` true), same meaning as authorize (human at the keyboard).
- DISTILL asserts those fields on Graph `auditLogs/signIns` plus Admin `GET /admin/api/audit`. No new Graph route. Crafter owns how the existing projection maps URI vs GUID.

## Alternatives considered

1. **Stranger CI only (no recorder)** — Interop KPI as the sole signal. **Rejected:** user ranked auditability first; DISTILL must assert challenge / success / refuse in admin and Graph logs.
2. **New audit table or file for WS-Fed** — Dedicated protocol log. **Rejected:** Graph already projects one recorder; a second store splits the operator view and contradicts “no new datastore.”
3. **Log full `wresult` for debugging** — Easier interop diagnosis. **Rejected:** live credential; DISCUSS/SPIKE forbid dumping it; KPI measurement uses TokenType/version/audience, not the assertion body.

## Consequences

### Positive

- One operator surface; Graph SIEM-shaped consumers see WS-Fed; refuse-unsafe is evidence, not only a 4xx page.

### Negative

- Existing `audited` helper reads `client_id` and JSON error bodies; WS-Fed uses `wtrealm` and HTML error pages — crafter must still meet the **observable** ClientID/Reason contracts. Graph today treats only `Flow == "authorize"` as interactive and looks up apps by GUID — those projections need to understand `wsfed` / ID URI (existing Graph adapter, not a new component; see Decision projection scope).
