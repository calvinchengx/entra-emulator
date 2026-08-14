# Solution testing — ws-fed

**Feature ID:** `ws-fed`
**Wave:** DISCOVER / Phase 3 (updated after maintainer interview #1)
**Status:** hypotheses ready; **no prototype was run.** Q1: the maintainer has never pointed a WS-Fed RP at Entra or this emulator.

Gate G3 requires >80% task completion with 5+ users. That bar is **not met**.

---

## Solution concept under test (not a requirement spec)

Candidate concept (SAML analog), with interview #1 locks applied:

1. Extend the **existing** FederationMetadata document with a WS-Fed `RoleDescriptor` (O2 / S2a). Advertise the PassiveRequestorEndpoint for sign-in **and** sign-out; **do not witness SLO** (Q4).
2. Add `GET|POST /{tenant}/wsfed` that reads `wa=wsignin1.0`, `wtrealm`, `wreply`, `wctx` (O1 / S1a).
3. Reuse the OIDC/SAML login UI via signed state `Kind: "wsfed"` (A8).
4. POST back `wa=wsignin1.0` + `wresult` (RSTR wrapping a signed assertion) + echoed `wctx`.
5. Sign with the same tenant RSA / derived X.509 already used for SAML (O5).
6. Witness with unmodified **`Microsoft.AspNetCore.Authentication.WsFederation`** (A5 **locked**, Q3). Chosen witness, not a past run.

Token version inside `wresult` (O3 / A3) is **not chosen**. That is the spike.

SOAP / active WS-Trust is **out** (Q5). Unsolicited logins stay out (D3).

---

## Hypotheses

### H1 — Value (stranger completes sign-in)

We believe implementing S1a+S2a for a developer using `Microsoft.AspNetCore.Authentication.WsFederation` will achieve an unmodified library completing metadata fetch → challenge → account picker → POST `/signin-wsfed` with a verifiable token.

- **TRUE when:** the handler succeeds against the emulator with only host/TLS knobs changed (same bar as `e2e/saml`).
- **FALSE when:** the stranger rejects metadata, refuses the RSTR, or requires a gallery/policy feature this emulator will not grow.

**Status:** untested. Analog: SAML + `node-saml` in v0.6.0. Witness is now named; still never run by this maintainer (Q1).

### H2 — Usability (MetadataAddress keeps working)

We believe growing the existing metadata document (S2a) will achieve WsFederation's `MetadataAddress` locating `PassiveRequestorEndpoint` and a signing cert.

- **TRUE when:** the middleware configured with `.../federationmetadata/2007-06/federationmetadata.xml` finds `/wsfed` and a cert.
- **FALSE when:** the parser requires `fed:SecurityTokenServiceEndpoint`, a document signature, or `sts.windows.net` as entityID.

**Status:** untested. Part of the recommended spike (load **live Entra** metadata with the library first, then an emulator-shaped document).

### H3 — Feasibility (SAML 1.1 vs 2.0 for this stranger)

We believe the assertion version Entra puts in `wresult` when the RP is an app-registration / `Wtrealm=api://...` (the WsFederation Entra config) is knowable from one capture, and this emulator can mint that version with the existing tenant key.

- **TRUE when:** a capture from real Entra for that shape shows one TokenType, and WsFederation verifies it (and later an emulator-minted copy).
- **FALSE when:** Entra's version depends on app flags we cannot see, or the library rejects the captured type.

**Status:** **conflict, not tested.** D5 (SharePoint, not our witness) = SAML 1.1. D7 (app-reg-shaped Entra capture) = SAML 2.0. **Highest remaining protocol risk (A3, score 14).** Leading hypothesis is S3b (SAML 2.0) because it matches D7's RP class — still a hypothesis.

### H4 — Usability (login is not a second UI)

We believe `Kind: "wsfed"` on the existing account picker will achieve sign-in without a new HTML flow.

**Status:** analog-validated for SAML; not run for WS-Fed.

### H5 — Sign-out is advertise-only

We believe advertising `wsignout` on the same PassiveRequestorEndpoint (SAML metadata pattern) **without** a SLO witness will still let the v0.8.0 parity row go green on **sign-in**.

- **TRUE when:** the CI witness is WsFederation sign-in only (Q4).
- **FALSE when:** the library's default test cannot complete sign-in without driving `wsignout1.0`.

**Status:** **locked as advertise-only** (Q4). No longer a v0.8.0 value hypothesis to prove with users.

### H6 — Viability (one green parity row, not a policy engine)

Unchanged. **Status:** conceptually aligned with SAML. Not a substitute for A1 usage validation.

---

## Analog evidence (SAML v0.6.0)

| SAML past behavior | Transfers to WS-Fed? |
|---|---|
| Unmodified stranger found defects Go tests missed | Yes — witness bar unchanged |
| Login reused via signed `Kind` | Likely (H4) |
| SLO advertised, sign-in shipped | **Locked for WS-Fed** (Q4) |
| `saml-acs` redirect type | WS-Fed reply URL type still untested |

---

## Recommended next experiment (smallest testable thing)

**This is the recommended next command: a spike, before DISCUSS.** Not run yet.

1. **Capture (H3 / A3):** configure `Microsoft.AspNetCore.Authentication.WsFederation` against **real Entra** (`MetadataAddress` + `Wtrealm` as in the ASP.NET tutorial). Save FederationMetadata.xml and one `wresult`. Record TokenType / assertion namespace / whether `SecurityTokenServiceEndpoint` is required.
2. **Metadata parse (H2):** point the same library's metadata reader at that live document, then at a fixture that looks like the emulator's SAML-only document **plus** a RoleDescriptor. Pass if it locates `/wsfed` and a cert.
3. **Do not** implement `/wsfed` sign-in, SOAP, unsolicited login, `/common/wsfed`, or SLO witnessing in the spike.

Step 3 (sign-in prototype) waits until A3 is a measured TokenType, then belongs in DELIVER / a later prototype — not in DISCUSS stories as a guess.

---

## Task-completion table (empty — honest)

| Task | Users | Pass |
|---|---|---|
| Fetch metadata; locate PassiveRequestorEndpoint | 0 | — |
| Challenge → `/wsfed?wa=wsignin1.0&wtrealm=...` | 0 | — |
| Complete account picker; receive `wresult` | 0 | — |
| WsFederation verifies signature, audience, lifetime | 0 | — |
| `wsignout1.0` | 0 | **Out of v0.8.0 witness** (Q4) |

**Task completion: 0%.**

---

## Gate G3

| Metric | Target | Result |
|---|---|---|
| Users tested | 5+ per iteration | 0 |
| Task completion | >80% | 0% |
| Key hypotheses proven | >80% | H5 locked by decision, not by a test. H3 conflicted. H1/H2/H4 unrun. |

**G3: FAIL.** Solution testing has not started. The spike above is how it starts. Do not treat "SAML worked" as "WS-Fed will work."
