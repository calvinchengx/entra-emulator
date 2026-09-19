# OIDF conformance

> **Status: rungs 0 and 1 have shipped.** entra-emulator passes the OpenID
> Foundation's **Config OP** profile (34 conditions, no warnings) and runs its
> **Basic OP** profile, all 35 modules: 20 PASSED, 4 REVIEW, 4 SKIPPED, 7
> WARNING, with every non-pass declared and justified in
> `e2e/conformance/config/expected.json`. Run them with
> `make conformance` and `make conformance PLAN=basic`.

## Why this is different from every other check in the repo

[19-golden-reference-parity.md](19-golden-reference-parity.md) explains that the
emulator is graded against three golden references we captured. That is the
right discipline, and it has one structural limit: on the OIDC surface, the
oracle is **our reading of Entra's discovery document**. `golden_parity_test.go`
asserts the emulator against `e2e/golden/oidc-discovery.golden.json`, and
`check_golden_drift.py` asserts that file against the live document. Both ends
of that chain are ours.

The OIDF conformance suite is a third party asserting the emulator against the
**specification**. It is not a stronger form of the `diff:` witness tier; it is a
different axis. `diff:` answers "would Entra have said this?". `oidf:` answers
"does this conform to OpenID Connect?". A surface can pass one and fail the
other, and the two together are worth more than either twice.

This is also the same suite the real thing was measured by. Azure Active
Directory V2 is listed on the OIDF's
[certified providers](https://openid.net/certification/certified-openid-providers-profiles/)
for Basic OP, Implicit OP, Config OP and FormPost OP, all dated 15 January 2019.
Note what is absent: **Hybrid OP and Dynamic OP**, the latter consistent with
Entra advertising no `registration_endpoint`. Certification there is
self-certification against a published suite, not an audit, which is precisely
why running the suite ourselves is worth something.

## How the harness is shaped

`e2e/conformance/` is upstream's own
[`docker-compose-localtest.yml`](https://gitlab.com/openid/conformance-suite/-/blob/master/docker-compose-localtest.yml)
topology with entra-emulator in the place of their sample provider. The OP under
test is a **sibling compose service**, so the suite reaches it over the compose
network:

```
run.py
  │ 1. docker compose up entra-emulator mongodb
  │ 2. docker compose cp  entra-emulator:/app/data/tls/cert.pem
  │ 3. docker compose build conformance   (keytool imports that cert)
  │ 4. POST /api/plan, POST /api/runner, poll /api/info, GET /api/log
  ▼
conformance ──── https://entra-emulator:8443/{tenant}/v2.0/.well-known/openid-configuration
   (JVM)                         (the OP under test)
```

Four things that are not obvious and cost real time to rediscover:

- **No tunnel and no public hostname.** An earlier sketch of this work assumed
  the hosted suite at `conformance.openid.net` had to reach a localhost
  emulator. It does not: the suite is fully self-hostable.
- **No Maven build.** The OIDF publishes multi-arch images at
  `registry.gitlab.com/openid/conformance-suite`, pullable anonymously. The
  harness pins the **index** digest, not a per-architecture manifest, so it
  works on both amd64 and arm64 runners.
- **The suite rejects plain HTTP on its own API** with a 500 that talks about
  reverse proxies. Upstream fixes that with an nginx in front; the harness sends
  `X-Forwarded-Proto: https` instead, which Tomcat's already-configured
  `RemoteIpValve` honours from the docker gateway. One container fewer.
- **The published image's entrypoint requires non-empty Google and GitLab OAuth
  client ids**, or Spring Security kills the container during bean creation with
  an error that mentions neither TLS nor conformance. They are set to `unused`.

## What Config OP actually checks

One module, `oidcc-discovery-endpoint-verification`, running 34 conditions:
issuer consistency with the retrieval URL, every advertised endpoint on https,
JWKS fetchable and valid, `scopes_supported` containing `openid`, response types,
subject types, signing algorithms, locale syntax, and the metadata document
against the RFC 8414 schema. No browser, no login, no client registration.

It found one real thing on the first run. `CheckForUnexpectedParametersInServerMetadata`
flagged the six Entra-specific fields the emulator advertises on purpose:
`cloud_graph_host_name`, `cloud_instance_name`, `http_logout_supported`,
`msgraph_host`, `rbac_url`, `tenant_region_scope`. Real Entra emits all six, so
removing them would break parity to satisfy the spec. They are declared in
`config/oidcc-config-op.json` under `allow_unexpected_metadata_fields`, which is
the mechanism the suite offers for exactly this. The value of declaring them is
that **a seventh field would warn**.

## What Basic OP actually checks

35 modules, each driving a real login through a scripted browser: the whole
authorization-code flow, userinfo three ways, scope handling, `prompt`,
`max_age`, `login_hint`, `id_token_hint`, locales, `acr_values`, code reuse,
redirect-URI registration, PKCE, refresh, request objects, and both
`client_secret_basic` and `client_secret_post`.

The harness registers **three** clients per run through the emulator's admin
API rather than committing client ids: `client`, `client2` (several modules
check that one client cannot spend another's code), and `client_secret_post`,
which `OIDCCServerTestClientSecretPost` copies over `client` because most real
servers tie a client to one authentication method. Omitting the third fails that
module complaining about a missing `client`, which reads as the wrong problem
entirely.

Three modules stop and ask a human for a screenshot, and cannot reach a terminal
state without one. The harness fills the placeholder so the plan can finish, and
those modules then end as **REVIEW, which is not a pass** — nobody looked at a
screenshot, and nothing here claims otherwise.

### What it found

Everything that is not a pass is declared in `config/expected.json` with a
reason and a category. The categories are the interesting part, because they
separate "the emulator is wrong" from "the emulator is right and the spec
disagrees":

| category | modules | what it means |
|---|---|---|
| `parity` | 7 | The emulator behaves like Entra rather than like the bare spec. |
| `not-in-entra` | 4 | Neither supports the feature, so the suite skips the module. |
| `needs-a-human` | 4 | Blocked on a screenshot; every condition passes. |

**The `parity` group is the whole argument for running this.** Real Entra puts
`name`, `preferred_username` and `ver` in every v2.0 id_token whether or not
they were requested, and `docs/parity.md` grades that shape 🟢. The suite calls
each one a warning: `EnsureIdTokenDoesNotContainName`,
`EnsureIdTokenDoesNotContainNonRequestedClaims`,
`EnsureIdTokenDoesNotContainEmailForScopeEmail`. Both are correct. Satisfying
the suite here would mean diverging from the product being emulated, which is
why `oidf:` is a different axis from `diff:` and not a stronger one.
`acr_values` is the same shape: the spec says an OP SHOULD return `acr`, and
Entra v2.0 does not.

### The four defects, and what became of them

The first run of this plan reported four defects. Two were real and are fixed;
one was real and is fixed as far as the architecture allows; one was not a
defect at all, and the original description of it was wrong.

**Fixed: the refusal of an inline `request` parameter was delivered as an HTML
error page** instead of `error=request_not_supported` on the `redirect_uri`.
Refusing the parameter is correct and matches Entra; delivering the refusal as a
page is not, once `client_id` and `redirect_uri` are both usable (OIDC Core
3.1.2.6, RFC 6749 4.1.2.1). An unusable one still gets a page, which is the
open-redirect guard, and a test now pins both halves. The module used to hang
waiting for a redirect that never came; it now reports the behaviour as
"permitted" in the suite's own words.

**Fixed: userinfo did not accept the access token in the POST body** (OIDC Core
5.3.1, RFC 6750 2.2). It does now, validated identically to the header form, and
presenting both at once is an `invalid_request` rather than a silent preference
for one. Graph itself still takes the header alone, as real Entra's Graph does.
`oidcc-userinfo-post-body` passes.

**Fixed as far as it can be: a replayed authorization code did not revoke what
it had produced.** RFC 6749 4.1.2 asks for revocation "when possible", and the
refresh chain is the possible part: it is revoked now, inherited across
rotations, so a replay costs continued access rather than one exchange. The
access token is not revoked, here or in Entra, because it is a stateless JWT a
resource server verifies offline against JWKS. Microsoft's own documentation is
explicit that before continuous access evaluation "clients would replay the
access token from its cache as long as it wasn't expired", and that CAE exists
so "a resource provider can reject a token when it isn't expired" — a separate
subscription mechanism, first-party services only, up to 15 minutes of latency.
Revoking centrally would need stateful validation production does not have.
`oidcc-codereuse-30seconds` therefore stays a declared warning, now with that
reasoning rather than "unmeasured".

**Not a defect: "userinfo does not return the full `profile` claim set".** That
description was wrong; the endpoint already returns `given_name` and
`family_name`. What the condition actually wants is every claim OIDC associates
with the scope, including `middle_name`, `nickname`, `gender`, `birthdate`,
`zoneinfo`, `locale`, `updated_at` and `email_verified`. Microsoft documents
that its UserInfo endpoint returns `sub`, `name`, `family_name`, `given_name`,
`picture` and `email`, that "the claims shown in the response are all those that
the UserInfo endpoint can return", and that "you can't add to or customize"
them. Synthesising a gender or a birthdate would invent data Entra cannot
return. Reclassified as `parity`.

Two smaller differences on that same surface are recorded rather than changed,
because the evidence for them is one documentation sample and this repo's bar
for a projection change is a live diff (`e2e/differential`), which has not been
captured for userinfo: Entra returns `picture` and the emulator does not, and
the emulator returns `oid` and `tid`, which that reference does not list.

`max_age` and `auth_time` were a fifth defect when this harness first ran, and
both `oidcc-max-age-1` and `oidcc-max-age-10000` failed on
`CheckIdTokenAuthTimeClaimPresentDueToMaxAge`. They were implemented in #170
while this was in flight, and `oidcc-max-age-10000` now passes outright. One
detail from the suite worth recording, because it validates the design chosen
there: the first authorization in `oidcc-max-age-1` carries no `auth_time` (it
did not request `max_age`), and the suite tolerates that under
`CheckSecondIdTokenAuthTimeIsLaterIfPresent`. Emitting `auth_time`
unconditionally would not have been rewarded.

## The gate is not vacuous

The most likely way a harness like this dies is going green while testing
nothing, so two guards are built in rather than bolted on:

- `EXPECTED_MODULES` in `run.py` is compared to the plan the suite actually
  returns, by identity and not just count. A plan that quietly stopped shipping
  a module would otherwise run fewer tests and still exit 0.
- Only `PASSED` is green. Anything else fails unless it is declared with a
  reason in `config/expected.json`, so a new `WARNING` breaks the run instead of
  accumulating quietly.

A third guard arrived with rung 1. A module can sit in `WAITING` forever when
the OP answers the browser in a way the module has no task for, and one such
module must not swallow the other 34, so the harness records it as `STALLED`
after 90 seconds and moves on. `STALLED` is not `PASSED`, so it still fails the
run unless declared.

All three were exercised. Pointing `PUBLIC_ORIGIN` at `http://` while still
serving TLS produces 7 condition failures and a red run; removing the
`allow_unexpected_metadata_fields` declaration produces a `WARNING` and a red
run; the stall path is how the inline-`request` defect above presented before
it was fixed, and no module stalls today.

The witness checker has the same treatment. `oidf:<module>` must name a module
the runner runs **and** one that `expected.json` does not declare as a non-pass,
so a row cannot read as conformance-tested when the conformance result was "we
decided this one is allowed to be red". A witness failing either test is
reported as dangling.

## The remaining rungs

| rung | plan | modules | state |
|---|---|---|---|
| 0 | `oidcc-config-certification-test-plan` | 1 | **shipped** |
| 1 | `oidcc-basic-certification-test-plan` | 35 | **shipped** |
| 2 | `oidcc-formpost-basic-certification-test-plan` | 35 | cheap now that rung 1 exists |
| 3 | `oidcc-implicit-certification-test-plan` | — | blocked, by choice |

An earlier draft of this page said Basic OP had 38 modules, counted from the
plan's Java source. The plan the suite actually builds for our variant has 35.
Both numbers now come from `--capture-modules`, which reads the plan back from
the suite, rather than from anyone's reading of the source.

**Rung 3 is blocked deliberately.** The implicit plan needs the `id_token token`
response type. The emulator does not implement it, and
`internal/server/implicit_hybrid_test.go` actively asserts it is never
advertised. Real Entra does support it, so this is a genuine, already-declared
divergence rather than something the suite would newly discover.

## Boundaries

Running the suite is not certification. Certification requires OIDF membership,
a fee, and submission of logs for a deployed product, and none of that applies
to an emulator. What this buys is the evidence, not the badge.

One live divergence is worth naming because it sits on this exact surface and
the suite does **not** object to it: the emulator advertises
`request_uri_parameter_supported: true` while real Entra reports false. That is
spec-legal in both directions, so Config OP passes either way. It is recorded in
`e2e/golden/oidc-discovery.golden.json` under `emulator_divergences` and remains
an open product decision, not a bug this work resolves.
