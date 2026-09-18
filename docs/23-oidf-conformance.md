# OIDF conformance

> **Status: rung 0 has shipped.** entra-emulator's discovery document passes
> the OpenID Foundation's **Config OP certification profile**, judged by the
> OIDF's own conformance suite: 34 conditions SUCCESS, 0 warnings, 0 failures.
> Run it with `make conformance`. The remaining rungs are scoped below and not
> started.

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

## The gate is not vacuous

The most likely way a harness like this dies is going green while testing
nothing, so two guards are built in rather than bolted on:

- `EXPECTED_MODULES` in `run.py` is compared to the plan the suite actually
  returns, by identity and not just count. A plan that quietly stopped shipping
  a module would otherwise run fewer tests and still exit 0.
- Only `PASSED` is green. Anything else fails unless it is declared with a
  reason in `config/expected.json`, so a new `WARNING` breaks the run instead of
  accumulating quietly.

Both were exercised. Pointing `PUBLIC_ORIGIN` at `http://` while still serving
TLS produces 7 condition failures and a red run; removing the
`allow_unexpected_metadata_fields` declaration produces a `WARNING` and a red
run. The witness checker has the same treatment: `oidf:<module>` is validated
against the runner's `EXPECTED_MODULES`, and a witness naming a module we do not
run is reported as dangling.

## The remaining rungs

| rung | plan | modules | state |
|---|---|---|---|
| 0 | `oidcc-config-certification-test-plan` | 1 | **shipped** |
| 1 | `oidcc-basic-certification-test-plan` | 38 | scoped, not started |
| 2 | `oidcc-formpost-basic-certification-test-plan` | 38 | cheap once rung 1 exists |
| 3 | `oidcc-implicit-certification-test-plan` | — | blocked, by choice |

**Rung 1 needs a browser and one piece of real work.** Every Basic OP module
drives an actual login, which the suite scripts through a `browser` block of
Selenium-style commands. The emulator's sign-in page is already built for this
(`internal/identity/signin.go` says so, and `e2e/browser` already drives it), so
the harness cost is configuration rather than code. The code gap is `max_age`
and `auth_time`: `authorize.go` never reads `max_age`, no `auth_time` claim is
emitted anywhere, and `OIDCCMaxAge1` and `OIDCCMaxAge10000` need both. Real
Entra supports them, so this is a parity gap worth closing on its own merits.
Rung 1 also needs two statically registered clients whose redirect URIs point at
the suite.

Expected to land in `config/expected.json` rather than being fixed:
`OIDCCScopeAddress`, `OIDCCScopePhone` and `OIDCCClaimsEssential`. The emulator
supports none of them, and neither does real Entra.

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
