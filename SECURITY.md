# Security

## Reporting a vulnerability

Report privately through GitHub, on this repository:
**[Security → Report a vulnerability](https://github.com/calvinchengx/entra-emulator/security/advisories/new)**.

That opens a draft advisory visible only to you and the maintainer. Please do
not open a public issue for a security report, and please give the project a
chance to ship a fix before disclosing.

Include what you would want if you were fixing it:

- the component (token service, OIDC endpoints, Graph, SCIM, passkeys, admin
  API, portal, TLS);
- how to reproduce, ideally as a failing test or a `curl` against a local run;
- what an attacker gains, and from what starting position.

Expect an acknowledgement within a few days. This is a personal open-source
project, not a staffed security team, so please be patient with timelines.

## What this project is, and what that means for scope

**entra-emulator is a local development tool that is intentionally insecure**, as
its README states plainly: an open admin API, publicly known seeded users and
client secrets, self-signed TLS, and a **signing key stored unencrypted**. It is
meant to run on `localhost`. It is not an identity provider, not a security
boundary, and must never authenticate real users or issue tokens anything real
will trust.

That framing matters more here than in most projects, because this emulator
*mints tokens*. Its whole job is to hand out credentials freely, and it even
ships a documented way to forge them
([docs/13-testing-with-forged-tokens.md](docs/13-testing-with-forged-tokens.md)).
"I obtained a token for an arbitrary user" is the product working.

### In scope

Reports that matter here are ones where the emulator betrays the developer
running it, or teaches code a lesson that is wrong against real Entra:

- **Token validation logic that is wrong rather than absent.** Consumers write
  and test their *own* validation against this issuer, so a token this emulator
  accepts that real Entra would reject is a genuine finding: a signature check
  that passes on a tampered token, an `exp`/`nbf`/`aud`/`iss` claim that is not
  enforced where the docs say it is, a `kid` confusion, or an algorithm
  downgrade. Anything that makes a consumer's verifier look correct while it is
  not.
- **Claims or scopes the emulator issues too generously**, where a consumer's
  authorization code would then pass locally and fail in production. Being more
  permissive than the thing being emulated certifies code that is broken.
- **Escape from the emulator to the host**: path traversal, command injection, or
  SCIM/Graph input reaching the filesystem or process beyond its documented
  surface.
- **Cross-tenant or cross-user leakage** in the stateful directory, where
  isolation is claimed and enforced rather than absent.
- **Real credentials leaking.** If a genuine secret ever reaches a log, an error
  body, or a fixture, that is in scope even in a tool this permissive.
- **Supply chain.** A compromised or typosquatted dependency, or anything in the
  release pipeline that could ship a binary we did not build.

### Not in scope

- The unauthenticated admin API. It exists so tests can drive the directory.
- Seeded users, passwords, client secrets, and the unencrypted signing key. They
  are published on purpose; `docs/06-data-model-and-seed.md` lists them.
- Issuing a token for any user or client on request. That is the feature.
- Forging tokens by the documented mechanism.
- Self-signed or locally trusted TLS, and the local CA the docs tell you to
  install.
- Anything that requires exposing the emulator to a hostile network. Do not do
  that; it is out of scope by construction.
- Denial of service against a single-tenant local process.

If you are unsure which side a report falls on, send it. A misfiled report costs
little; a silent one costs more.

## Supported versions

Fixes land on `main` and ship in the next release. There are no long-lived
maintenance branches, so please confirm against `main` before reporting.
