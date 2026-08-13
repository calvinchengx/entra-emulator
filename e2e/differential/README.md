# Differential capture

Tooling for the one thing no emulator in this family has: evidence gathered by
diffing against **real Azure**, rather than by witnessing locally against real
clients. Everything graded 🟢 in `docs/parity.md` today means "an unmodified
client accepted our responses" — never "our responses matched Entra's".

The first six token-endpoint scenarios are captured (app-only envelope, claim
names, four error envelopes) and checked offline by
`internal/server/differential_test.go`. Envelope field sets are an exact
normalised match. The claims fixture is a **structural** comparison — `ver`,
header `alg`/`typ`, `tid`, `azp`, issuer path `/{tid}/v2.0`, and protocol claim
*names* — not an exact JWT. Entra telemetry (`aio`, `rh`, `uti`, …), the local
issuer host, `oid` on app-only tokens, and `aud` as GUID vs App ID URI are
recorded divergences, not silent skips.

Recapture with `./seed.sh && ./capture.sh && ./teardown.sh` when the fixtures
go stale (90 days).

## The capture tenant

A free Microsoft Entra tenant, separate from any production directory:

| | |
|---|---|
| domain | `entraemulatordiff.onmicrosoft.com` |
| region | Singapore (Asia Pacific) |
| type | Workforce **(legacy)**, deliberately not the Governed Workforce preview |

Legacy rather than the recommended preview because fixtures captured against a
preview configuration would record behaviour that is not the stable product and
can shift underneath them. Note that Microsoft restricts creation of additional
legacy workforce tenants after **15 August 2026**, so this exact configuration
may not be reproducible later.

Entra ID **Free** covers the whole diffable surface — discovery, tokens, Graph
v1.0, consent. The P1/P2 features it does not cover (Conditional Access, PIM,
Identity Protection) are this emulator's stated non-goals anyway. Custom
security attributes are the one 🟢 row that likely needs P1/P2.

## Use

```sh
az login --allow-no-subscriptions --tenant entraemulatordiff.onmicrosoft.com
./seed.sh        # create the directory objects
./teardown.sh    # remove them, and purge from the recycle bin
```

`teardown.sh` is safe on an empty tenant and safe to run twice.

## Why the scripts look defensive

**`tenant-guard.sh` is the important file.** Every other script mutates a
directory, and the failure that matters is doing that in the *wrong* one — a
production tenant is indistinguishable from this one once `az` is signed into
it. So nothing runs before the guard passes, and the guard compares a **verified
domain** rather than a tenant GUID, because a wrong GUID looks like any other
GUID while a wrong domain is readable at a glance.

**Teardown only removes objects prefixed `emudiff`.** A teardown that deleted
"all users" would behave perfectly on a fresh tenant and catastrophically
anywhere else. The blast radius is a property of the code, not of who runs it.

**Teardown purges, it does not merely delete.** Entra soft-deletes into a
recycle bin, and leftover soft-deleted applications are a documented blocker on
deleting a tenant. A teardown that only soft-deleted would leave the tenant
quietly undeletable.

**Teardown was written and run before `seed.sh` existed.** An exit path that has
never executed is a belief about reversibility rather than a capability. The
guard's refusal is tested too — pointed at another tenant it must abort, and a
guard only ever observed passing proves nothing.

## `.capture-identity.json`

Written by `seed.sh`, removed by `teardown.sh`, **gitignored**, mode 600. It
holds generated passwords and a client secret, and:

- **the identity map** — emulator seed id ↔ Azure object id.

That map is the point. Azure assigns its own GUIDs, so the emulator's seeded ids
have no counterpart, and a diff that does not normalise through this map is
drowned in GUID mismatch before it can report anything real.

It is also where the first real risk lives. **The normaliser is the instrument,
and instrument bugs surface as passes**: over-normalise and every response
matches, which is a false pass that no green run would reveal. Whatever consumes
this map needs its own mutation check — feed it a deliberately wrong response
and assert the diff fails.

## `capture.sh`

Records real Entra responses as fixtures under `testdata/fixtures/`, and stamps
`testdata/fixture-manifest.json`. Guard-protected like everything else here.

```sh
az login --allow-no-subscriptions --tenant entraemulatordiff.onmicrosoft.com
./seed.sh
./capture.sh
./teardown.sh
```

The tenant is also recorded as GitHub repository **variables**,
`EMU_DIFF_DOMAIN` and `EMU_DIFF_TENANT_ID`, for a future workflow that runs
capture on a schedule. They are variables rather than secrets deliberately:
neither value is confidential (the domain is in this file, and unauthenticated
OIDC discovery maps it to the GUID), and secrets are **masked in logs**, which
would render `tenant-guard.sh`'s "expected X, signed in to Y" as `***` and
destroy the readability the guard was designed around. Secrets are for the
credential a scheduled run would need, not for identifiers.

**Normalisation happens at capture time, not at diff time.** The identity map
lives in `.capture-identity.json`, which is gitignored because it also holds a
secret and two passwords — CI never has it. An id left raw in a fixture can
therefore never be reconciled later, so the fixture is written already
normalised and is safe to commit.

**Access tokens are never recorded.** A captured JWT is a live credential until
it expires. The envelope keeps `access_token` as `{redacted-jwt}`; a separate
scenario records the token's header, its claim NAMES and the few structural
claim values, which is the part an emulator has to get right.

The first scenarios are the token endpoint: the app-only envelope, and four
error envelopes. Errors first because they are the richest differential surface
and carry no secrets — `error_codes`, the AADSTS number, `trace_id` and
`correlation_id` are exactly what a from-the-docs implementation omits, and no
local test can tell us we omitted them.

## Checking, which is separate from capturing

`internal/server/differential_test.go` replays the fixtures against the
emulator and diffs. It is **offline** — no Azure, no credentials, no network —
so it runs in the ordinary `go test` gate. Capture is the privileged step;
checking is not.

Three properties it deliberately has:

- **It skips loudly.** With nothing captured, the comparison skips but the
  manifest test logs that there is no differential evidence at all. A silent
  skip would read as a pass.
- **It fails STALE rather than passing** once a fixture is older than
  `maxAgeDays`, per the rule below. Age is measured per fixture, not from the
  manifest, because a partial recapture leaves the manifest looking current.
- **It mutation-checks the normaliser**, which is the risk the section above
  names. `TestDifferentialNormaliserDoesNotHideDifferences` feeds it differences
  that must be caught (a missing field, an extra field, a wrong error code, a
  wrong AADSTS number) and differences it must absorb (a new trace id, a new
  timestamp). Verified by breaking the normaliser on purpose and confirming the
  test fails with its own message rather than a build error.

## What differential evidence will and will not mean

For the recorded interactions, at the capture date, against that API version,
the emulator's normalised response matched Azure's. Fixtures need `capturedAt`
and should report **stale** past a max age rather than passing, or an old
recording silently certifies drift.

It will not mean "parity with Azure", and the grade must not be allowed to read
that way — that is the over-claim this whole evidence system exists to prevent.
