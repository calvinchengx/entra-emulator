# Graph conformance

> **Status: the recorder, the vendored spec and the checker have shipped.** Real
> SDK traffic is held to Microsoft's published Graph OpenAPI on every push. It
> found one real bug on its first run. The surface ledger and the route ratchet
> (below) are not built.

## What this is, and what it is not

Microsoft publishes an OpenAPI for Graph
([`microsoftgraph/msgraph-metadata`](https://github.com/microsoftgraph/msgraph-metadata),
MIT): **17,870 operations and 5,187 schemas**. This repo had never compared a
response to it. [19-golden-reference-parity.md](19-golden-reference-parity.md)
describes a golden file derived from that spec: four resources and 26 property
names, captured once by hand. This replaces the hand with a machine.

It is one of three kinds of evidence, and they are not interchangeable:

| kind | oracle | strength | narrowness |
|---|---|---|---|
| `ci:` | a real SDK's own model | strong | asserts on the fields it uses and ignores the rest |
| `diff:` | the real service, captured | strongest | 17 scenarios |
| `ci:graph-conformance` (this) | Microsoft's published schema | shape only | covers every route a suite happens to touch |

**Shape, never semantics.** A user whose `displayName` is the wrong string is
perfectly conformant. A pass says the answer was *shaped* right, not that it was
*true*.

**Identity endpoints are out of scope.** `/authorize`, `/token` and JWKS have no
OpenAPI; Microsoft specifies them in prose and RFCs. Their third-party oracle is
the OIDF suite ([23-oidf-conformance.md](23-oidf-conformance.md)). SCIM is RFCs
7643/7644, with `scim2-tester` as the client witness.

## How it works

```
e2e suites (real SDKs) ──▶ emulator with RECORD_RESPONSES=file ──▶ one JSON line per response
                                                                     │  method, path, query, status, body
                                                                     ▼   never a header
                        third_party/msgraph-openapi  ──▶  scripts/check_graph_conformance.py --strict
```

- **The recorder lives in the emulator, not in a proxy.** A proxy would have to be
  spliced into every suite, and any suite that forgot would contribute nothing
  silently. It is opt-in by one variable and covers whatever traffic a suite
  already produces. It records **no headers**, so no bearer token can reach a file
  CI uploads (`TestRecordingNeverContainsACredential` reads the whole file as text).
- **Compat mode has two spellings of one API.** Graph is `/v1.0/users` on its own
  origin and `/graph/v1.0/users` under `ORIGIN_MODE=compat`. The recorder
  normalises to the spec's spelling; otherwise every compat request looks like an
  undocumented route.
- **The spec is vendored, pinned and reproducible.** See
  `third_party/msgraph-openapi/PROVENANCE.md`.

## Four things about this spec that were measured, not assumed

Each of these would have produced a wrong answer if assumed.

1. **Statuses are ranges.** There is no `200` and no `default`: responses are
   keyed `2XX`, `4XX`, `5XX`, plus exact codes such as `204`. An exact code wins
   over its range, and a 2xx the spec does not list is a finding rather than being
   swallowed by an error schema.
2. **`@odata.type` is marked required on every entity, and real Graph does not
   send it.** The captured real-tenant fixture `graph-user-shape.json` is Graph's
   *complete* default key set: 12 keys, `@odata.context` present, `@odata.type`
   absent. A required `@odata.*` name is therefore never reported. Without that
   exclusion every entity response is a finding, which the checker's own tests
   demonstrate.
3. **Paths collide.** `/users/delta()` also matches `/users/{user-id}`. The most
   specific template wins, not the first.
4. **`additionalProperties` appears twice in the whole spec.** Checking for
   unexpected properties would fire on essentially every response, so it is
   deliberately not checked.

What *is* checked: undocumented status, undocumented route, missing required
property (including inside the OData error envelope, which the spec genuinely
specifies), wrong type, null where the spec does not mark it nullable, enum
membership, and `pattern` (220 Graph properties carry one, including every
datetime). `anyOf`/`oneOf` are clean if any branch is; if none is, the closest
branch is reported.

## What it found

On the first run: 67 responses over 50 route shapes, from three suites.

| finding | verdict |
|---|---|
| `POST .../authentication/passwordMethods/{id}/resetPassword` is not a documented operation | **A real bug, fixed.** Microsoft's spec has one `resetPassword`, under `methods`, and every SDK snippet in the docs uses it. The emulator served the other spelling, so `Authentication.Methods[..].ResetPassword` got a 404 here and worked against Entra. The real-SDK suite hard-coded the invented URL through the SDK's raw `api()`, so the client witness was green while asserting a URL Entra rejects. |
| `error.innerError.date` has no zone, and the spec's pattern requires one | **Pinned: the spec is the outlier.** The emulator emits `2026-09-19T16:12:03`; `internal/httpx` records that Entra's own format there has no offset, written while diffing four real errors. The fixtures normalise every timestamp to `{timestamp}`, so the real format is not preserved; a raw capture would settle it. |
| `signIn.userId` is null on some rows and the spec says non-nullable | **Pinned: an open question.** Microsoft's docs give no value for a user-less sign-in, so nothing public settles it. The rows are client-credentials exchanges (which `e2e/graph` asserts are listed, a deliberate design) and one failed login for an unknown user. Real v1.0 `signIns` are user sign-ins, so listing service-principal exchanges is a further divergence this pin does not cover. Inventing a zero GUID would satisfy the schema and assert something nobody measured. |

The second row is where the `oidf:`-style axis and the `diff:` axis disagree, in
miniature: the spec and the service say different things, and an emulator follows
the service.

## The checker has its own tests

It reported almost nothing on 67 real responses, and "the emulator is good" and
"the checker is lenient" look identical when green. So
`scripts/test_check_graph_conformance.py` feeds every rule a response known to
break it, against the real vendored spec rather than a stand-in. Mutating three of
the checker's rules turns the suite red each time; removing the `@odata.*`
exclusion alone fails eight of its 23 tests.

Two refusals exist because of mistakes made building it. A recording where
*nothing* matches is diagnosed as a matching fault instead of being reported as
dozens of defects: the first version forgot that the spec's paths carry no
`/v1.0` prefix and printed 46 "findings" that were all its own. And an empty or
missing recording is a failure, not a pass.

## Not built yet

This is a port of fabric-emulator's design, which has three gates with three
different denominators. Only the first exists here.

| gate | question | denominator | state |
|---|---|---|---|
| conformance | did the response match the schema? | what a suite happened to touch | **shipped** |
| surface ledger | is every documented operation served, refused, or silent? | **the spec** (17,870) | not built |
| route ratchet | is every route we register exercised? | what we register | not built |

The ledger is the one that would say something new. Route coverage can read 100%
while most of the API answers nothing, and only a gate whose denominator is the
spec can tell a silent gap from a refused one. It needs a proper enumeration of
registered routes, which `http.ServeMux` does not offer and which parsing the Go
source does not do reliably: a first attempt read 19 of 88 handlers and would have
reported nonsense.

Other open items, none of them settled by this work:

- The whole union is small: 78 recorded responses. That is the honest ceiling on
  what a pass means today, and the ratchet is what would stop it shrinking.
- `Location` on `resetPassword` points at the method resource; Graph points at an
  `authentication/operations/{id}` resource that is not served.
- `graph-resources.golden.json` (26 hand-listed property names) is now a strict
  subset of what this holds responses to, and can be retired once nothing depends
  on it.
