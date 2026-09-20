# Graph conformance

> **Status: all three gates have shipped.** Real SDK traffic is held to
> Microsoft's published Graph OpenAPI on every push; every one of its 17,870
> operations is classified as served, refused or silent; and the emulator's own 94
> registered routes are ratcheted so the number that have never been driven can
> only fall. Between them they found two real bugs.

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

## The surface ledger

Conformance asks "did what we answered match the schema", and its denominator is
whatever a suite happened to touch: 120 responses. It is silent about the 17,870
operations Microsoft documents. The ledger's denominator is **the spec**.

```
graph.RegisteredPatterns  ──▶  internal/graph/cmd/graphroutes  ──▶  scripts/check_graph_ledger.py --strict
  (the real Register)            prints 97 METHOD /path lines        vs the vendored spec + the recordings
```

Every documented operation is in exactly one state:

| state | meaning |
|---|---|
| **served** | a registered route has the same *shape*: same method, same segments, parameter names ignored (`{user-id}` is `{id}`) |
| **refused** | not served, and a recording *measured* a 404 for it. Evidence, not a claim |
| **silent** | neither: nothing serves it and nothing has ever asked |

**Today: 88 served, 0 refused, 17,782 silent (0.49%).** That headline is
misleading on its own, because most of the spec is Exchange, Teams, SharePoint,
OneNote and Intune, which a localhost Entra emulator should never serve. No "in
scope" denominator is asserted here, since which families belong to an Entra
emulator is a product decision the script does not get to make. The per-family
view (`--families`) is the honest one:

| family | served / documented |
|---|---|
| `oauth2PermissionGrants` | 3 / 7 |
| `directory` | 20 / 210 (9.5%) |
| `applications` | 13 / 141 (9.2%) |
| `auditLogs` | 2 / 23 |
| `roleManagement` | 9 / 226 (4.0%) |
| `servicePrincipals` | 8 / 223 (3.6%) |
| `policies` | 4 / 205 (2.0%) |
| `users` | 13 / 1,790, mostly Exchange/Teams/OneNote relations |

And whole Entra product areas with nothing served: `identityGovernance` (2,396
operations), `identity` (234), `admin` (217). `refused` is currently empty: the
recordings contain 404s only on routes that are served, where a 404 means "not
found" and not "not implemented", so served correctly wins.

### The reverse direction, which found the second bug

Fabric's ledger goes spec to emulator only. This one also goes emulator to spec:
a registered route whose shape matches **no** documented operation is an *invented
endpoint*, so code that works here fails against Entra. That is the class the
`resetPassword` bug belonged to. It found, on its first run, seven routes to
adjudicate, and they were three different stories:

| route | verdict |
|---|---|
| `directory/deletedItems/microsoft.graph.{user,group,application}` | **A real gap, fixed.** Microsoft's docs write the type cast this way, but the spec, and therefore every Kiota-generated SDK (`DeletedItems.GraphUser`), writes `graph.user`. The emulator served only the docs' spelling, so a generated SDK's own request builder fell through to the `{id}` wildcard and got a 404 naming a resource "graph.user". Both spellings are served now, identically, and the docs' spelling is pinned as a documented-but-not-in-spec route. Microsoft's own page uses *both*: the raw HTTP and JavaScript examples say `microsoft.graph.group`, the C#, Go, Java, PHP and Python snippets on the same page say `.GraphGroup`. |
| `GET /v1.0/{key}` | **Not invented; a generic route that serves one documented operation.** `getByAlternateKey` answers exactly `servicePrincipals(appId='...')`. Real Graph serves it: the `diff:` fixture `graph-serviceprincipal-shape` was captured from it. Declared in `SERVED_VIA` with that evidence, credited only while the route is registered. |
| `oAuth2PermissionGrants` (capital A) | **Pinned as an open question.** `consent.go` registers both casings with the comment "register both Entra casings", and the spec has only the lowercase form. Nothing in the tree cites the other. It is harmless if real Graph resolves resource names case-insensitively and a lie if it does not, and that is unmeasured. Left in place rather than deleted on a hunch. |

The conformance checker could not have found the first: it matched
`deletedItems/microsoft.graph.user` to `deletedItems/{id}` and reported nothing.
Only a gate whose denominator is the spec, and which compares shapes, sees that a
wildcard is not the operation.

### Enumerating the routes

`http.ServeMux` cannot list its own patterns. The first attempt regexed the Go
source and read 19 of the routes; its "0.04% served" was **invalid and never
reported**. The fix is `graph.Router`, a one-method interface that
`*http.ServeMux` already satisfies, plus a collector that records patterns and
serves nothing, run against the real `Register`. It sees **97** patterns, more
than the 89 `HandleFunc` call sites, because some calls sit in loops: which is the
whole reason the source cannot simply be counted.

### The ledger has its own tests

21 controls, and mutating four of its rules turns the suite red each time (7, 4,
1 and 1 failures). Two of them are bugs the tests themselves found: the first
version returned early on a missing baseline and **hid** invented routes, and its
baseline message raised when the file was outside the repo. `--update` rewrites
the baseline; a stale baseline, a route that stops being served, and a newly served
route nobody recorded all fail, so the file cannot become a story about a tree that
no longer exists.

## The route ratchet

The conformance checker validates the responses a suite happened to produce, and
the ledger says which documented operations are served. Neither says anything
about routes this emulator **registers** that no suite has ever driven, and those
are where a wrong shape lives longest: nobody is looking.

**94 registered `/v1.0` routes. 83 driven to a 2xx. 11 not yet.** Before the Graph
suite was extended it was 46 and 48, a number that had not been visible at all.

The gate is that the number cannot get worse, in every direction:

| what happens | result |
|---|---|
| a new route is registered with no traffic | fails, so an endpoint arrives with its evidence |
| a route stops being driven | fails: coverage silently regressing is the same defect as a stale witness |
| a route **starts** being driven | **also fails**, until the baseline is updated |
| a baseline entry names a route that no longer exists | fails |

The third row sounds perverse and is the point: the baseline records what is *not*
yet proved, and an improvement that does not shrink it leaves a lie in the file. It
fired on all 37 routes closed while building this, and refused to pass until they
were recorded.

**What counts as driven is stricter than fabric's rule: a 2xx.** A route reached
only by a 401, a 403 or a 404 has been shown to *exist*, not to *work*: nothing
watched its success path against the schema.

**An oracle that does not trust the enumeration.** The ledger and the coverage
count both trust that the registered routes are complete. So every recorded
**non-404** response must match some registered pattern, because a response the
emulator really served that matches nothing means the enumerator is blind to
whatever handled it. Fabric found 95 of these once, all Livy calls past a
rest-of-path wildcard, by exactly this check. Against the real recordings it finds
none.

**Precedence is modelled, then checked against the real table.** Where several
patterns match, the one with the most literal segments wins, which is
`http.ServeMux`'s rule: `/deletedItems/graph.user` must take the credit for a
request to it, not the `{id}` wildcard beside it. A test builds a concrete request
from every one of the emulator's registered routes and requires each to resolve
back to itself; inverting the precedence fails it.

### What closing 37 routes involved

Extending `e2e/graph/suite.mjs` to list, read, patch and delete what its earlier
sections had created, and to read the recycle bin under **both** namespace
spellings, so the alias the ledger found cannot regress unseen. It also put the
responses for those routes under the conformance checker: 78 recorded responses
became 120, with no new findings.

One assertion of mine was wrong, and the suite caught it: I asserted that
`getMemberGroups` lists the group the user joined, but the suite removes the user
from the group earlier, so an empty answer was correct. The test now asserts the
empty case *and* re-adds the membership before asserting the positive, because an
empty answer would pass equally against a handler that ignored membership.

### The eleven that remain, and why

| routes | why |
|---|---|
| `GET/POST/DELETE /oAuth2PermissionGrants` (capital A) | the uncited second casing, pinned as an open question in the ledger. Driving it would be asserting something nobody has measured |
| seven `/me` routes | need a signed-in user's token; this suite uses client credentials |
| `DELETE .../fido2Methods/{id}` | needs a registered passkey to delete |

## Not built yet

Nothing in the three-gate design. Open items, none settled by this work:

- The union is 120 recorded responses. That is the honest ceiling on what a pass
  means today.
- `Location` on `resetPassword` points at the method resource; Graph points at an
  `authentication/operations/{id}` resource that is not served.
- `graph-resources.golden.json` (26 hand-listed property names) is now a strict
  subset of what this holds responses to, and can be retired once nothing depends
  on it.
- The `oAuth2PermissionGrants` casing needs one request against a real tenant.
- The seven `/me` routes could be driven from a suite that signs a user in.
