#!/usr/bin/env python3
"""Every Graph operation Microsoft documents, in one of three states.

WHY THIS EXISTS, given there is already a conformance checker. That gate asks "did
what we answered match the schema", and its denominator is whatever a suite
happened to touch: 78 recorded responses. It is silent, by construction, about the
17,870 operations Microsoft documents and this emulator does not serve, which is
nearly all of them. This is the gate whose denominator is the SPEC, so it is the
only one that can say how much of Graph this emulator answers. It is a port of
fabric-emulator's scripts/check_surface_ledger.py.

The three states, and only three:

  SERVED   -- a registered route has the same SHAPE as the documented operation:
              same method, same segments, parameter NAMES ignored (the spec says
              {user-id}, the emulator says {id}). What it answers is then held to
              the schema by check_graph_conformance.py.
  REFUSED  -- not served, and MEASURED to answer 404: a recording contains a 404
              for a concrete path under this operation. Evidence, not a claim.
  SILENT   -- neither. Nothing serves it and nothing has ever asked.

THE REVERSE DIRECTION, which fabric's copy does not have and which found this
repo's one real bug. A registered route whose shape matches NO documented
operation is an INVENTED endpoint: the emulator answers something Graph does not,
so code that works here fails against Entra. `resetPassword` was served under
`/authentication/passwordMethods/`, which Microsoft does not have. Those are
listed separately and are findings; KNOWN_INVENTED pins the deliberate ones.

THE GATE IS A RATCHET, and it ratchets in every direction: a served operation
that stops being served, a newly served one nobody recorded, and a stale baseline
all fail, so the file cannot become a story about a tree that no longer exists.

WHAT THIS IS NOT. It says nothing about whether a served operation answers
CORRECTLY, which is conformance's job, on a different input. An operation can be
SERVED and wrong; it can be SILENT and be exactly what this emulator should not
serve, since it is a localhost subset and most of Graph is Exchange, Teams and
SharePoint.

WHY THE ROUTES ARE ENUMERATED AT RUNTIME. http.ServeMux cannot list its own
patterns, and regexing the Go source read only 19 (registration goes through
prefix variables and some calls sit in loops). graph.RegisteredPatterns collects
them from the real Register, and the program in internal/graph/cmd/graphroutes
prints them.

Usage:
    check_graph_ledger.py [recording.jsonl ...]            report, exit 0
    check_graph_ledger.py [recording.jsonl ...] --strict   exit non-zero on drift
    check_graph_ledger.py [recording.jsonl ...] --update   rewrite the baseline
"""
import argparse
import collections
import functools
import json
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
BASELINE = ROOT / "docs" / "graph-surface-ledger.json"

sys.path.insert(0, str(ROOT / "scripts"))
import check_graph_conformance as conf  # noqa: E402

# Registered routes that are not Graph's v1.0 API and so are outside the spec:
# OIDC userinfo lives on the Graph host but is specified by OIDC Core, and its
# oracle is the OIDF suite.
OUT_OF_SPEC_PREFIXES = ("/oidc/",)

# Registered routes Microsoft's v1.0 spec does not document, on purpose. Each
# entry is a SUBSTRING of "METHOD /path" and carries the reason. Adding one is a
# claim that the route is deliberate; the list is meant to shrink.
KNOWN_INVENTED: dict[str, str] = {
    # THE DOCS' SPELLING OF A TYPE CAST, which the spec does not use. Microsoft's
    # own page (directory-deleteditems-list) writes
    # `GET /directory/deletedItems/microsoft.graph.group` in its HTTP request
    # section and its JavaScript example, while the SDK snippets on the SAME page
    # (`DeletedItems.GraphGroup`) are the OpenAPI's `graph.group`. Both are real,
    # so both are served, and the emulator answers them identically
    # (TestDeletedItemsCastAnswersUnderBothNamespaceSpellings). The spec, which is
    # generated, abbreviates the namespace to its alias; the docs, which are
    # written, do not.
    "/v1.0/directory/deletedItems/microsoft.graph.":
        "the docs' qualified spelling of the type cast; the spec spells it graph.*",
    # AN OPEN QUESTION, NOT A DEFENCE. internal/graph/consent.go registers
    # oauth2PermissionGrants under BOTH "/oauth2PermissionGrants" and
    # "/oAuth2PermissionGrants" with the comment "register both Entra casings".
    # Microsoft's spec has only the lowercase-a form, and nothing in this tree
    # cites the other. Go's ServeMux is case-sensitive, so this is a deliberate
    # second route. It is harmless if real Graph resolves resource names
    # case-insensitively and a lie if it does not, and that is unmeasured: a
    # request with the capital A against the capture tenant would settle it. Left
    # in place rather than deleted, because removing a route on a hunch could
    # break a client that works today.
    "/v1.0/oAuth2PermissionGrants":
        "second casing registered on purpose; the spec has only oauth2PermissionGrants. "
        "Needs one request against a real tenant.",
}

# GENERIC ROUTES THAT SERVE A DOCUMENTED OPERATION. A wildcard such as
# `GET /v1.0/{key}` has a different shape from every operation it serves, so shape
# comparison alone would call it invented and the operation silent. Each entry
# names what the route really serves and the evidence that real Graph serves it,
# and is only credited while that route is still registered.
SERVED_VIA: dict[str, tuple[list[str], str]] = {
    "GET /v1.0/{key}": (
        ["GET /servicePrincipals(appId='{appId}')"],
        "alternate-key lookup. getByAlternateKey answers exactly "
        "servicePrincipals(appId='...') and gives Graph's own 404 envelope for "
        "anything else. Real Graph serves it: the diff: fixture "
        "graph-serviceprincipal-shape was captured from it "
        "(internal/server/graph_alternate_key_test.go).",
    ),
}


def shape(path: str) -> str:
    """A path with its parameter NAMES removed.

    The spec spells it {user-id} and this emulator spells it {id}: same route. A
    literal segment stays literal, so `/users/$count` and `/users/{id}` are
    DIFFERENT shapes, which is the point: a wildcard that happens to swallow
    `$count` does not serve the documented `$count` operation.
    """
    return re.sub(r"\{[^}]+\}", "{}", path).rstrip("/")


def registered_routes(routes_file=None) -> list[str]:
    """Every "METHOD /path" the emulator registers, unprefixed."""
    if routes_file:
        return [l.strip() for l in pathlib.Path(routes_file).read_text().splitlines() if l.strip()]
    out = subprocess.run(
        ["go", "run", "./internal/graph/cmd/graphroutes"],
        cwd=ROOT, capture_output=True, text=True, check=True)
    return [l.strip() for l in out.stdout.splitlines() if l.strip()]


def served_shapes(routes):
    """(method -> shapes) with the /v1.0 base stripped, plus the invented set."""
    served = collections.defaultdict(set)
    in_v1 = []
    for route in routes:
        method, _, path = route.partition(" ")
        if path.startswith(OUT_OF_SPEC_PREFIXES):
            continue
        if not path.startswith("/v1.0/"):
            in_v1.append((method, path, False))
            continue
        served[method].add(shape(path[len("/v1.0"):]))
    return served


def documented(spec: conf.Spec):
    """{"METHOD template": (method, template)} for every documented operation."""
    ops = {}
    for (method, _n), bucket in spec.index.items():
        for _lit, _params, _pattern, template, _responses in bucket:
            ops[f"{method} {template}"] = (method, template)
    return ops


def refused(spec: conf.Spec, recordings):
    """Operations a recording shows answering 404: a MEASURED refusal."""
    seen = set()
    for recording in recordings:
        for entry in conf.read_recording(pathlib.Path(recording)):
            if entry.get("status") != 404:
                continue
            template, _ = spec.match(entry.get("method", ""), entry.get("path", ""))
            if template:
                seen.add(f"{entry['method']} {template}")
    return seen


def invented(routes, spec_shapes):
    """Registered v1.0 routes with no documented operation of that shape."""
    out = []
    for route in routes:
        method, _, path = route.partition(" ")
        if path.startswith(OUT_OF_SPEC_PREFIXES) or not path.startswith("/v1.0/"):
            continue
        if route in SERVED_VIA:
            continue
        if shape(path[len("/v1.0"):]) not in spec_shapes.get(method, ()):
            out.append(route)
    return sorted(out)


@functools.lru_cache(maxsize=1)
def load_spec() -> conf.Spec:
    """The vendored spec, parsed once. It is 37 MB of JSON, so a process that
    classifies more than once (the tests do, dozens of times) should not pay for
    it each time. load_spec also re-checks the pin, so caching does not skip it."""
    return conf.Spec(conf.load_spec())


def classify(recordings, routes):
    spec = load_spec()
    ops = documented(spec)
    served = served_shapes(routes)
    measured = refused(spec, recordings)
    spec_shapes = collections.defaultdict(set)
    for method, template in ops.values():
        spec_shapes[method].add(shape(template))
    via = {op for route, (served_ops, _why) in SERVED_VIA.items()
           if route in routes for op in served_ops}
    unknown_via = sorted(op for route, (served_ops, _why) in SERVED_VIA.items()
                         for op in served_ops if op not in ops)
    if unknown_via:
        # A SERVED_VIA entry naming an operation the spec does not have is a typo
        # that would silently credit nothing.
        sys.exit(f"SERVED_VIA names operation(s) not in the spec: {unknown_via}")
    states = {}
    for label, (method, template) in ops.items():
        if label in via or shape(template) in served.get(method, ()):
            states[label] = "served"
        elif label in measured:
            states[label] = "refused"
        else:
            states[label] = "silent"
    return states, invented(routes, spec_shapes)


def read_baseline():
    return json.loads(BASELINE.read_text()) if BASELINE.is_file() else None


def write_baseline(states):
    counts = collections.Counter(states.values())
    BASELINE.write_text(json.dumps({
        "_comment": [
            "Every operation in Microsoft's Graph v1.0 OpenAPI, in one of three",
            "states. Written by scripts/check_graph_ledger.py --update; do not",
            "hand-edit. `silent` is the set nothing serves and nothing has ever",
            "asked about. `served` and `refused` are listed so that leaving those",
            "states is also a diff somebody reviews.",
        ],
        "documented": len(states),
        "served": counts["served"],
        "refused": counts["refused"],
        "silent": counts["silent"],
        "servedOperations": sorted(k for k, v in states.items() if v == "served"),
        "refusedOperations": sorted(k for k, v in states.items() if v == "refused"),
    }, indent=2) + "\n")


def family(template: str) -> str:
    """The top-level resource an operation belongs to: `/users/{id}/x` -> users."""
    return template.strip("/").split("/")[0].split("(")[0]


def print_families(states):
    """Served/documented per top-level family.

    THE HEADLINE NUMBER IS MISLEADING ON ITS OWN. Most of the spec is Exchange,
    Teams, SharePoint, OneNote and Intune, which a localhost Entra emulator should
    never serve, and `users`, `groups` and `me` are mostly those relations hung off
    a directory object. So the per-family view is the honest one, and no "in
    scope" denominator is asserted here: which families belong to an Entra
    emulator is a product decision this script does not get to make.
    """
    total, served = collections.Counter(), collections.Counter()
    for label, state in states.items():
        fam = family(label.partition(" ")[2])
        total[fam] += 1
        served[fam] += state == "served"
    print("\n  served / documented, by top-level family (families with any served):")
    for fam in sorted((f for f in total if served[f]), key=lambda f: -total[f]):
        print(f"    {fam:28s} {served[fam]:4d} / {total[fam]:5d}  ({served[fam] / total[fam] * 100:5.1f}%)")
    dark = sorted(((f, n) for f, n in total.items() if not served[f]), key=lambda x: -x[1])[:8]
    print("  largest families with nothing served: "
          + ", ".join(f"{f} ({n})" for f, n in dark))


def run(recordings, strict, update, routes_file=None, families=False):
    routes = registered_routes(routes_file)
    if not routes:
        # A silent zero here would make every operation SILENT and every route
        # look absent: no routes read is not the same as none registered.
        print("check_graph_ledger: no routes were enumerated, so nothing can be "
              "classified. Is `go run ./internal/graph/cmd/graphroutes` working?",
              file=sys.stderr)
        return 1
    states, invented_routes = classify(recordings, routes)
    counts = collections.Counter(states.values())
    print(f"check_graph_ledger: {len(states)} documented operations, "
          f"{counts['served']} served, {counts['refused']} refused, "
          f"{counts['silent']} silent; {len(routes)} routes registered")

    if families:
        print_families(states)

    problems = []
    for route in invented_routes:
        if not any(pin in route for pin in KNOWN_INVENTED):
            problems.append(f"INVENTED ROUTE, registered but Microsoft's spec has no such "
                            f"operation: {route}")

    if update:
        write_baseline(states)
        print(f"  baseline written to {os.path.relpath(BASELINE, ROOT)}")
    else:
        base = read_baseline()
        if base is None:
            # NOT an early return: an invented route is a finding whether or not
            # a baseline exists, and returning here hid them.
            problems.append("no baseline; run with --update")
            base = {}
        was_served = set(base.get("servedOperations", ()))
        was_refused = set(base.get("refusedOperations", ()))
        now_served = {k for k, v in states.items() if v == "served"}
        now_refused = {k for k, v in states.items() if v == "refused"}
        for label in sorted(was_served - now_served):
            problems.append(f"no longer served, and the baseline still says it is: {label}")
        for label in sorted(was_refused - now_refused):
            problems.append(f"no longer a measured refusal, did a suite stop asking? {label}")
        for label in sorted(now_served - was_served):
            problems.append(f"newly served and not in the baseline: {label}")
        for label in sorted(now_refused - was_refused):
            problems.append(f"newly refused and not in the baseline: {label}")

    stale = sorted(p for p in KNOWN_INVENTED if not any(p in r for r in invented_routes))
    if stale:
        print(f"\n  {len(stale)} KNOWN_INVENTED entr(y/ies) match no registered route; "
              f"delete them:")
        for p in stale:
            print(f"    - {p}")

    if problems:
        print(f"\n{len(problems)} disagreement(s):")
        for p in problems[:40]:
            print(f"  - {p}")
        if len(problems) > 40:
            print(f"  ... and {len(problems) - 40} more")
        print("\n  -> an invented route needs fixing or a KNOWN_INVENTED reason; a "
              "baseline drift needs --update and a reviewed diff.")
        return 1 if strict else 0

    print(f"  ledger agrees with the tree ({counts['silent']} silent, unchanged)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("recordings", nargs="*")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--update", action="store_true")
    ap.add_argument("--routes", help="a file of `METHOD /path` lines, instead of running Go")
    ap.add_argument("--families", action="store_true", help="also print served/documented per family")
    a = ap.parse_args()
    return run(a.recordings, a.strict, a.update, a.routes, a.families)


if __name__ == "__main__":
    sys.exit(main())
