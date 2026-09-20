#!/usr/bin/env python3
"""A Graph route the emulator registers must be driven, or listed as not yet.

THE RATCHET, and it is the piece that keeps a coverage number honest. The
conformance checker validates the responses a suite happened to produce, and the
ledger says which documented operations are served. Neither says anything about
the routes this emulator REGISTERS that no suite has ever driven, and those are
where a wrong shape lives longest: nobody is looking. It is a port of
fabric-emulator's scripts/check_route_coverage.py.

THE GATE IS THAT THE NUMBER CANNOT GET WORSE, in every direction:

  * a NEW route registered with no traffic fails, so an endpoint arrives with its
    evidence instead of acquiring it later;
  * a route that STOPS being driven fails, because coverage silently regressing is
    the same defect a stale witness is;
  * a route that STARTS being driven also fails, which sounds perverse and is the
    point: the baseline is a record of what is not yet proved, and an improvement
    that does not shrink it leaves a lie in the file. Updating it is one command
    and the diff is the review;
  * a baseline entry for a route that no longer exists fails, so the file cannot
    keep describing a tree that is gone.

WHY NOT SIMPLY REQUIRE FULL COVERAGE. A gate nobody can pass is a gate somebody
deletes. The honest denominator is the routes this emulator serves, and not every
one is reachable by the suites that exist today. A gate that only ratchets keeps
paying.

WHAT COUNTS AS DRIVEN, and it is stricter than fabric's rule: at least one
recorded response with a 2xx status. A route reached only by a 401, a 403 or a
404 has been shown to exist, not to WORK: nothing has watched its success path
against the schema. "Driven" here means driven to success with conformance
watching, which is what the number is for.

THE ORACLE THAT DOES NOT TRUST THE ENUMERATION. Coverage and the ledger both
trust that the registered routes are complete. This does not: every recorded
NON-404 response must match some registered pattern, because a response the
emulator actually served that matches nothing means the enumerator is blind to
whatever handled it. (Fabric found 95 of these once, all Livy calls two segments
past a rest-of-path wildcard, by exactly this check.) A 404 is exempt: an unrouted
request is the normal way to be told no.

ROUTES ARE ENUMERATED AT RUNTIME, by the real Register (see graph.Router), so
unlike fabric's copy there is no source parsing here to go blind.

Usage:
    check_graph_route_coverage.py <recording.jsonl> [...]          report, exit 0
    check_graph_route_coverage.py <recording.jsonl> [...] --strict exit non-zero on drift
    check_graph_route_coverage.py <recording.jsonl> [...] --update rewrite the baseline
"""
import argparse
import collections
import json
import os
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
BASELINE = ROOT / "docs" / "graph-route-coverage.json"

sys.path.insert(0, str(ROOT / "scripts"))
import check_graph_conformance as conf  # noqa: E402
import check_graph_ledger as ledger  # noqa: E402

# Kept in step with the recorder (graph_path in internal/server/record.go): only
# /v1.0 is recorded, so only /v1.0 can ever be proved.
IN_SCOPE = "/v1.0/"

_PARAM = re.compile(r"^\{[^}]+\}$")


def in_scope_routes(routes):
    """The registered "METHOD /v1.0/..." patterns a recording could ever prove."""
    return sorted({r for r in routes
                   if r.partition(" ")[2].startswith(IN_SCOPE)})


def _segments(path):
    return path.strip("/").split("/")


def resolve(routes, method, path):
    """The registered route that would serve (method, path), or None.

    Mirrors http.ServeMux for the only forms this package registers: literal
    segments and single-segment `{name}` wildcards. Where several patterns match,
    the one with the MOST LITERAL segments wins, which is ServeMux's precedence:
    `/directory/deletedItems/graph.user` must take the credit for a request to it,
    not the `/directory/deletedItems/{id}` wildcard beside it. ServeMux refuses to
    register two patterns it cannot order, so there is never a tie to break.
    """
    want = _segments(path)
    best, best_literals = None, -1
    for route in routes:
        m, _, pattern = route.partition(" ")
        if m != method:
            continue
        have = _segments(pattern)
        if len(have) != len(want):
            continue
        literals = 0
        for h, w in zip(have, want):
            if _PARAM.match(h):
                continue
            if h != w:
                break
            literals += 1
        else:
            if literals > best_literals:
                best, best_literals = route, literals
    return best


def read_entries(recordings):
    entries = []
    for recording in recordings:
        entries.extend(conf.read_recording(pathlib.Path(recording)))
    return entries


def measure(routes, entries):
    """(exercised set, orphaned responses) over the union of recordings."""
    in_scope = in_scope_routes(routes)
    exercised, orphaned = set(), collections.Counter()
    for e in entries:
        method, path, status = e.get("method", ""), e.get("path", ""), e.get("status", 0)
        route = resolve(in_scope, method, path)
        if route is None:
            # Not a v1.0 route this package registers. Only a NON-404 response
            # means the emulator really served it, so only that is a blind spot.
            if status != 404 and status < 500:
                orphaned[f"{method} {path}"] += 1
            continue
        if 200 <= status < 300:
            exercised.add(route)
    return exercised, orphaned


def read_baseline():
    return json.loads(BASELINE.read_text()) if BASELINE.is_file() else None


def write_baseline(registered, exercised):
    not_yet = sorted(set(registered) - exercised)
    BASELINE.write_text(json.dumps({
        "_comment": [
            "Graph routes the emulator registers that no recorded suite has driven to",
            "a 2xx. Written by scripts/check_graph_route_coverage.py --update; do not",
            "hand-edit. This is a record of what is NOT yet proved, and the gate holds",
            "it down: a new route with no traffic fails, a route that stops being",
            "driven fails, and a route that starts being driven ALSO fails until the",
            "baseline is updated, so an improvement is recorded and cannot leave a",
            "stale file behind.",
        ],
        "registered": len(registered),
        "exercised": len(registered) - len(not_yet),
        "notYetExercised": not_yet,
    }, indent=2) + "\n")


def run(recordings, strict, update, routes_file=None):
    routes = ledger.registered_routes(routes_file)
    if not routes:
        print("check_graph_route_coverage: no routes were enumerated, so coverage "
              "of nothing would read as 100%. Is `go run ./internal/graph/cmd/graphroutes` "
              "working?", file=sys.stderr)
        return 1
    registered = in_scope_routes(routes)
    missing = [r for r in recordings if not pathlib.Path(r).is_file()]
    if missing:
        # NAMED, not a traceback and not skipped. A suite that recorded nothing
        # would otherwise shrink the union and read as a coverage regression on
        # routes that are fine, which blames the routes for the suite's fault.
        print("check_graph_route_coverage: no such recording: " + ", ".join(map(str, missing)),
              file=sys.stderr)
        return 1
    entries = read_entries(recordings)
    if not entries:
        print("check_graph_route_coverage: no recorded responses. A run that recorded "
              "nothing proves nothing, so this is a failure and not a clean pass.",
              file=sys.stderr)
        return 1

    exercised, orphaned = measure(routes, entries)
    not_yet = sorted(set(registered) - exercised)
    print(f"check_graph_route_coverage: {len(registered)} registered /v1.0 routes, "
          f"{len(exercised)} driven to a 2xx, {len(not_yet)} not yet")

    problems = []
    for label, n in sorted(orphaned.items()):
        problems.append(f"ORPHANED: served {n}x but matches no registered route, so the "
                        f"enumeration is blind to whatever handled it: {label}")

    if update:
        write_baseline(registered, exercised)
        print(f"  baseline written to {os.path.relpath(BASELINE, ROOT)}")
    else:
        base = read_baseline()
        if base is None:
            problems.append("no baseline; run with --update")
            base = {}
        was = set(base.get("notYetExercised", ()))
        now = set(not_yet)
        gone = sorted(was - set(registered))
        for r in gone:
            problems.append(f"in the baseline but no longer registered, delete it: {r}")
        for r in sorted(now - was):
            problems.append(f"registered and not driven, and not in the baseline: {r}")
        for r in sorted((was - now) - set(gone)):
            problems.append(f"now driven, but the baseline still lists it as not yet: {r}")

    if problems:
        print(f"\n{len(problems)} disagreement(s):")
        for p in problems[:40]:
            print(f"  - {p}")
        if len(problems) > 40:
            print(f"  ... and {len(problems) - 40} more")
        print("\n  -> drive the route from a suite that records, or, if that is genuinely "
              "not possible yet, run with --update and review the diff. An improvement "
              "has to be recorded to count.")
        return 1 if strict else 0

    print(f"  agrees with the baseline ({len(not_yet)} not yet driven, unchanged)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("recordings", nargs="+")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--update", action="store_true")
    ap.add_argument("--routes", help="a file of `METHOD /path` lines, instead of running Go")
    a = ap.parse_args()
    return run(a.recordings, a.strict, a.update, a.routes)


if __name__ == "__main__":
    sys.exit(main())
