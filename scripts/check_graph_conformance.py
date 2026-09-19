#!/usr/bin/env python3
r"""Graph responses the emulator really returned, against Microsoft's own schema.

WHY THIS EXISTS, and it is a different KIND of evidence from the rest. The `ci:`
witnesses in docs/witnesses.json are clients: an SDK drives a surface and its own
model rejects a wrong shape. That is strong and narrow, because a typed client
asserts on the fields it uses and ignores the rest. The `diff:` witnesses are
stronger still (the oracle is the service itself) and there are seventeen of
them. This reads the machine-readable spec Microsoft publishes for Graph and
covers every route a suite happens to touch. It is a port of fabric-emulator's
scripts/check_openapi_conformance.py, redesigned for OpenAPI 3 and for what THIS
spec actually contains (see below), which differs from Fabric's in ways that
matter.

HOW THE INPUT IS PRODUCED. RECORD_RESPONSES=<file> makes the emulator append one
JSON line per Graph response: method, path, query, status, body. No headers,
ever; see internal/server/record.go. The e2e suites already generate the traffic.

WHAT IS CHECKED, chosen because they are what a typed client stumbles into:

  1. UNDOCUMENTED STATUS -- the emulator answered a code the spec does not list.
  2. UNDOCUMENTED ROUTE -- the emulator served a path the spec has no operation
     for. Fabric treats this as "not a finding" because its swagger covers only
     part of what it serves. Graph's spec is the whole v1.0 API, so a route it
     does not have is the emulator inventing an endpoint.
  3. MISSING REQUIRED PROPERTY -- including inside arrays and the OData error
     envelope, which the spec genuinely specifies (`error`, `code`, `message`).
  4. WRONG TYPE, NULL WHERE NOT NULLABLE, ENUM MEMBERSHIP, PATTERN (220 Graph
     properties carry one, including every datetime), and numeric bounds.

WHAT IS DELIBERATELY NOT CHECKED. Unexpected properties. `additionalProperties`
appears TWICE in the 37 MB spec, so "extra field" would fire on essentially every
response and a checker that cries wolf gets muted.

WHAT A PASS MEANS. Shape, never semantics. A user whose displayName is the wrong
string is perfectly conformant. This says the answer was SHAPED right, not TRUE.

THREE THINGS ABOUT THIS SPEC THAT WERE MEASURED, each of which would have
produced a wrong answer if assumed:

  * STATUSES ARE RANGES. There is no `200` and no `default`: responses are keyed
    `2XX`, `4XX`, `5XX`, plus exact codes such as `204`. An exact code wins over
    its range, and a 2xx the spec does not list is a finding rather than being
    swallowed by an error schema.
  * `@odata.type` IS MARKED REQUIRED ON EVERY ENTITY, and real Graph does not
    send it on ordinary reads. Evidence, not assumption: the captured real-tenant
    fixture e2e/differential/testdata/fixtures/graph-user-shape.json is Graph's
    COMPLETE default key set, and it contains `@odata.context` and no
    `@odata.type`. So a required `@odata.*` name is never reported.
  * PATHS COLLIDE. `/users/delta()` also matches `/users/{user-id}`; the most
    specific template wins, not the first.

Usage:
    check_graph_conformance.py <recording.jsonl> [more.jsonl ...]
    check_graph_conformance.py <recording.jsonl> --strict   exit non-zero on findings
"""
import argparse
import collections
import gzip
import hashlib
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC_DIR = ROOT / "third_party" / "msgraph-openapi"
SPEC = SPEC_DIR / "openapi-v1.0.json.gz"
PIN = SPEC_DIR / "pin.json"

# Disagreements this tree still has, pinned so a NEW one fails.
#
# An entry is a SUBSTRING of the finding text and carries the reason. Adding one
# is a claim that the disagreement is known and unadjudicated; the list is
# auditable, and it is meant to shrink. See fabric-emulator's, which went from
# eleven to one.
KNOWN: dict[str, str] = {
    # THE SPEC IS THE OUTLIER HERE, and the emulator deliberately follows the
    # service. Microsoft's ODataError.innerError.date carries a pattern that
    # requires a `Z` or an offset; the emulator emits `2026-09-19T16:12:03`, a
    # local timestamp with none. That is on purpose: internal/httpx/httpx.go
    # records that "Entra's own format here is a local timestamp with no zone
    # offset", written while diffing four real Graph errors, and it matches the
    # error bodies real Graph returns in the wild.
    #
    # PINNED RATHER THAN FIXED because "fixing" it would make the emulator agree
    # with the document and disagree with the service, which is the wrong way
    # round for an emulator. What would settle it is a raw (un-normalised)
    # capture: e2e/differential replaces every timestamp with `{timestamp}`, so
    # the real zone format is not preserved in the fixtures. That is the honest
    # open item, and it is the same axis disagreement docs/23 describes: the
    # oidf: witnesses judge against the spec, the diff: witnesses against Entra.
    ".error.innerError.date:":
        "spec's pattern requires a zone; real Graph sends none. Follows the service.",
    # AN OPEN QUESTION, NOT A DEFENSE. signIn.userId is `type: string` and not
    # nullable in the spec, and Microsoft's signIn docs give no value for it when
    # there is no user, so this cannot be settled from anything public. The
    # emulator returns null for two kinds of row: a client-credentials exchange
    # (e2e/graph asserts these ARE listed, so it is a deliberate design) and a
    # failed sign-in for a user that does not exist. Real v1.0 signIns are user
    # sign-ins, so listing service-principal exchanges at all is a further
    # divergence that this pin does not cover. Neither is fixed by inventing a
    # value: a guessed zero GUID would satisfy the schema and assert something
    # nobody has measured. Needs a tenant capture.
    "GET /auditLogs/signIns.value[].userId: is null":
        "no public statement of userId for a user-less sign-in; needs a tenant capture.",
}

HTTP_METHODS = ("get", "post", "put", "patch", "delete")

TYPES = {
    "string": str, "integer": int, "number": (int, float),
    "boolean": bool, "array": list, "object": dict,
}

# How many entries of an array to validate. Entries share a schema, so the tenth
# is evidence of little the first did not give.
ARRAY_SAMPLE = 5

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def load_spec() -> dict:
    """Load the vendored spec, refusing one that no longer matches its pin.

    The check runs on every load rather than in a separate step, so a tampered
    file cannot be measured against by a gate that forgot to ask.
    """
    pin = json.loads(PIN.read_text())
    raw = gzip.decompress(SPEC.read_bytes())
    if hashlib.sha256(raw).hexdigest() != pin["derived_json_sha256"]:
        sys.exit(f"{SPEC} does not match pin.json: the vendored spec was modified. "
                 "Run scripts/vendor_graph_spec.py --verify.")
    return json.loads(raw)


class Spec:
    """Microsoft's Graph OpenAPI, indexed for matching a recorded request."""

    def __init__(self, doc: dict):
        self.doc = doc
        # THE SPEC'S PATHS CARRY NO VERSION PREFIX. `/users/{user-id}` is the
        # template and `https://graph.microsoft.com/v1.0` is the server, so a
        # recorded `/v1.0/users/abc` has to lose its `/v1.0` before it can match
        # anything. Read from the document rather than hardcoded, so it is
        # whatever Microsoft says. Forgetting this made every one of the first 46
        # "findings" this checker ever printed a false one.
        server = (doc.get("servers") or [{}])[0].get("url", "")
        self.base = "/" + server.split("://", 1)[-1].partition("/")[2].strip("/")
        if self.base == "/":
            self.base = ""
        self.schemas = doc["components"]["schemas"]
        self.responses = doc["components"].get("responses", {})
        # (method, segment count) -> [(literal chars, params, regex, template, responses)]
        # so a recorded request is compared with dozens of templates, not 17,870.
        self.index: dict[tuple[str, int], list] = collections.defaultdict(list)
        self.operations = 0
        for template, item in doc["paths"].items():
            key = template.split("?")[0]
            n = key.count("/")
            params = re.findall(r"\{[^}]+\}", key)
            literal = len(re.sub(r"\{[^}]+\}", "", key))
            # Literal text is escaped: paths carry `$ref`, `$count`, `.` and
            # `()`, and matching them as regex metacharacters would let `$ref`
            # match nothing and `microsoft.graph.delta()` match almost anything.
            pattern = re.compile("^" + "".join(
                "[^/]+" if part.startswith("{") else re.escape(part)
                for part in re.split(r"(\{[^}]+\})", key) if part) + "$")
            for method in HTTP_METHODS:
                if method in item:
                    self.operations += 1
                    self.index[(method.upper(), n)].append(
                        (literal, len(params), pattern, key, item[method].get("responses", {})))
        for bucket in self.index.values():
            # Most literal text first, then fewest parameters: `/users/delta()`
            # must beat `/users/{user-id}`.
            bucket.sort(key=lambda r: (-r[0], r[1]))

    def match(self, method: str, path: str):
        if self.base and path.startswith(self.base + "/"):
            path = path[len(self.base):]
        else:
            return None, None  # not under the documented base: not a Graph path
        for _lit, _n, pattern, template, responses in self.index.get((method, path.count("/")), ()):
            if pattern.match(path):
                return template, responses
        return None, None

    def deref(self, node, depth=0):
        """Resolve a local $ref. Graph's spec is one document, so refs are local."""
        while isinstance(node, dict) and "$ref" in node and depth < 20:
            ref = node["$ref"]
            if not ref.startswith("#/components/"):
                return {}
            _, _, kind, name = ref.split("/", 3)
            node = (self.schemas if kind == "schemas" else self.responses).get(name, {})
            depth += 1
        return node

    def allows_null(self, schema, depth=0) -> bool:
        schema = self.deref(schema)
        if not isinstance(schema, dict) or depth > 8:
            return False
        if schema.get("nullable"):
            return True
        for key in ("anyOf", "oneOf"):
            if any(self.allows_null(b, depth + 1) for b in schema.get(key, [])):
                return True
        return any(self.allows_null(b, depth + 1) for b in schema.get("allOf", []))


def documented_response(responses: dict, status: int):
    """The spec's entry for a status: an exact code wins over its range."""
    for key in (str(status), f"{status // 100}XX"):
        if key in responses:
            return key, responses[key]
    return None, None


class Findings:
    def __init__(self):
        self.items: list[str] = []
        self.skipped_patterns = 0


def _check_scalar(value, schema, where, out: list):
    """type / enum / pattern / format / bounds for one non-container value."""
    choices = schema.get("enum")
    if choices and isinstance(value, (str, int)) and not isinstance(value, bool) and value not in choices:
        out.append(f"{where}: {value!r} is not in the spec's enum {choices}")
    if isinstance(value, str):
        pattern = schema.get("pattern")
        if pattern:
            try:
                if not re.search(pattern, value):
                    out.append(f"{where}: {value!r} does not match the spec's pattern {pattern}")
            except re.error:
                pass  # a pattern Python cannot express is skipped, not guessed at
        elif schema.get("format") == "uuid" and not UUID_RE.match(value):
            out.append(f"{where}: {value!r} is not a UUID")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        lo, hi = schema.get("minimum"), schema.get("maximum")
        if lo is not None and value < lo:
            out.append(f"{where}: {value} is below the spec's minimum {lo}")
        if hi is not None and value > hi:
            out.append(f"{where}: {value} is above the spec's maximum {hi}")


def validate(value, schema, spec: Spec, where: str, out: list, depth=0):
    """Append a finding for every way `value` disagrees with `schema`."""
    schema = spec.deref(schema)
    if not isinstance(schema, dict) or depth > 30:
        return

    if value is None:
        if not spec.allows_null(schema):
            out.append(f"{where}: is null, and the spec does not mark it nullable")
        return

    for sub in schema.get("allOf", []):
        validate(value, sub, spec, where, out, depth + 1)

    # anyOf / oneOf: clean if ANY branch is clean. If none is, report the closest
    # branch (fewest findings) rather than every branch's, which would be noise.
    for key in ("anyOf", "oneOf"):
        branches = schema.get(key)
        if branches:
            attempts = []
            for b in branches:
                found: list = []
                validate(value, b, spec, where, found, depth + 1)
                if not found:
                    attempts = None
                    break
                attempts.append(found)
            if attempts:
                closest = min(attempts, key=len)
                out.extend(f"{f} (closest of {len(branches)} alternatives)" for f in closest)

    expected = schema.get("type")
    if expected in TYPES:
        ok = isinstance(value, TYPES[expected])
        # A bool is an int in Python, and reporting `true` as a bad integer would
        # be this checker's own type system leaking into its findings.
        if isinstance(value, bool) and expected in ("integer", "number"):
            ok = False
        if not ok:
            out.append(f"{where}: type is {type(value).__name__}, spec says {expected}")
            return

    if isinstance(value, dict):
        for name in schema.get("required", []):
            # NEVER an `@odata.*` name. See the module docstring: measured against
            # a real tenant, the spec's required `@odata.type` is not sent.
            if name not in value and not name.startswith("@odata."):
                out.append(f"{where}: MISSING required property '{name}'")
        for name, sub in (schema.get("properties") or {}).items():
            if name in value:
                validate(value[name], sub, spec, f"{where}.{name}", out, depth + 1)
    elif isinstance(value, list):
        item = schema.get("items")
        if item:
            # `[]`, not `[3]`. Entries share a schema, so the same defect in five
            # rows is ONE disagreement, and printing it five times is the crying
            # wolf that gets a checker muted. It also lets a KNOWN pin name the
            # property without guessing which row provoked it.
            for entry in value[:ARRAY_SAMPLE]:
                validate(entry, item, spec, f"{where}[]", out, depth + 1)
    else:
        _check_scalar(value, schema, where, out)


def read_recording(path: pathlib.Path):
    """One JSON object per line; a truncated final line is skipped, not fatal."""
    entries = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


def conformance(entries, spec: Spec):
    """(findings, matched) for a recording."""
    found, matched = [], 0
    for e in entries:
        method, path, status = e["method"], e["path"], e["status"]
        template, responses = spec.match(method, path)
        if template is None:
            found.append(f"{method} {path}: UNDOCUMENTED ROUTE, the spec has no such operation")
            continue
        matched += 1
        where = f"{method} {template}"
        key, documented = documented_response(responses, status)
        if documented is None:
            found.append(f"{where}: answered {status}, spec documents {sorted(responses)}")
            continue
        documented = spec.deref(documented)
        body = e.get("body")
        if body is None:
            continue
        content = (documented.get("content") or {}).get("application/json") or {}
        schema = content.get("schema")
        if schema:
            validate(body, schema, spec, where, found)
    return found, matched


def is_known(finding):
    return any(pin in finding for pin in KNOWN)


def stale_pins(raw):
    """KNOWN entries no finding matches any more. Reported, never fatal: a pin is
    silent when its route was not exercised, which happens whenever one suite
    runs alone, and failing on that would turn an unrelated gap into a second,
    more confusing failure."""
    return sorted(pin for pin in KNOWN if not any(pin in f for f in raw))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("recordings", nargs="+", type=pathlib.Path,
                    help="JSONL files written by RECORD_RESPONSES")
    ap.add_argument("--strict", action="store_true", help="exit non-zero on any finding")
    a = ap.parse_args()

    present = [r for r in a.recordings if r.is_file()]
    if not present:
        print("check_graph_conformance: no recording at "
              + ", ".join(map(str, a.recordings))
              + ". Set RECORD_RESPONSES on the emulator and re-run a suite.", file=sys.stderr)
        return 1

    spec = Spec(load_spec())
    # THE UNION: each suite drives a slice, and a disagreement is a disagreement
    # whichever suite happened to provoke it.
    entries = [e for r in present for e in read_recording(r)]
    if not entries:
        print("check_graph_conformance: the recording is empty. A suite that records "
              "nothing proves nothing, so this is a failure rather than a pass.",
              file=sys.stderr)
        return 1

    raw, matched = conformance(entries, spec)
    # NOTHING MATCHING AT ALL IS A DIFFERENT FAULT FROM MANY DISAGREEMENTS. It
    # means the recorded paths and the spec's templates are not speaking the same
    # language, which is a bug in the matching or the recorder, and reporting it
    # as dozens of "undocumented routes" sends a reader to fix an emulator that
    # is fine. Refused outright, strict or not.
    if matched == 0:
        print(f"check_graph_conformance: 0 of {len(entries)} recorded responses matched "
              f"ANY of the {spec.operations} documented operations. That is a path-"
              f"matching problem, not {len(entries)} defects. Recorded, for example: "
              f"{entries[0]['method']} {entries[0]['path']}; the spec's base path is "
              f"{spec.base!r}.", file=sys.stderr)
        return 1
    occurrences = collections.Counter(raw)
    found = [f for f in occurrences if not is_known(f)]
    pinned = sum(n for f, n in occurrences.items() if is_known(f))

    print(f"check_graph_conformance: {len(entries)} recorded responses from "
          f"{len(present)} recording(s), {matched} matched to one of "
          f"{spec.operations} documented operations")
    if pinned:
        print(f"  {pinned} known disagreement(s) pinned in KNOWN, not counted")
    stale = stale_pins(raw)
    if stale:
        print(f"\n  {len(stale)} pinned disagreement(s) did not occur in this run. Not a "
              "failure, but if the defect is gone, delete the entry:")
        for pin in stale:
            print(f"    - {pin}")

    if not found:
        print("no conformance findings")
        return 0

    print(f"\ncheck_graph_conformance: {len(found)} distinct finding(s), a response "
          f"disagrees with Microsoft's published schema:\n")
    for f in sorted(found):
        n = occurrences[f]
        print(f"  - {f}" + (f"  ({n} responses)" if n > 1 else ""))
    print("\n  -> correct the response, or pin it in KNOWN with the reason it is deliberate.")
    return 1 if a.strict else 0


if __name__ == "__main__":
    sys.exit(main())
