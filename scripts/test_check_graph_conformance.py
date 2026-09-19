"""Controls for scripts/check_graph_conformance.py.

WHY A CHECKER NEEDS ITS OWN TESTS. It reported almost nothing across 67 real
responses, and "the emulator is good" and "the checker is lenient" produce the
same green output. Each rule class below is fed a response known to break it, and
must fail; a checker that cannot fail proves nothing. They run against the real
vendored Graph spec rather than a hand-written stand-in, because a stand-in would
test this file's assumptions about the spec instead of the spec.

Run:  uv run --no-project --python 3.12 python -m unittest scripts/test_check_graph_conformance.py
"""
import contextlib
import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("checker", HERE / "check_graph_conformance.py")
checker = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(checker)

SPEC = checker.Spec(checker.load_spec())
GUID = "a98fd830-3261-4ea5-aa94-49e01ded23a2"
GOOD_ERROR = {"error": {"code": "Request_ResourceNotFound", "message": "nope"}}


def check(method, path, status, body=None):
    """Findings for one recorded response, with KNOWN not applied."""
    entry = {"method": method, "path": path, "status": status}
    if body is not None:
        entry["body"] = body
    found, _ = checker.conformance([entry], SPEC)
    return found


class Status(unittest.TestCase):
    def test_a_2xx_range_accepts_any_success_code(self):
        # The spec has no `200` and no `default`, only `2XX`. Matching literal
        # codes would report every successful response as undocumented.
        self.assertEqual(check("GET", f"/v1.0/users/{GUID}", 200, {"id": GUID}), [])
        self.assertEqual(check("POST", "/v1.0/users", 201, {"id": GUID}), [])

    def test_an_exact_code_is_still_required_where_the_spec_gives_one(self):
        # DELETE documents `204`, not `2XX`. A 200 is the emulator being wrong.
        self.assertEqual(check("DELETE", f"/v1.0/users/{GUID}", 204), [])
        got = check("DELETE", f"/v1.0/users/{GUID}", 200)
        self.assertEqual(len(got), 1)
        self.assertIn("answered 200", got[0])

    def test_error_statuses_fall_in_the_4xx_range(self):
        self.assertEqual(check("GET", f"/v1.0/users/{GUID}", 404, GOOD_ERROR), [])
        self.assertEqual(check("GET", f"/v1.0/users/{GUID}", 500, GOOD_ERROR), [])

    def test_an_undocumented_status_is_a_finding(self):
        got = check("GET", f"/v1.0/users/{GUID}", 302)
        self.assertTrue(any("answered 302" in f for f in got), got)


class Routes(unittest.TestCase):
    def test_a_route_the_spec_does_not_have_is_a_finding(self):
        # This is the check that found the invented /passwordMethods/.../
        # resetPassword route, which every SDK snippet Microsoft publishes 404s on.
        got = check("POST", f"/v1.0/users/{GUID}/authentication/passwordMethods/x/resetPassword", 202)
        self.assertTrue(any("UNDOCUMENTED ROUTE" in f for f in got), got)

    def test_the_documented_resetpassword_route_matches(self):
        got = check("POST", f"/v1.0/users/{GUID}/authentication/methods/28c10230-6103-485e-b985-444c60001490/resetPassword", 202)
        self.assertEqual(got, [])

    def test_the_most_specific_template_wins(self):
        # `/users/delta()` also matches `/users/{user-id}`. First-match would
        # validate a delta response against the single-user schema.
        template, _ = SPEC.match("GET", "/v1.0/users/delta()")
        self.assertEqual(template, "/users/delta()")

    def test_literal_dollar_segments_are_not_regex_metacharacters(self):
        # `$ref` and `$count` are path text. Unescaped, `$` anchors the pattern
        # and the route matches nothing.
        template, _ = SPEC.match("POST", f"/v1.0/groups/{GUID}/members/$ref")
        self.assertEqual(template, "/groups/{group-id}/members/$ref")

    def test_a_path_outside_the_documented_base_never_matches(self):
        self.assertEqual(SPEC.match("GET", "/users"), (None, None))
        self.assertEqual(SPEC.match("GET", "/beta/users"), (None, None))


class Bodies(unittest.TestCase):
    def test_the_odata_error_envelope_is_enforced(self):
        # The spec genuinely specifies it: `error` required, then `code` and
        # `message` inside. A 404 with a bare message would break every SDK's
        # error deserialiser.
        self.assertTrue(any("MISSING required property 'error'" in f
                            for f in check("GET", f"/v1.0/users/{GUID}", 404, {})))
        self.assertTrue(any("MISSING required property 'code'" in f
                            for f in check("GET", f"/v1.0/users/{GUID}", 404, {"error": {"message": "x"}})))

    def test_null_where_the_spec_does_not_allow_it(self):
        # entity.id is a plain string; displayName is `nullable: true`.
        self.assertTrue(any("is null" in f for f in check("GET", f"/v1.0/users/{GUID}", 200, {"id": None})))
        self.assertEqual(check("GET", f"/v1.0/users/{GUID}", 200, {"id": GUID, "displayName": None}), [])

    def test_wrong_type(self):
        self.assertTrue(any("type is int" in f for f in check("GET", f"/v1.0/users/{GUID}", 200, {"displayName": 5})))
        self.assertTrue(any("type is str" in f for f in check("GET", f"/v1.0/users/{GUID}", 200, {"accountEnabled": "yes"})))

    def test_a_bool_is_not_an_integer_and_not_reported_as_one(self):
        # Python's bool subclasses int; the checker's own type system must not
        # leak into its findings.
        self.assertEqual(check("GET", f"/v1.0/users/{GUID}", 200, {"accountEnabled": True}), [])

    def test_a_datetime_pattern_is_enforced(self):
        # 220 Graph properties carry a pattern, including every datetime.
        self.assertTrue(any("does not match the spec's pattern" in f
                            for f in check("GET", f"/v1.0/users/{GUID}", 200, {"createdDateTime": "yesterday"})))
        self.assertEqual(check("GET", f"/v1.0/users/{GUID}", 200, {"createdDateTime": "2026-01-01T00:00:00Z"}), [])

    def test_an_enum_reached_through_anyof(self):
        # conditionalAccessStatus is anyOf [enum $ref, nullable object]: clean if
        # ANY branch is clean, and null is allowed by the second.
        path = "/v1.0/auditLogs/signIns"
        ok = check("GET", path, 200, {"value": [{"conditionalAccessStatus": "success"}]})
        self.assertEqual(ok, [])
        self.assertEqual(check("GET", path, 200, {"value": [{"conditionalAccessStatus": None}]}), [])
        bad = check("GET", path, 200, {"value": [{"conditionalAccessStatus": "bogus"}]})
        self.assertTrue(any("bogus" in f and "alternatives" in f for f in bad), bad)

    def test_a_required_odata_annotation_is_never_reported(self):
        # entity marks `@odata.type` required; real Graph does not send it on an
        # ordinary read (see the module docstring for the captured evidence).
        got = check("GET", f"/v1.0/users/{GUID}", 200, {"id": GUID})
        self.assertFalse(any("@odata" in f for f in got), got)

    def test_extra_properties_are_deliberately_not_findings(self):
        # `additionalProperties` appears twice in a 37 MB spec.
        self.assertEqual(check("GET", f"/v1.0/users/{GUID}", 200, {"id": GUID, "somethingElse": {"x": 1}}), [])

    def test_the_same_defect_in_many_rows_is_one_finding(self):
        rows = {"value": [{"id": None}, {"id": None}, {"id": None}]}
        got = check("GET", "/v1.0/users", 200, rows)
        # conformance() returns every occurrence and main() counts the distinct
        # ones, so what matters is that the three are the SAME string. Index-
        # bearing text (`value[0]`, `value[1]`...) would make three findings.
        self.assertEqual(len(got), 3)
        self.assertEqual(len(set(got)), 1, got)
        self.assertIn(".value[].id", got[0])


class Refusals(unittest.TestCase):
    def run_main(self, lines):
        with tempfile.TemporaryDirectory() as d:
            f = pathlib.Path(d) / "r.jsonl"
            f.write_text("".join(json.dumps(l) + "\n" for l in lines))
            argv = sys.argv
            sys.argv = ["check", str(f), "--strict"]
            err, out = io.StringIO(), io.StringIO()
            try:
                with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
                    rc = checker.main()
            finally:
                sys.argv = argv
            return rc, err.getvalue() + out.getvalue()

    def test_an_empty_recording_is_a_failure_not_a_pass(self):
        rc, _ = self.run_main([])
        self.assertEqual(rc, 1)

    def test_a_recording_where_nothing_matches_is_diagnosed_as_a_matching_fault(self):
        # This is what the first version of this checker did to itself: it forgot
        # the spec's paths carry no /v1.0 prefix, matched nothing, and reported 46
        # "defects" that were all its own.
        rc, text = self.run_main([{"method": "GET", "path": "/no/such/route", "status": 200}])
        self.assertEqual(rc, 1)
        self.assertIn("path-matching problem", text)

    def test_a_missing_recording_is_a_failure(self):
        argv = sys.argv
        sys.argv = ["check", "/nonexistent/none.jsonl"]
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(checker.main(), 1)
        finally:
            sys.argv = argv


class Pins(unittest.TestCase):
    def test_a_pin_silences_only_what_it_names(self):
        self.assertTrue(checker.is_known("GET /x.error.innerError.date: '2026' does not match"))
        self.assertFalse(checker.is_known("GET /x.error.code: is null"))

    def test_a_pin_that_matches_nothing_is_reported_stale(self):
        self.assertEqual(checker.stale_pins([]), sorted(checker.KNOWN))
        self.assertEqual(checker.stale_pins(["GET /a.error.innerError.date: x"]),
                         sorted(p for p in checker.KNOWN if ".error.innerError.date:" not in p))


if __name__ == "__main__":
    unittest.main()
