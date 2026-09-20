"""Controls for scripts/check_graph_route_coverage.py.

A ratchet that never fires is indistinguishable from a healthy tree, so each way
the gate can fail is provoked here and required to fail. Routes are synthetic
where the assertion is about this script's logic, and REAL (enumerated from the
emulator) where it is about whether the script's model of http.ServeMux agrees
with the table it is modelling.

Run:  uv run --no-project --python 3.12 python -m unittest scripts/test_check_graph_route_coverage.py
"""
import contextlib
import importlib.util
import io
import json
import pathlib
import re
import shutil
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
_spec = importlib.util.spec_from_file_location("ratchet", HERE / "check_graph_route_coverage.py")
ratchet = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ratchet)

ROUTES = [
    "GET /v1.0/users",
    "GET /v1.0/users/{id}",
    "DELETE /v1.0/users/{id}",
    "GET /v1.0/directory/deletedItems/graph.user",
    "GET /v1.0/directory/deletedItems/{id}",
    "GET /oidc/userinfo",
]


def hit(method, path, status=200):
    return {"method": method, "path": path, "status": status}


class Resolve(unittest.TestCase):
    def test_a_literal_beats_a_wildcard(self):
        # `/deletedItems/graph.user` must take the credit for a request to it, not
        # the `{id}` wildcard beside it. ServeMux's precedence; without it the
        # literal alias route could never be seen as driven.
        got = ratchet.resolve(ROUTES, "GET", "/v1.0/directory/deletedItems/graph.user")
        self.assertEqual(got, "GET /v1.0/directory/deletedItems/graph.user")
        got = ratchet.resolve(ROUTES, "GET", "/v1.0/directory/deletedItems/1234")
        self.assertEqual(got, "GET /v1.0/directory/deletedItems/{id}")

    def test_method_and_length_must_match(self):
        self.assertIsNone(ratchet.resolve(ROUTES, "POST", "/v1.0/users"))
        self.assertIsNone(ratchet.resolve(ROUTES, "GET", "/v1.0/users/1/extra"))

    def test_a_wildcard_matches_exactly_one_segment(self):
        self.assertEqual(ratchet.resolve(ROUTES, "GET", "/v1.0/users/abc"), "GET /v1.0/users/{id}")

    def test_the_real_route_table_resolves_to_itself(self):
        # The one check that tests the MODEL against the thing modelled. For every
        # route the emulator really registers, a concrete request built from it
        # must resolve back to that same route. A precedence bug in resolve() shows
        # up here as a route that another route steals, which is a route that could
        # never be reported as driven.
        if shutil.which("go") is None:
            self.skipTest("go is not installed")
        routes = ratchet.in_scope_routes(ratchet.ledger.registered_routes())
        self.assertGreater(len(routes), 50)
        for route in routes:
            method, _, pattern = route.partition(" ")
            concrete = re.sub(r"\{[^}]+\}", "x", pattern)
            self.assertEqual(ratchet.resolve(routes, method, concrete), route, concrete)


class Measure(unittest.TestCase):
    def test_only_a_2xx_counts_as_driven(self):
        # A 401 or a 404 shows a route exists, not that it works.
        exercised, _ = ratchet.measure(ROUTES, [hit("GET", "/v1.0/users", 401)])
        self.assertEqual(exercised, set())
        exercised, _ = ratchet.measure(ROUTES, [hit("GET", "/v1.0/users/abc", 404)])
        self.assertEqual(exercised, set())
        exercised, _ = ratchet.measure(ROUTES, [hit("GET", "/v1.0/users", 200)])
        self.assertEqual(exercised, {"GET /v1.0/users"})
        exercised, _ = ratchet.measure(ROUTES, [hit("DELETE", "/v1.0/users/abc", 204)])
        self.assertEqual(exercised, {"DELETE /v1.0/users/{id}"})

    def test_a_served_response_matching_no_route_is_orphaned(self):
        # The oracle that does not trust the enumeration.
        _, orphaned = ratchet.measure(ROUTES, [hit("GET", "/v1.0/notAResource", 200)])
        self.assertEqual(list(orphaned), ["GET /v1.0/notAResource"])

    def test_a_404_on_an_unregistered_route_is_not_orphaned(self):
        # Being told no is the normal way for an unrouted request to end.
        _, orphaned = ratchet.measure(ROUTES, [hit("GET", "/v1.0/notAResource", 404)])
        self.assertEqual(orphaned, {})

    def test_a_5xx_on_an_unregistered_route_is_not_orphaned(self):
        _, orphaned = ratchet.measure(ROUTES, [hit("GET", "/v1.0/notAResource", 502)])
        self.assertEqual(orphaned, {})

    def test_out_of_scope_routes_are_not_counted(self):
        # OIDC userinfo is on the Graph host but is not /v1.0, and is not recorded.
        self.assertNotIn("GET /oidc/userinfo", ratchet.in_scope_routes(ROUTES))


class Gate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        self._baseline = ratchet.BASELINE
        ratchet.BASELINE = self.dir / "baseline.json"

    def tearDown(self):
        ratchet.BASELINE = self._baseline
        self.tmp.cleanup()

    def go(self, hits, routes=ROUTES, update=False):
        rt = self.dir / "routes.txt"
        rt.write_text("\n".join(routes) + "\n")
        rec = self.dir / "rec.jsonl"
        rec.write_text("".join(json.dumps(h) + "\n" for h in hits))
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            rc = ratchet.run([str(rec)], True, update, str(rt))
        return rc, out.getvalue()

    BASE = [hit("GET", "/v1.0/users"), hit("GET", "/v1.0/users/a")]

    def test_a_fresh_baseline_then_no_change_agrees(self):
        self.assertEqual(self.go(self.BASE, update=True)[0], 0)
        self.assertEqual(self.go(self.BASE)[0], 0)

    def test_a_missing_baseline_fails(self):
        rc, text = self.go(self.BASE)
        self.assertEqual(rc, 1)
        self.assertIn("no baseline", text)

    def test_a_new_route_with_no_traffic_fails(self):
        self.go(self.BASE, update=True)
        rc, text = self.go(self.BASE, routes=ROUTES + ["POST /v1.0/users"])
        self.assertEqual(rc, 1)
        self.assertIn("registered and not driven, and not in the baseline: POST /v1.0/users", text)

    def test_a_route_that_stops_being_driven_fails(self):
        self.go(self.BASE, update=True)
        rc, text = self.go([hit("GET", "/v1.0/users")])
        self.assertEqual(rc, 1)
        self.assertIn("GET /v1.0/users/{id}", text)

    def test_a_route_that_starts_being_driven_fails_until_recorded(self):
        # The improvement that does not update the file leaves a lie in it.
        self.go(self.BASE, update=True)
        rc, text = self.go(self.BASE + [hit("DELETE", "/v1.0/users/a", 204)])
        self.assertEqual(rc, 1)
        self.assertIn("now driven, but the baseline still lists it", text)

    def test_a_baseline_entry_for_a_removed_route_fails(self):
        self.go(self.BASE, update=True)
        rc, text = self.go(self.BASE, routes=[r for r in ROUTES if "DELETE" not in r])
        self.assertEqual(rc, 1)
        self.assertIn("no longer registered", text)

    def test_an_orphaned_response_fails_even_with_a_perfect_baseline(self):
        self.go(self.BASE, update=True)
        rc, text = self.go(self.BASE + [hit("GET", "/v1.0/mystery", 200)])
        self.assertEqual(rc, 1)
        self.assertIn("ORPHANED", text)

    def test_no_recorded_responses_is_a_failure_not_a_clean_pass(self):
        rc, text = self.go([])
        self.assertEqual(rc, 1)
        self.assertIn("recorded nothing", text)

    def test_a_missing_recording_is_named_not_a_traceback(self):
        rt = self.dir / "routes.txt"
        rt.write_text("\n".join(ROUTES) + "\n")
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            rc = ratchet.run([str(self.dir / "nope.jsonl")], True, False, str(rt))
        self.assertEqual(rc, 1)
        self.assertIn("no such recording", out.getvalue())

    def test_no_routes_at_all_is_a_failure_not_100_percent(self):
        rc, text = self.go(self.BASE, routes=[])
        self.assertEqual(rc, 1)
        self.assertIn("no routes were enumerated", text)


if __name__ == "__main__":
    unittest.main()
