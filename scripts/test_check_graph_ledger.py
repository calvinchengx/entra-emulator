"""Controls for scripts/check_graph_ledger.py.

A ratchet that never fires is indistinguishable from a healthy tree, so each way
the gate can fail is provoked here and required to fail. Runs against the real
vendored spec with synthetic route lists, so the assertions are about this
script's logic and not about which routes the emulator happens to register today.

Run:  uv run --no-project --python 3.12 python -m unittest scripts/test_check_graph_ledger.py
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
sys.path.insert(0, str(HERE))
_spec = importlib.util.spec_from_file_location("ledger", HERE / "check_graph_ledger.py")
ledger = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ledger)

USERS = ["GET /v1.0/users", "GET /v1.0/users/{id}", "POST /v1.0/users"]


def classify(routes, recordings=()):
    return ledger.classify(recordings, routes)


class Shape(unittest.TestCase):
    def test_parameter_names_are_ignored(self):
        # The spec says {user-id}, the emulator says {id}: the same route.
        self.assertEqual(ledger.shape("/users/{user-id}/memberOf"), ledger.shape("/users/{id}/memberOf"))

    def test_a_literal_segment_stays_literal(self):
        # `/users/$count` and `/users/{id}` are DIFFERENT operations. A wildcard
        # that happens to swallow `$count` does not serve it.
        self.assertNotEqual(ledger.shape("/users/$count"), ledger.shape("/users/{id}"))


class Classification(unittest.TestCase):
    def test_a_matching_route_is_served_and_a_stranger_is_silent(self):
        states, _ = classify(USERS)
        self.assertEqual(states["GET /users"], "served")
        self.assertEqual(states["GET /users/{user-id}"], "served")
        self.assertEqual(states["DELETE /users/{user-id}"], "silent")

    def test_a_wildcard_does_not_serve_a_literal_operation(self):
        states, _ = classify(USERS)
        self.assertEqual(states["GET /users/$count"], "silent")

    def test_method_matters(self):
        states, _ = classify(["GET /v1.0/users"])
        self.assertEqual(states["GET /users"], "served")
        self.assertEqual(states["POST /users"], "silent")

    def test_a_recorded_404_makes_an_unserved_operation_refused(self):
        with tempfile.TemporaryDirectory() as d:
            rec = pathlib.Path(d) / "r.jsonl"
            rec.write_text(json.dumps({"method": "GET", "status": 404,
                                       "path": "/v1.0/users/abc/todo/lists"}) + "\n")
            states, _ = classify(["GET /v1.0/users"], [str(rec)])
        self.assertEqual(states["GET /users/{user-id}/todo/lists"], "refused")

    def test_served_beats_refused(self):
        # A 404 on a SERVED route is "user not found", not "route not served".
        with tempfile.TemporaryDirectory() as d:
            rec = pathlib.Path(d) / "r.jsonl"
            rec.write_text(json.dumps({"method": "GET", "status": 404, "path": "/v1.0/users/nope"}) + "\n")
            states, _ = classify(USERS, [str(rec)])
        self.assertEqual(states["GET /users/{user-id}"], "served")


class ReverseDirection(unittest.TestCase):
    def test_a_route_the_spec_does_not_have_is_reported_as_invented(self):
        # This is the class the resetPassword bug belonged to.
        _, inv = classify(USERS + ["POST /v1.0/users/{id}/authentication/passwordMethods/{m}/resetPassword"])
        self.assertEqual(inv, ["POST /v1.0/users/{id}/authentication/passwordMethods/{m}/resetPassword"])

    def test_the_documented_spelling_is_not_invented(self):
        _, inv = classify(USERS + ["POST /v1.0/users/{id}/authentication/methods/{m}/resetPassword"])
        self.assertEqual(inv, [])

    def test_oidc_routes_are_outside_the_spec_not_invented(self):
        _, inv = classify(USERS + ["GET /oidc/userinfo"])
        self.assertEqual(inv, [])

    def test_a_generic_route_that_serves_a_documented_operation_is_credited(self):
        route = "GET /v1.0/{key}"
        states, inv = classify(USERS + [route])
        self.assertEqual(states["GET /servicePrincipals(appId='{appId}')"], "served")
        self.assertNotIn(route, inv)

    def test_the_credit_disappears_with_the_route(self):
        states, _ = classify(USERS)
        self.assertEqual(states["GET /servicePrincipals(appId='{appId}')"], "silent")


class Gate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        self._baseline = ledger.BASELINE
        ledger.BASELINE = self.dir / "baseline.json"
        self._known = dict(ledger.KNOWN_INVENTED)
        ledger.KNOWN_INVENTED.clear()

    def tearDown(self):
        ledger.BASELINE = self._baseline
        ledger.KNOWN_INVENTED.clear()
        ledger.KNOWN_INVENTED.update(self._known)
        self.tmp.cleanup()

    def routes(self, lines):
        f = self.dir / "routes.txt"
        f.write_text("\n".join(lines) + "\n")
        return str(f)

    def go(self, lines, update=False):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            rc = ledger.run([], True, update, self.routes(lines))
        return rc, out.getvalue()

    def test_a_fresh_baseline_then_no_change_agrees(self):
        self.assertEqual(self.go(USERS, update=True)[0], 0)
        self.assertEqual(self.go(USERS)[0], 0)

    def test_a_missing_baseline_fails_strict(self):
        rc, text = self.go(USERS)
        self.assertEqual(rc, 1)
        self.assertIn("no baseline", text)

    def test_a_route_that_stops_being_served_fails(self):
        self.go(USERS, update=True)
        rc, text = self.go(USERS[:2])
        self.assertEqual(rc, 1)
        self.assertIn("no longer served", text)

    def test_a_newly_served_route_fails_until_recorded(self):
        # The improvement that does not update the file leaves a lie in it.
        self.go(USERS[:2], update=True)
        rc, text = self.go(USERS)
        self.assertEqual(rc, 1)
        self.assertIn("newly served", text)

    def test_an_invented_route_fails_even_with_a_perfect_baseline(self):
        bad = USERS + ["POST /v1.0/users/{id}/authentication/passwordMethods/{m}/resetPassword"]
        self.go(bad, update=True)
        rc, text = self.go(bad)
        self.assertEqual(rc, 1)
        self.assertIn("INVENTED ROUTE", text)

    def test_an_invented_route_is_reported_even_with_no_baseline(self):
        # The first version returned early on a missing baseline and hid these.
        rc, text = self.go(USERS + ["GET /v1.0/notAResource"])
        self.assertEqual(rc, 1)
        self.assertIn("INVENTED ROUTE", text)

    def test_a_pin_silences_only_what_it_names(self):
        ledger.KNOWN_INVENTED["/v1.0/notAResource"] = "test"
        self.go(USERS + ["GET /v1.0/notAResource"], update=True)
        self.assertEqual(self.go(USERS + ["GET /v1.0/notAResource"])[0], 0)
        rc, _ = self.go(USERS + ["GET /v1.0/notAResource", "GET /v1.0/alsoNot"])
        self.assertEqual(rc, 1)

    def test_a_stale_pin_is_reported(self):
        ledger.KNOWN_INVENTED["/v1.0/gone"] = "test"
        self.go(USERS, update=True)
        _, text = self.go(USERS)
        self.assertIn("match no registered route", text)

    def test_no_routes_at_all_is_a_failure_not_a_clean_pass(self):
        # A silent zero would make every operation SILENT and every route look
        # absent: no routes READ is not the same as none registered.
        rc, text = self.go([])
        self.assertEqual(rc, 1)
        self.assertIn("no routes were enumerated", text)


if __name__ == "__main__":
    unittest.main()
