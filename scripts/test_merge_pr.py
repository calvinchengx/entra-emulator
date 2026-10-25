"""Controls for scripts/merge_pr.py's message building.

The merge itself needs GitHub, so what is pinned here is the part that decides
what lands: the subject gets the ` (#N)` suffix exactly once, and no trailer
line in the description survives into the body.

Run:  uv run --no-project --python 3.12 python -m unittest scripts/test_merge_pr.py
"""
import importlib.util
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
_spec = importlib.util.spec_from_file_location("merge_pr", HERE / "merge_pr.py")
merge_pr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(merge_pr)


class BuildMessage(unittest.TestCase):
    def test_subject_gets_the_number_once(self):
        self.assertEqual(merge_pr.build_message("fix: x", 7, "")[0], "fix: x (#7)")
        self.assertEqual(merge_pr.build_message("fix: x (#7)", 7, "")[0], "fix: x (#7)")

    def test_trailers_in_the_description_are_dropped(self):
        body = ("Bumps a thing.\n\nSigned-off-by: dependabot[bot] <support@github.com>\n"
                "Co-authored-by: dependabot[bot] <bot@users.noreply.github.com>\n"
                "Claude-Session: https://claude.ai/code/session_x\n")
        _, out = merge_pr.build_message("t", 1, body)
        self.assertEqual(merge_pr.offending_lines(out), [])
        self.assertIn("Signed-off-by: dependabot[bot]", out)
        self.assertTrue(out.startswith("Bumps a thing."))

    def test_empty_description(self):
        self.assertEqual(merge_pr.build_message("t", 1, None)[1], "\n")


if __name__ == "__main__":
    unittest.main()
