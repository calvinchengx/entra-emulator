#!/usr/bin/env python3
"""Emit the numbers this repo can honestly claim, for the badges and the landing page.

Self-hosted on purpose: no third-party coverage service, no upload token, no
account. CI computes the numbers, this writes them as JSON, and the docs site
serves them from its own origin — so a published number is exactly as
trustworthy as the site, and nothing about the project leaves it.

Two documents, deliberately in two schemas:

  witnesses.json           a shields.io `endpoint` badge document ("55/55").
                           README.md renders it. Its schema is shields', so it
                           has room for one string and no room for detail.

  witnesses-manifest.json  this project's own schema, for site/index.html.
                           Carries the tier split and the ledger grades, which
                           a badge cannot hold.

WHY THE LANDING PAGE FETCHES RATHER THAN HARDCODES: a number typed into a page
has no idea a witness was added. The sibling data-agent-service had three go
stale in one day. The page's fallback is an em dash, never a number, so a
manifest it cannot read makes it say nothing rather than something untrue.

THE PARSING RULES COME FROM check_witnesses.py BY IMPORT, NOT BY COPY. Which
parity sections make a capability claim is that script's business, and it is
the one with teeth. A badge that disagrees with the gate is worse than no
badge. (This used to scrape the skip list out of the checker's source with a
regex and ast.literal_eval, which was the same intent held together with
string matching.)

A go-coverage document is written only when CI passes --go. This repo does not
measure coverage today, so it publishes the witness documents alone rather than
a badge reading "n/a", which would take up space to say nothing.

Usage:
    coverage_badges.py --out DIR [--go PCT]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_witnesses  # noqa: E402  (after the path insert, by necessity)

REPO = Path(__file__).resolve().parents[1]
WITNESSES = REPO / "docs" / "witnesses.json"

# The ledger's emoji are unreadable as JSON keys.
GRADE_NAMES = {"🟢": "real", "🟡": "emulated", "🟠": "bring-your-own-engine", "🔴": "not-implemented"}


def colour_for(pct: float) -> str:
    """Deliberately not flattering: a repo enforcing a high floor should not
    paint a mediocre number green."""
    if pct >= 95:
        return "brightgreen"
    if pct >= 90:
        return "green"
    if pct >= 80:
        return "yellow"
    return "orange"


def badge(label: str, message: str, colour: str) -> dict:
    return {"schemaVersion": 1, "label": label, "message": message, "color": colour}


# Strongest evidence first; each claim is counted once, under the first of these
# it cites. diff: leads because it is the only kind that evidences parity with
# real Entra rather than client compatibility; oidf: sits beside it as a
# different axis (conformance to the specification) rather than a weaker one.
# Keep in step with the kinds documented in scripts/check_witnesses.py.
TIERS = ("diff", "oidf", "ci", "sdk", "go", "boundary")


def survey() -> dict:
    """Everything both documents need, computed once from the parity map.

    Counting the MAP rather than the manifest is the point: a claim added to
    the map with no entry in witnesses.json must show as unwitnessed, not
    vanish from both numerator and denominator and leave the badge perfect.

    `by_tier` counts each claim ONCE, by its strongest witness. That is not the
    same number as the checker's per-witness tally and must never be reported
    as if it were: one claim can cite four witnesses, so counting citations
    flatters every repo. 52 claims whose best evidence is a CI job is a
    statement about coverage; 58 `ci:` citations is a statement about nothing.
    """
    manifest = json.loads(WITNESSES.read_text()) if WITNESSES.exists() else {}
    # Every witness kind check_witnesses.py accepts must appear in TIERS, or a
    # claim citing only that kind counts as witnessed and lands in no tier, so
    # the tiers silently stop summing to `witnessed`. That is exactly what
    # happened when diff: was introduced: one claim was witnessed by four
    # differential scenarios and reported under no tier at all. `unknown`
    # catches the next one instead of hiding it.
    tiers = {t: 0 for t in TIERS}
    tiers.update(unknown=0, unwitnessed=0)
    suites: dict[str, int] = {}
    unknown_kinds: set[str] = set()
    total = witnessed = 0

    for _section, _feature, key in check_witnesses.green_claims():
        total += 1
        cited = [w for w in (manifest.get(key) or {}).get("witnesses", []) if w != "TODO"]
        if not cited:
            tiers["unwitnessed"] += 1
            continue
        witnessed += 1
        kinds = {w.partition(":")[0] for w in cited}
        for tier in TIERS:
            if tier in kinds:
                tiers[tier] += 1
                break
        else:
            tiers["unknown"] += 1
            unknown_kinds.update(kinds)
        for w in cited:
            if w.startswith("ci:"):
                suites[w] = suites.get(w, 0) + 1

    grades = {GRADE_NAMES[e]: n for e, n in check_witnesses.grade_counts().items()}
    return {
        "claims": total,
        "witnessed": witnessed,
        "by_tier": tiers,
        "unknown_kinds": sorted(unknown_kinds),
        "grades": grades,
        "suites": dict(sorted(suites.items(), key=lambda kv: (-kv[1], kv[0]))),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--go", default="")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    if args.go:
        pct = float(args.go)
        doc = badge("go coverage", f"{pct:.1f}%", colour_for(pct))
        (out / "coverage-go.json").write_text(json.dumps(doc) + "\n")
        shown = doc["message"]
    else:
        shown = "not written"

    s = survey()
    if not s["claims"]:
        print("FAIL: parsed 0 green claims from docs/parity.md — the map is not "
              "empty, so this is a parsing failure and the badge would lie.")
        return 1

    colour = "brightgreen" if s["witnessed"] == s["claims"] else "orange"
    (out / "witnesses.json").write_text(
        json.dumps(badge("parity claims witnessed", f"{s['witnessed']}/{s['claims']}", colour)) + "\n")
    (out / "witnesses-manifest.json").write_text(json.dumps(s, indent=2) + "\n")

    t = s["by_tier"]
    print(f"badges: go={shown} witnesses={s['witnessed']}/{s['claims']} → {out}")
    print("  by strongest witness: "
          + " ".join(f"{k}={t[k]}" for k in (*TIERS, "unwitnessed")))
    print(f"  ledger grades: {s['grades']}")

    if t["unknown"]:
        print(f"FAIL: {t['unknown']} claim(s) cite only witness kinds this script "
              f"does not rank: {', '.join(s['unknown_kinds'])}. They count as "
              "witnessed but appear under no tier, so the tiers no longer sum to "
              "the total. Add the kind to TIERS.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
