#!/usr/bin/env python3
"""Emit shields.io endpoint JSON for the numbers this repo can honestly claim.

Self-hosted on purpose: no third-party coverage service, no upload token, no
account. CI computes the numbers, this writes them as shields `endpoint`
documents, and the docs site serves them from its own origin — so a badge is
exactly as trustworthy as the site, and nothing about the project leaves it.

THE NUMBER THAT MATTERS:

  witnesses     parity claims that name a witness which still exists

A go-coverage document is written only when CI passes --go. This repo does not
measure coverage today, so it publishes the witness endpoint alone rather than
a badge reading "n/a", which would take up space to say nothing.

The second is the integration measure. "48/48 claims witnessed" says every
claim of support is backed by something that ran, which is precisely what a
coverage percentage cannot say: coverage scores the unit suites, while what
catches consumer-facing defects here is the real-client fleet — the six real-SDK
suites (msal-node, the Graph SDK, MSAL Go/azidentity, MSAL Python, MSAL.NET,
MSAL Java), the msal-browser witness, and Flutter on real device emulators.

THE SKIP LIST IS READ FROM check_witnesses.py, NOT COPIED. Which parity
sections make no capability claim is that script's business, and a second copy
of the list here would drift the day someone adds a section. A badge that
disagrees with the gate is worse than no badge, because the gate is the thing
with teeth.

The percentage is supplied by the caller because only CI knows it. Omit it and
no coverage document is written at all, rather than publishing an "n/a" badge
that says nothing a reader can act on.

Usage:
    coverage_badges.py --out DIR [--go PCT]
"""
from __future__ import annotations

import argparse
import ast
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
WITNESSES = REPO / "docs" / "witnesses.json"
PARITY = REPO / "docs" / "parity.md"
CHECKER = REPO / "scripts" / "check_witnesses.py"


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


def checker_rules() -> tuple[set, set]:
    """The sections and header cells the gate itself ignores."""
    skip: set = set()
    heads: set = set()
    if not CHECKER.exists():
        return skip, heads
    src = CHECKER.read_text(encoding="utf-8")
    m = re.search(r"SKIP_SECTIONS\s*=\s*(\{.*?\})", src, re.S)
    if m:
        try:
            skip = ast.literal_eval(m.group(1))
        except (ValueError, SyntaxError):
            pass
    m = re.search(r"if cells\[0\] in \(([^)]*)\)", src)
    if m:
        try:
            heads = set(ast.literal_eval("(" + m.group(1) + ",)"))
        except (ValueError, SyntaxError):
            pass
    return skip, heads


def witness_counts() -> tuple[int, int]:
    """(claims that are witnessed, total green claims in the parity map).

    Counting the MAP rather than the manifest is the point: a claim added to
    the map with no entry here must show as unwitnessed, not vanish from both
    numerator and denominator and leave the badge looking perfect.
    """
    manifest = json.loads(WITNESSES.read_text()) if WITNESSES.exists() else {}
    skip, heads = checker_rules()
    total = witnessed = 0
    section = None
    for line in PARITY.read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            section = line[3:].strip()
            continue
        if not line.startswith("| ") or section is None or section in skip:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 3 or cells[0] in heads or set(cells[0]) <= set("-"):
            continue
        if "🟢" not in cells[-1]:
            continue
        total += 1
        text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", cells[0])
        text = re.sub(r"[*`_]", "", text)
        key = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
        entry = manifest.get(key) or {}
        if entry.get("witnesses"):
            witnessed += 1
    return witnessed, total


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

    witnessed, total = witness_counts()
    if not total:
        print("FAIL: parsed 0 green claims from docs/parity.md — the map is not "
              "empty, so this is a parsing failure and the badge would lie.")
        return 1
    colour = "brightgreen" if witnessed == total else "orange"
    (out / "witnesses.json").write_text(
        json.dumps(badge("parity claims witnessed", f"{witnessed}/{total}", colour)) + "\n")

    print(f"badges: go={shown} witnesses={witnessed}/{total} → {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
