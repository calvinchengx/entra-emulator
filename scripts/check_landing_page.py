#!/usr/bin/env python3
"""The landing page tells the truth about where it points and what it ships.

site/index.html is hand-written and copied over the built site's root. Astro
never sees it, so none of the checks that protect the docs protect it: a
renamed doc, a moved anchor, a missing image or a manifest that stopped being
published would all publish silently as a broken front page.

Three checks, each from a way this can go wrong:

  links      every relative href and src resolves inside the assembled site,
             including the manifest the page fetches for its numbers
  anchors    every same-page fragment names an id that exists
  version    the release pill names the newest v* tag, so the front page cannot
             advertise a version that was superseded

The link check FAILS IF IT FINDS NOTHING TO CHECK. A regex that quietly stops
matching reports a clean run over zero links, which is indistinguishable from
success and is how this class of checker dies.

Usage:
    check_landing_page.py --site DIR      DIR is the assembled site root
    check_landing_page.py --site DIR --skip-version
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SOURCE = REPO / "site" / "index.html"

# href="..." / src="..." with a double-quoted value.
REF_RE = re.compile(r'(?:href|src)="([^"]+)"')
# The page fetches its numbers; that path is a link like any other.
FETCH_RE = re.compile(r"fetch\('([^']+)'\)")
ID_RE = re.compile(r'\sid="([^"]+)"')
PILL_RE = re.compile(r'class="release-pill"[^>]*>\s*<span>(v[0-9][^<]*)</span>')

EXTERNAL = ("http://", "https://", "mailto:", "data:", "//")


def newest_tag() -> str | None:
    out = subprocess.run(
        ["git", "-C", str(REPO), "tag", "--list", "v*", "--sort=-v:refname"],
        capture_output=True, text=True,
    )
    tags = [t for t in out.stdout.split() if t]
    return tags[0] if tags else None


def resolve(site: Path, target: str) -> Path:
    """Where a relative reference from the site root lands on disk."""
    clean = target.split("#", 1)[0].split("?", 1)[0]
    clean = clean[2:] if clean.startswith("./") else clean
    if clean in ("", "/"):
        return site / "index.html"
    path = site / clean.lstrip("/")
    return path / "index.html" if target.rstrip("#").endswith("/") else path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--site", required=True, help="the assembled site root")
    ap.add_argument("--skip-version", action="store_true")
    args = ap.parse_args()
    site = Path(args.site).resolve()

    served = site / "index.html"
    if not served.is_file():
        print(f"FAIL: {served} does not exist — the landing page was never copied in.")
        return 1
    html = served.read_text(encoding="utf-8")

    if html != SOURCE.read_text(encoding="utf-8"):
        print(f"FAIL: {served} differs from {SOURCE} — something rewrote the page after assembly.")
        return 1

    ids = set(ID_RE.findall(html))
    failures: list[str] = []
    checked = anchors = 0

    for ref in REF_RE.findall(html) + FETCH_RE.findall(html):
        if ref.startswith(EXTERNAL):
            continue
        if ref.startswith("#"):
            anchors += 1
            if ref[1:] not in ids:
                failures.append(f"anchor {ref} names no id on the page")
            continue
        checked += 1
        landing = resolve(site, ref)
        if not landing.exists():
            failures.append(f"{ref} → {landing.relative_to(site)} does not exist")
        # "./#evidence" is both a link to the root and a same-page fragment.
        if "#" in ref and landing == served:
            anchors += 1
            frag = ref.split("#", 1)[1]
            if frag and frag not in ids:
                failures.append(f"anchor #{frag} names no id on the page")

    # A checker that matched nothing is not a passing checker.
    if checked == 0:
        failures.append("no relative links were found at all — REF_RE has stopped matching")
    if anchors == 0:
        failures.append("no same-page anchors were found at all — the nav should have several")

    if not args.skip_version:
        tag = newest_tag()
        pill = PILL_RE.search(html)
        if tag is None:
            failures.append("no v* tag is visible — checkout needs fetch-tags, or the check "
                            "would pass by seeing nothing")
        elif pill is None:
            failures.append("the release pill's version could not be read from the page")
        elif pill.group(1) != tag:
            failures.append(f"the release pill says {pill.group(1)}, the newest tag is {tag}")

    if failures:
        print("FAIL: the landing page does not hold up:")
        for f in failures:
            print(f"  {f}")
        return 1

    print(f"landing page: {checked} relative link(s) and {anchors} anchor(s) resolve in {site}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
