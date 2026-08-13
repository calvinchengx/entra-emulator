#!/usr/bin/env python3
"""Every 🟢 parity claim must name the test that witnesses it.

A row is graded 🟢 only when real cryptography or a real client does the work — but
nothing enforced that, and unenforced rules drift. The sibling fabric-emulator
repo hit the failure this prevents twice: one witness silently covering several
claims, so a row stayed green while half of what it claimed had no test at all.

This checker makes the mapping explicit and verifiable.

Witness kinds, deliberately distinguished because they are not equal evidence:

  ci:<job>      a CI job driving a real external client (strongest — this is
                what the rule in doc 24 actually asks for)
  go:<Test>     a Go test: real HTTP, real signed JWTs, real RBAC, but our own
                client rather than a third party's
  boundary:...  the claim is scoped by a documented limitation, with the reason
  TODO          not yet identified — the point of --strict

Usage:
    check_witnesses.py            report the mapping and exit 0
    check_witnesses.py --strict   also fail on TODO or dangling references
"""
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PARITY = ROOT / "docs" / "parity.md"
MANIFEST = ROOT / "docs" / "witnesses.json"
CI = ROOT / ".github" / "workflows" / "ci.yml"

# Sections that do not make capability claims: the legend, the conformance
# table (itself a list of witnesses), emulator-only helpers, and the explicit
# scope boundary.
SKIP_SECTIONS = {
    "Ecosystem conformance: real clients as witnesses",
    "Emulator-only (no Entra equivalent — these exist for testing)",
    "Legend",
    "Scope boundary: a dev-loop emulator, not an IdP",
}


def key_for(feature: str) -> str:
    """A stable-ish key from the row's feature cell: markdown and punctuation
    stripped, lowercased. Rewording a claim changes its key and trips the
    checker — that is intended, since a reworded claim deserves a fresh look
    at whether its witness still covers it."""
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", feature)  # links → text
    text = re.sub(r"[*`_]", "", text)
    text = re.sub(r"[^a-z0-9]+", "-", text.lower())
    return text.strip("-")


def green_claims():
    """Yield (section, feature, key) for every row claiming 🟢."""
    section = None
    for line in PARITY.read_text().splitlines():
        if line.startswith("## "):
            section = line[3:].strip()
            continue
        if not line.startswith("| ") or section is None or section in SKIP_SECTIONS:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 3:
            continue
        if cells[0] in ("Entra feature", "Capability", "Feature") or set(cells[0]) <= set("-"):
            continue
        if "🟢" in cells[-1]:
            yield section, cells[0], key_for(cells[0])


def grade_counts() -> dict[str, int]:
    """Capability-row grades, using the same skip list as green_claims."""
    counts = {"🟢": 0, "🟡": 0, "🟠": 0, "🔴": 0}
    section = None
    for line in PARITY.read_text().splitlines():
        if line.startswith("## "):
            section = line[3:].strip()
            continue
        if not line.startswith("| ") or section is None or section in SKIP_SECTIONS:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 3:
            continue
        if cells[0] in ("Entra feature", "Capability", "Feature") or set(cells[0]) <= set("-"):
            continue
        last = cells[-1]
        for g in counts:
            if g in last:
                counts[g] += 1
                break
    return counts


README = ROOT / "README.md"
# The glance table in README.md. A hardcoded count here is how the table went
# stale last time; the checker compares these labels to grade_counts().
GLANCE_LABELS = (
    ("🟢", "Real"),
    ("🟡", "Emulated"),
    ("🟠", "Bring-your-own-engine"),
    ("🔴", "Not implemented"),
)


def readme_glance_drift(counts: dict[str, int]) -> list[str]:
    """README glance numbers that disagree with docs/parity.md."""
    text = README.read_text() if README.exists() else ""
    drift = []
    for emoji, label in GLANCE_LABELS:
        m = re.search(rf"\| {re.escape(emoji)} \*\*{re.escape(label)}\*\* \| (\d+) \|", text)
        if not m:
            drift.append(f"README glance missing {emoji} **{label}**")
            continue
        got, want = int(m.group(1)), counts[emoji]
        if got != want:
            drift.append(f"README glance {label}: {got}, parity.md {want}")
    return drift


def ci_job_ids() -> set:
    return set(re.findall(r"^  ([a-z0-9-]+):$", CI.read_text(), re.M))


def go_test_names() -> set:
    out = subprocess.run(
        ["grep", "-rhoE", r"^func (Test[A-Za-z0-9_]+)", "--include=*_test.go", str(ROOT / "internal"), str(ROOT / "cmd")],
        capture_output=True, text=True,
    )
    return {line.split()[1] for line in out.stdout.splitlines() if line.startswith("func ")}


def main() -> int:
    strict = "--strict" in sys.argv
    manifest = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {}
    jobs, tests = ci_job_ids(), go_test_names()

    missing, dangling, todo = [], [], []
    kinds = {"ci": 0, "go": 0, "boundary": 0}
    # Which claims lean on each witness — a witness covering many claims is
    # where bundling hides.
    shared: dict[str, list[str]] = {}

    claims = list(green_claims())
    for section, feature, key in claims:
        entry = manifest.get(key)
        if entry is None:
            missing.append((section, feature, key))
            continue
        for witness in entry.get("witnesses", []):
            if witness == "TODO":
                todo.append((section, feature))
                continue
            kind, _, name = witness.partition(":")
            kinds[kind] = kinds.get(kind, 0) + 1
            shared.setdefault(witness, []).append(feature)
            if kind == "ci" and name not in jobs:
                dangling.append(f"{key} → {witness} (no such CI job)")
            elif kind == "go" and name not in tests:
                dangling.append(f"{key} → {witness} (no such Go test)")

    print(f"🟢 capability claims: {len(claims)}")
    print(f"  witnessed by a real external client (ci:) : {kinds.get('ci', 0)}")
    print(f"  witnessed by our own Go tests (go:)       : {kinds.get('go', 0)}")
    print(f"  scoped by a documented boundary           : {kinds.get('boundary', 0)}")
    print(f"  not yet identified (TODO)                 : {len(todo)}")
    print(f"  absent from the manifest                  : {len(missing)}")

    grades = grade_counts()
    print(
        f"ledger grades: 🟢 {grades['🟢']}  🟡 {grades['🟡']}  "
        f"🟠 {grades['🟠']}  🔴 {grades['🔴']}"
    )
    glance = readme_glance_drift(grades)
    if glance:
        print("\nREADME glance disagrees with docs/parity.md:")
        for g in glance:
            print(f"  {g}")

    heavy = sorted(((w, c) for w, c in shared.items() if len(c) > 3),
                   key=lambda x: -len(x[1]))
    if heavy:
        print("\nWitnesses carrying many claims (check none is over-credited):")
        for witness, covered in heavy[:5]:
            print(f"  {witness}: {len(covered)} claims")

    if missing:
        print("\nClaims with no manifest entry:")
        for section, feature, key in missing[:20]:
            print(f"  [{section}] {feature[:70]}\n      key: {key}")
    if dangling:
        print("\nDangling witness references:")
        for d in dangling:
            print(f"  {d}")

    if strict and (missing or dangling or todo or glance):
        print("\nFAIL: every 🟢 claim needs an identified, existing witness.")
        if glance:
            print("FAIL: README glance must match docs/parity.md grade counts.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
