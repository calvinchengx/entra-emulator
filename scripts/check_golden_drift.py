#!/usr/bin/env python3
"""Check the OIDC golden reference against the LIVE Entra discovery document.

The evidence chain has two links and only one is tested:

    emulator --[TestGoldenParityOIDCDiscovery]--> golden file --[ nothing ]--> real Entra

`golden_parity_test.go` proves the emulator conforms to the golden file. Nothing
proves the golden file still describes Entra. It was captured once and has been
the unquestioned authority ever since, so every green row resting on it inherits
the accuracy of a month-old snapshot.

This closes the second link. Entra's discovery document is public and
unauthenticated, which makes it the one surface in this repo where genuine
*differential* evidence against Azure is available rather than aspirational.

Exit codes are distinct on purpose:
    0  golden still matches Entra
    1  drift found — the golden reference is now wrong about Entra
    2  Entra unreachable — no verdict; NOT success

2 exists so an outage cannot be read as a pass. A checker that returns 0 when it
learned nothing is the same defect as a gate whose output was truncated: a green
that was never earned.

Not wired into the normal CI gate: that would make the build depend on
Microsoft's availability. Intended for a scheduled job that reports drift.
"""

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

TIMEOUT = 30


def fetch(url: str) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--golden", default="e2e/golden/oidc-discovery.golden.json")
    ap.add_argument("--tenant", default="common",
                    help="tenant segment; values are service-wide, so common is representative")
    args = ap.parse_args()

    golden = json.loads(Path(args.golden).read_text())
    url = golden.get("source") or (
        f"https://login.microsoftonline.com/{args.tenant}/v2.0/.well-known/openid-configuration")

    try:
        live = fetch(url)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        print(f"UNREACHABLE: could not fetch {url}: {e}")
        print("No verdict — this is not a pass.")
        return 2

    print(f"golden captured {golden.get('captured', '?')}  vs  live {url}")
    drift: list[str] = []

    # 1. Fields the golden says Entra provides must still be provided.
    for f in golden.get("required_fields", []):
        if f not in live:
            drift.append(f"required field {f!r} is no longer in Entra's document")

    pv = golden.get("protocol_values", {})

    def live_set(key):
        return set(live.get(key) or [])

    # 2. "equals" must still be exactly equal.
    for gk, lk in [("subject_types_supported_equals", "subject_types_supported")]:
        want, got = set(pv.get(gk) or []), live_set(lk)
        if want != got:
            drift.append(f"{lk}: golden says {sorted(want)}, Entra now advertises {sorted(got)}")

    # 3. "must_include" values must still be advertised by Entra.
    for gk, lk in [
        ("id_token_signing_alg_values_must_include", "id_token_signing_alg_values_supported"),
        ("scopes_supported_must_include", "scopes_supported"),
        ("claims_supported_must_include", "claims_supported"),
        ("token_endpoint_auth_methods_must_include", "token_endpoint_auth_methods_supported"),
    ]:
        missing = set(pv.get(gk) or []) - live_set(lk)
        if missing:
            drift.append(f"{lk}: golden requires {sorted(missing)}, Entra no longer advertises them")

    # 4. "subset_of" is the allowed universe. If Entra dropped a value, the
    #    golden would still permit the emulator to advertise something Entra
    #    does not — the exact failure this file exists to prevent.
    for gk, lk in [
        ("response_types_supported_subset_of", "response_types_supported"),
        ("response_modes_supported_subset_of", "response_modes_supported"),
        ("token_endpoint_auth_methods_subset_of", "token_endpoint_auth_methods_supported"),
    ]:
        stale = set(pv.get(gk) or []) - live_set(lk)
        if stale:
            drift.append(
                f"{lk}: golden permits {sorted(stale)} which Entra no longer advertises")

    # 5. Documented divergences must still be real. If Entra dropped a field we
    #    deliberately omit, the note describes a service that no longer exists.
    for f in golden.get("entra_only_fields_out_of_scope", []):
        if f not in live:
            drift.append(f"documented divergence {f!r} is stale — Entra no longer advertises it")

    # 6. Report Entra fields the golden has no opinion about. Not drift on its
    #    own, but it is how a new capability arrives unnoticed.
    known = set(golden.get("required_fields", [])) | set(
        golden.get("entra_only_fields_out_of_scope", []))
    unknown = sorted(set(live) - known)
    if unknown:
        print(f"\n  Entra fields the golden does not mention ({len(unknown)}):")
        for f in unknown:
            v = live[f]
            shown = v if isinstance(v, (bool, int, str)) else f"<{type(v).__name__}>"
            print(f"    {f} = {shown}")

    # 7. Boolean capability VALUES, not merely presence. required_fields records
    #    that a field exists; it cannot notice Entra changing its answer. That
    #    gap is how the emulator came to advertise request_uri_parameter_supported
    #    true against Entra's false with every test green.
    recorded = {k: v for k, v in (golden.get("entra_boolean_values") or {}).items()
                if isinstance(v, bool)}
    for k, want in recorded.items():
        if k not in live:
            drift.append(f"boolean {k!r} is recorded as {want} but Entra no longer returns it")
        elif live[k] != want:
            drift.append(f"boolean {k}: golden records {want}, Entra now answers {live[k]}")

    # 8. Known divergences must still BE divergences. If Entra changes its answer
    #    to match us, the note describes a gap that has closed, and leaving it
    #    would keep flagging a difference nobody has.
    for k, spec in (golden.get("emulator_divergences") or {}).items():
        if not isinstance(spec, dict) or "entra" not in spec:
            continue
        if k in live and live[k] != spec["entra"]:
            drift.append(
                f"divergence {k}: recorded as Entra={spec['entra']} vs emulator="
                f"{spec.get('emulator')}, but Entra now answers {live[k]} — the note is stale")

    flags = {k: v for k, v in live.items() if isinstance(v, bool)}
    if flags:
        print("\n  Entra boolean capability flags (live):")
        for k, v in sorted(flags.items()):
            mark = ""
            div = (golden.get("emulator_divergences") or {}).get(k)
            if isinstance(div, dict):
                mark = f"   <-- emulator answers {div.get('emulator')} (known divergence)"
            print(f"    {k} = {v}{mark}")

    if drift:
        print(f"\nDRIFT: the golden reference is wrong about Entra in {len(drift)} place(s):")
        for d in drift:
            print(f"  - {d}")
        return 1

    print("\nNo drift: the golden reference still matches Entra's live document.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
