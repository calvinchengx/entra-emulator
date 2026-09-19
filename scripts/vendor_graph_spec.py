# /// script
# requires-python = ">=3.12"
# dependencies = ["pyyaml"]
# ///
"""Vendor Microsoft's Graph v1.0 OpenAPI, and prove the copy is faithful.

The upstream document is 44 MB of YAML. What the conformance gates read is a
JSON rendering of it, gzip-compressed (about 2 MB), because parsing 44 MB of
YAML on every CI run is seconds of pure waste and the gates are stdlib-only.

THE COPY IS DERIVED, NEVER TRANSCRIBED, and the derivation is itself gated. A
vendored file that merely claims to be Microsoft's is a file somebody can edit,
and a hand-trimmed subset is a file that quietly stops describing the surface it
was meant to check. So this script does three separate jobs:

  --pin COMMIT   fetch the upstream YAML at an exact commit, record its sha256,
                 render the JSON, and write the vendored copy plus pin.json.
  --verify       OFFLINE. Re-hash the vendored copy against pin.json. This is the
                 tamper check, cheap enough to run on every push.
  --reproduce    ONLINE. Re-fetch the upstream YAML at the pinned commit, check
                 ITS sha256 against pin.json, re-derive the JSON, and require the
                 result to match the vendored copy byte for byte. This is the
                 check that the derivation is faithful and deterministic, and it
                 is what stops the vendored file drifting from what upstream
                 actually says.

The rendering is deterministic on purpose: key order is preserved, separators are
fixed, and the gzip header carries no timestamp, so the same YAML always yields
the same bytes.
"""

import argparse
import gzip
import hashlib
import json
import pathlib
import sys
import urllib.request

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
DIR = ROOT / "third_party" / "msgraph-openapi"
PIN = DIR / "pin.json"
VENDORED = DIR / "openapi-v1.0.json.gz"
LICENSE = DIR / "LICENSE"

REPO = "microsoftgraph/msgraph-metadata"
UPSTREAM_PATH = "openapi/v1.0/openapi.yaml"


def raw_url(commit: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/{REPO}/{commit}/{path}"


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=300) as r:
        return r.read()


def render(yaml_bytes: bytes) -> bytes:
    """The deterministic JSON rendering of the upstream YAML."""
    loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    doc = yaml.load(yaml_bytes, Loader=loader)
    # Fixed separators and preserved key order: same input, same bytes.
    return json.dumps(doc, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def compress(data: bytes) -> bytes:
    # mtime=0 and no filename: the gzip header would otherwise carry the time it
    # was written, and every re-derivation would differ from the last.
    import io
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=9, mtime=0, filename="") as g:
        g.write(data)
    return buf.getvalue()


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sanity(rendered: bytes) -> dict:
    """Refuse a rendering that is obviously not the Graph spec.

    A fetch that returned an HTML error page, or a YAML that parsed to something
    small, would otherwise be vendored and then quietly make every gate pass by
    checking against nothing.
    """
    doc = json.loads(rendered)
    stats = {
        "openapi": doc.get("openapi"),
        "paths": len(doc.get("paths", {})),
        "schemas": len(doc.get("components", {}).get("schemas", {})),
    }
    if not str(stats["openapi"]).startswith("3.") or stats["paths"] < 5000 or stats["schemas"] < 2000:
        sys.exit(f"this does not look like the Graph v1.0 spec: {stats}")
    return stats


def cmd_pin(commit: str) -> int:
    print(f"fetching {UPSTREAM_PATH} at {commit} ...")
    upstream = fetch(raw_url(commit, UPSTREAM_PATH))
    rendered = render(upstream)
    stats = sanity(rendered)
    DIR.mkdir(parents=True, exist_ok=True)
    VENDORED.write_bytes(compress(rendered))
    LICENSE.write_bytes(fetch(raw_url(commit, "LICENSE")))
    pin = {
        "upstream": f"https://github.com/{REPO}",
        "path": UPSTREAM_PATH,
        "commit": commit,
        "upstream_sha256": sha256(upstream),
        "upstream_bytes": len(upstream),
        "derived_json_sha256": sha256(rendered),
        "derived_json_bytes": len(rendered),
        "vendored_file": VENDORED.name,
        "vendored_bytes": VENDORED.stat().st_size,
        "openapi": stats["openapi"],
        "paths": stats["paths"],
        "schemas": stats["schemas"],
    }
    PIN.write_text(json.dumps(pin, indent=2) + "\n")
    print(json.dumps(pin, indent=2))
    return 0


def load_pin() -> dict:
    if not PIN.is_file():
        sys.exit(f"{PIN} is missing; run with --pin <commit> first")
    return json.loads(PIN.read_text())


def cmd_verify() -> int:
    pin = load_pin()
    if not VENDORED.is_file():
        sys.exit(f"{VENDORED} is missing")
    rendered = gzip.decompress(VENDORED.read_bytes())
    got = sha256(rendered)
    if got != pin["derived_json_sha256"]:
        print(f"TAMPERED OR CORRUPT: the vendored spec hashes to {got}, "
              f"pin.json says {pin['derived_json_sha256']}", file=sys.stderr)
        return 1
    stats = sanity(rendered)
    print(f"vendored Graph spec verified: {stats['paths']} paths, "
          f"{stats['schemas']} schemas, upstream {pin['commit'][:12]}")
    return 0


def cmd_reproduce() -> int:
    pin = load_pin()
    print(f"re-fetching upstream at the pinned commit {pin['commit'][:12]} ...")
    upstream = fetch(raw_url(pin["commit"], pin["path"]))
    if sha256(upstream) != pin["upstream_sha256"]:
        print("UPSTREAM CHANGED UNDER A PINNED COMMIT: the fetched YAML does not "
              "match pin.json's upstream_sha256. A commit SHA is supposed to be "
              "immutable, so either the pin is wrong or something is badly off.",
              file=sys.stderr)
        return 1
    rendered = render(upstream)
    if sha256(rendered) != pin["derived_json_sha256"]:
        print("DERIVATION DRIFT: rendering the pinned upstream YAML no longer "
              "yields the vendored JSON. PyYAML or this script changed behaviour.",
              file=sys.stderr)
        return 1
    if gzip.decompress(VENDORED.read_bytes()) != rendered:
        print("the vendored file is not the derivation of the pinned upstream",
              file=sys.stderr)
        return 1
    print(f"reproduced: the vendored spec is exactly what upstream "
          f"{pin['commit'][:12]} says")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--pin", metavar="COMMIT")
    g.add_argument("--verify", action="store_true")
    g.add_argument("--reproduce", action="store_true")
    a = ap.parse_args()
    if a.pin:
        return cmd_pin(a.pin)
    return cmd_verify() if a.verify else cmd_reproduce()


if __name__ == "__main__":
    sys.exit(main())
