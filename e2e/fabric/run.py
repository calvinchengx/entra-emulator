#!/usr/bin/env python3
"""Fabric-emulator as the third-party witness for Fabric-audience tokens
and the workspace-identity handshake.

entra owns the identity object and the Fabric-audience mint. fabric-emulator
is the consumer of that seam: it provisions over entra's admin API, mints a
token with no caller-held credential, and uses that token as the workspace's
own principal. Those tests live in fabric-emulator; running them here — against
THIS checkout, not the entra version fabric's go.mod pins — is the stranger
evidence the claim was missing.

The suite clones fabric-emulator at a pinned commit, replaces
github.com/calvinchengx/entra-emulator with this tree, and runs just
TestWorkspaceIdentityHandshake and TestWorkspaceIdentityCascadeDelete.
newFixture already does a real client_credentials grant for
https://api.fabric.microsoft.com/.default, so the token half is in the same
run. Nothing in fabric-emulator is patched.
"""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = os.environ.get("FABRIC_REPO", "https://github.com/calvinchengx/fabric-emulator.git")
# fabric-emulator main @ #211 (Opt-in ARM capacities). Pin a published
# commit, never a local feature branch — the witness must be fetchable in CI.
PIN = os.environ.get("FABRIC_PIN", "2f7a2e1eb75085ca5b336f517d72be200d7faa0d")
ENTRA = Path(__file__).resolve().parents[2]
TESTS = "TestWorkspaceIdentityHandshake$|TestWorkspaceIdentityCascadeDelete$"


def run(cmd, cwd, **kw):
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=cwd, check=True, **kw)


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="entra-fabric-e2e."))
    src = work / "fabric-emulator"
    try:
        src.mkdir(parents=True)
        run(["git", "init", "-q", str(src)], cwd=work)
        run(["git", "remote", "add", "origin", REPO], cwd=src)
        run(["git", "fetch", "-q", "--depth", "1", "origin", PIN], cwd=src)
        run(["git", "checkout", "-q", "FETCH_HEAD"], cwd=src)

        run(["go", "mod", "edit", f"-replace=github.com/calvinchengx/entra-emulator={ENTRA}"], cwd=src)
        # Current entra pulls packages (SAML etree, …) that fabric's go.sum —
        # still on entra v0.4.1 — does not list. tidy, do not patch source.
        run(["go", "mod", "tidy"], cwd=src)
        run([
            "go", "test", "./internal/server",
            "-run", TESTS, "-count=1", "-timeout", "3m",
        ], cwd=src)
        return 0
    except subprocess.CalledProcessError as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return e.returncode or 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
