#!/usr/bin/env python3
"""E2E runner: boots the emulator with an ephemeral store, then runs the
per-language SDK suites (docs/11-e2e-sdk-matrix.md).

Usage: python3 e2e/run.py [ts|go|python|dotnet|java ...]   (default: ts go python)

Real SDK clients (msal-node, MSAL Go/azidentity, MSAL Python, MSAL.NET,
MSAL4J) authenticate against the running emulator over HTTPS, so this proves
wire compatibility, not just our own tests. Stdlib-only.
"""

import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PORT = os.environ.get("E2E_PORT", "9743")
TENANT = "11111111-1111-1111-1111-111111111111"
ORIGIN = f"https://localhost:{PORT}"

TLS = ssl.create_default_context()
TLS.check_hostname = False
TLS.verify_mode = ssl.CERT_NONE


def healthy():
    try:
        with urllib.request.urlopen(f"{ORIGIN}/health", context=TLS, timeout=5) as r:
            return r.status == 200
    except (urllib.error.URLError, OSError):
        return False


def run(cmd, cwd, env):
    """Run a suite command; return True on success."""
    return subprocess.run(cmd, cwd=cwd, env=env).returncode == 0


def suite_ts(env):
    d = ROOT / "e2e" / "ts"
    if not (d / "node_modules").exists():
        subprocess.run(["npm", "install", "--silent"], cwd=d, check=True)
    return run(["node", "suite.mjs"], d, env)


def suite_go(env):
    d = ROOT / "e2e" / "go"
    subprocess.run(["go", "mod", "download"], cwd=d, env=env)
    return run(["go", "test", "./...", "-count=1"], d, env)


def suite_python(env):
    d = ROOT / "e2e" / "python"
    venv = d / ".venv"
    if not venv.exists():
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
    pip = venv / "bin" / "pip"
    py = venv / "bin" / "python"
    subprocess.run([str(pip), "install", "-q", "msal"], check=True)
    return run([str(py), "suite.py"], d, env)


def suite_graph(env):
    d = ROOT / "e2e" / "graph"
    if not (d / "node_modules").exists():
        subprocess.run(["npm", "install", "--silent"], cwd=d, check=True)
    return run(["node", "suite.mjs"], d, env)


def suite_dotnet(env):
    return run(["dotnet", "run", "-c", "Release"], ROOT / "e2e" / "dotnet", env)


def suite_java(env):
    return run(["mvn", "-q", "-B", "compile", "exec:java"], ROOT / "e2e" / "java", env)


SUITES = {
    "ts": suite_ts, "go": suite_go, "python": suite_python,
    "graph": suite_graph, "dotnet": suite_dotnet, "java": suite_java,
}


def main(argv):
    suites = argv or ["ts", "go", "python"]
    unknown = [s for s in suites if s not in SUITES]
    if unknown:
        sys.exit(f"unknown suite(s): {', '.join(unknown)}")

    work = Path(tempfile.mkdtemp(prefix="entra-e2e.", dir=os.environ.get("TMPDIR", "/tmp")))
    emu = None
    try:
        print("==> building emulator")
        emu_bin = work / "entra-emulator"
        subprocess.run(["go", "build", "-o", str(emu_bin), "./cmd/entra-emulator"],
                       cwd=ROOT, check=True)

        print(f"==> starting emulator on :{PORT}")
        log = open(work / "server.log", "w")
        emu = subprocess.Popen(
            [str(emu_bin)], cwd=work, stdout=log, stderr=subprocess.STDOUT,
            env={**os.environ, "PORT": PORT, "ORIGIN_MODE": "compat",
                 "DB_PATH": str(work / "e2e.db"), "TLS_CERT_DIR": str(work / "tls")})

        deadline = time.time() + 10
        while time.time() < deadline and not healthy():
            time.sleep(0.2)
        if not healthy():
            print("emulator failed to start", file=sys.stderr)
            print((work / "server.log").read_text(), file=sys.stderr)
            return 1

        env = {**os.environ,
               "EMU_ORIGIN": ORIGIN, "EMU_TENANT": TENANT,
               "EMU_CERT": str(work / "tls" / "cert.pem"),
               # Node honors NODE_EXTRA_CA_CERTS to trust the self-signed cert.
               "NODE_EXTRA_CA_CERTS": str(work / "tls" / "cert.pem")}

        fail = 0
        for s in suites:
            print(f"\n=== e2e: {s} ===")
            if not SUITES[s](env):
                fail = 1
        return fail
    finally:
        if emu:
            emu.terminate()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
