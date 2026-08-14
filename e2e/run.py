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
TENANT = "6f89cf12-978b-4d23-ac18-9ef0c127cf87"
ORIGIN = f"https://localhost:{PORT}"

TLS = ssl.create_default_context()
TLS.check_hostname = False
TLS.verify_mode = ssl.CERT_NONE


def healthy(origin=None):
    # origin defaults to the shared emulator; suites that start their own pass
    # theirs, so one probe serves both without duplicating the TLS setup.
    origin = origin or ORIGIN
    try:
        with urllib.request.urlopen(f"{origin}/health", context=TLS, timeout=5) as r:
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


def suite_saml(env):
    """A real SP library completing SP-initiated SSO."""
    d = ROOT / "e2e" / "saml"
    if not (d / "node_modules").exists():
        subprocess.run(["npm", "install", "--silent"], cwd=d, check=True)
    return run(["node", "suite.mjs"], d, env)


def suite_go(env):
    d = ROOT / "e2e" / "go"
    subprocess.run(["go", "mod", "download"], cwd=d, env=env)
    return run(["go", "test", "./...", "-count=1"], d, env)


def venv_bin(venv, name):
    """The path to an executable inside a virtualenv, on any platform.

    Windows puts them in Scripts\\ with an .exe suffix; POSIX in bin/. Hard-coding
    bin/ made this suite unrunnable on Windows even though the emulator and every
    other suite work there.
    """
    if os.name == "nt":
        return venv / "Scripts" / f"{name}.exe"
    return venv / "bin" / name


def suite_python(env):
    d = ROOT / "e2e" / "python"
    venv = d / ".venv"
    if not venv.exists():
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
    pip = venv_bin(venv, "pip")
    py = venv_bin(venv, "python")
    subprocess.run([str(pip), "install", "-q", "msal"], check=True)
    return run([str(py), "suite.py"], d, env)


def suite_graph(env):
    d = ROOT / "e2e" / "graph"
    if not (d / "node_modules").exists():
        subprocess.run(["npm", "install", "--silent"], cwd=d, check=True)
    return run(["node", "suite.mjs"], d, env)


def suite_scim(env):
    """scim2-tester, an independent RFC 7643/7644 compliance checker.

    Run through uv rather than a venv: the checker is only needed here, and uv
    resolves it per-run without leaving a tree in the repo.
    """
    return run(["uv", "run", "--no-project", "--python", "3.12",
                "--with", "scim2-client[httpx]", "--with", "scim2-tester", "--with", "httpx",
                "python", "suite.py"], ROOT / "e2e" / "scim", env)


def suite_graph_permissions(env):
    """Real Graph SDK against the permission gate, on its OWN emulator.

    GRAPH_PERMISSIONS is config-only with no runtime toggle, and the shared
    emulator runs with the gate off (its default). So this suite starts a second
    emulator with the gate on, rather than changing the environment every other
    suite depends on.
    """
    d = ROOT / "e2e" / "graph-permissions"
    if not (d / "node_modules").exists():
        subprocess.run(["npm", "install", "--silent"], cwd=d, check=True)

    port = os.environ.get("GP_PORT", "9755")
    work = Path(tempfile.mkdtemp(prefix="entra-gperm.", dir=os.environ.get("TMPDIR", "/tmp")))
    binary = work / "entra-emulator"
    subprocess.run(["go", "build", "-o", str(binary), "./cmd/entra-emulator"], cwd=ROOT, check=True)
    log = open(work / "server.log", "w")
    proc = subprocess.Popen(
        [str(binary)], cwd=work, stdout=log, stderr=subprocess.STDOUT,
        env={**os.environ, "PORT": port, "ORIGIN_MODE": "compat",
             "GRAPH_PERMISSIONS": "true",
             "DB_PATH": str(work / "gperm.db"), "TLS_CERT_DIR": str(work / "tls")})
    try:
        origin = f"https://localhost:{port}"
        deadline = time.time() + 30
        while time.time() < deadline and not healthy(origin):
            if proc.poll() is not None:
                print((work / "server.log").read_text()[-2000:], file=sys.stderr)
                return False
            time.sleep(0.2)
        if not healthy(origin):
            print("gate emulator did not start", file=sys.stderr)
            print((work / "server.log").read_text()[-2000:], file=sys.stderr)
            return False
        cert = str(work / "tls" / "cert.pem")
        return run(["node", "suite.mjs"], d,
                   {**env, "GP_ORIGIN": origin, "GP_TENANT": TENANT,
                    "EMU_CERT": cert, "NODE_EXTRA_CA_CERTS": cert})
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(work, ignore_errors=True)


def suite_persistence(env):
    """Real Graph SDK across an emulator RESTART on the same database.

    The restart is the whole point, so this suite owns the emulator lifecycle:
    write through the SDK, stop the process, start a new one on the same
    DB_PATH, and read the work back. Against the shared emulator there would be
    no restart and every check would pass on an in-memory directory.
    """
    d = ROOT / "e2e" / "persistence"
    if not (d / "node_modules").exists():
        subprocess.run(["npm", "install", "--silent"], cwd=d, check=True)

    port = os.environ.get("PERSIST_PORT", "9757")
    work = Path(tempfile.mkdtemp(prefix="entra-persist.", dir=os.environ.get("TMPDIR", "/tmp")))
    binary = work / "entra-emulator"
    subprocess.run(["go", "build", "-o", str(binary), "./cmd/entra-emulator"], cwd=ROOT, check=True)

    db, tls = work / "directory.db", work / "tls"
    origin = f"https://localhost:{port}"

    def boot(tag):
        log = open(work / f"server-{tag}.log", "a")
        p = subprocess.Popen(
            [str(binary)], cwd=work, stdout=log, stderr=subprocess.STDOUT,
            env={**os.environ, "PORT": port, "ORIGIN_MODE": "compat",
                 "DB_PATH": str(db), "TLS_CERT_DIR": str(tls)})
        deadline = time.time() + 30
        while time.time() < deadline and not healthy(origin):
            if p.poll() is not None:
                print((work / f"server-{tag}.log").read_text()[-2000:], file=sys.stderr)
                return None
            time.sleep(0.2)
        if not healthy(origin):
            print(f"emulator ({tag}) did not start", file=sys.stderr)
            p.terminate()
            return None
        return p

    def stop(p):
        p.terminate()
        try:
            p.wait(timeout=15)
        except subprocess.TimeoutExpired:
            p.kill()

    senv = {**env, "PERSIST_ORIGIN": origin, "PERSIST_TENANT": TENANT,
            "PERSIST_STATE": str(work / "state.json"),
            "EMU_CERT": str(tls / "cert.pem"),
            "NODE_EXTRA_CA_CERTS": str(tls / "cert.pem")}
    try:
        first = boot("write")
        if first is None:
            return False
        ok = run(["node", "suite.mjs", "write"], d, senv)
        stop(first)
        if not ok:
            return False

        # The database file is the only thing carried across; a fresh process
        # reads it or the claim is false.
        print("==> emulator stopped; restarting on the same database")
        second = boot("read")
        if second is None:
            return False
        try:
            return run(["node", "suite.mjs", "read"], d, senv)
        finally:
            stop(second)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def suite_scim_outbound(env):
    """Microsoft's own SCIM reference server as the provisioning target.

    Needs the .NET SDK (to build the pinned sample) and git (to fetch it); the
    suite itself is stdlib-only, so it runs on the bare interpreter.
    """
    return run([sys.executable, "suite.py"], ROOT / "e2e" / "scim-outbound", env)


def suite_dotnet(env):
    return run(["dotnet", "run", "-c", "Release"], ROOT / "e2e" / "dotnet", env)


def suite_wsfed(env):
    """Unmodified Microsoft.AspNetCore.Authentication.WsFederation (KPI-1)."""
    return run(["dotnet", "run", "-c", "Release"], ROOT / "e2e" / "wsfed", env)


def suite_java(env):
    return run(["mvn", "-q", "-B", "compile", "exec:java"], ROOT / "e2e" / "java", env)


SUITES = {
    "ts": suite_ts, "go": suite_go, "python": suite_python, "saml": suite_saml,
    "graph": suite_graph, "dotnet": suite_dotnet, "java": suite_java,
    "wsfed": suite_wsfed,
    "scim": suite_scim, "scim-outbound": suite_scim_outbound,
    "graph-permissions": suite_graph_permissions,
    "persistence": suite_persistence,
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
