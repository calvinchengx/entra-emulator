#!/usr/bin/env python3
"""Microsoft's own `az` CLI, unmodified, logging in against this entra.

arm-emulator and azure-keyvault-emulator already drive `az login` as *their*
witness — those jobs prove ARM and Key Vault, not this ledger. This suite
stops at the STS: register a private cloud, service-principal login, then
`az account get-access-token` for Graph and ARM audiences. A localhost HTTPS
stub answers `GET /subscriptions` with an empty list so login can finish
without arm-emulator. The CLI verifies TLS; the harness points
REQUESTS_CA_BUNDLE at the emulator cert instead of turning verification off.

    python3 e2e/az-cli/run.py
"""

import base64
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PORT = os.environ.get("E2E_PORT", "18946")
TENANT = "6f89cf12-978b-4d23-ac18-9ef0c127cf87"
SP_CLIENT = "00d88624-f0d7-46f6-a641-6232c2608928"
SP_SECRET = "daemon-app-secret"
ORIGIN = f"https://localhost:{PORT}"
CLOUD = os.environ.get("AZ_CLOUD_NAME", "EntraEmulatorCloud")

TLS = ssl.create_default_context()
TLS.check_hostname = False
TLS.verify_mode = ssl.CERT_NONE

AZ_ENV: dict[str, str] = {}


class _ArmStub(BaseHTTPRequestHandler):
    """Enough ARM for `az login` to finish. Not a witness of ARM.

    After the token arrives, the CLI lists subscriptions. A connection
    refused or a non-JSON 404 (entra's) crashes the client before
    --allow-no-subscriptions can apply. An empty list is the honest
    entra-only answer: this cloud has no ARM.
    """

    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path.startswith("/subscriptions"):
            body = b'{"value":[]}'
        elif path.startswith("/metadata/endpoints"):
            body = json.dumps({
                "authentication": {
                    "loginEndpoint": ORIGIN + "/",
                    "audiences": [
                        "https://management.core.windows.net/",
                        "https://management.azure.com/",
                    ],
                },
                "graphEndpoint": ORIGIN + "/",
                "resourceManager": f"https://localhost:{self.server.server_address[1]}",
            }).encode()
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_arm_stub(cert: Path, key: Path) -> ThreadingHTTPServer:
    # Same leaf the emulator minted: it already names localhost. HTTPS is
    # required — az refuses bearer tokens on http.
    srv = ThreadingHTTPServer(("localhost", 0), _ArmStub)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def healthy() -> bool:
    try:
        with urllib.request.urlopen(f"{ORIGIN}/health", context=TLS, timeout=5) as r:
            return r.status == 200
    except (urllib.error.URLError, OSError):
        return False


def az(*args, check=True):
    cmd = ["az", *args]
    print(f"    $ {' '.join(cmd)}", file=sys.stderr, flush=True)
    r = subprocess.run(cmd, env={**os.environ, **AZ_ENV}, capture_output=True, text=True)
    if check and r.returncode != 0:
        sys.exit(f"FAIL: {' '.join(cmd)}\n{(r.stderr or r.stdout)[:2000]}")
    return r


def az_json(*args):
    r = az(*args, "-o", "json")
    return json.loads(r.stdout) if r.stdout.strip() else None


def jwt_payload(token: str) -> dict:
    raw = token.split(".")[1]
    raw += "=" * (-len(raw) % 4)
    return json.loads(base64.urlsafe_b64decode(raw))


def jwt_header(token: str) -> dict:
    raw = token.split(".")[0]
    raw += "=" * (-len(raw) % 4)
    return json.loads(base64.urlsafe_b64decode(raw))


def assert_app_only(token: str, resource: str) -> dict:
    header = jwt_header(token)
    payload = jwt_payload(token)
    if header.get("alg") != "RS256":
        sys.exit(f"FAIL: {resource}: expected alg RS256, got {header.get('alg')}")
    if not header.get("kid"):
        sys.exit(f"FAIL: {resource}: token header has no kid")
    if payload.get("tid") != TENANT:
        sys.exit(f"FAIL: {resource}: tid {payload.get('tid')!r} != {TENANT}")
    if payload.get("ver") != "2.0":
        sys.exit(f"FAIL: {resource}: ver {payload.get('ver')!r} != '2.0'")
    azp = payload.get("azp") or payload.get("appid")
    if azp != SP_CLIENT:
        sys.exit(f"FAIL: {resource}: azp/appid {azp!r} != {SP_CLIENT}")
    aud = payload.get("aud")
    auds = aud if isinstance(aud, list) else [aud]
    if not any(resource.rstrip("/") in (a or "").rstrip("/") for a in auds):
        sys.exit(f"FAIL: {resource}: aud {aud!r} does not contain the resource")
    return payload


def driver(arm: str):
    print("-- 1. register the emulator as a cloud")
    az("cloud", "unregister", "--name", CLOUD, check=False)
    az("cloud", "register", "--name", CLOUD,
       "--skip-endpoint-discovery",
       "--endpoint-resource-manager", arm,
       "--endpoint-active-directory", ORIGIN,
       "--endpoint-active-directory-resource-id", "https://management.azure.com/",
       "--endpoint-microsoft-graph-resource-id", f"{ORIGIN}/graph/")
    az("cloud", "set", "--name", CLOUD)
    print(f"   {CLOUD} registered and selected")

    print("-- 2. az login --service-principal against entra-emulator")
    az("login", "--service-principal", "-u", SP_CLIENT, "-p", SP_SECRET,
       "--tenant", TENANT, "--allow-no-subscriptions")
    print("   the CLI holds a token")

    print("-- 3. az account get-access-token for Microsoft Graph")
    graph = az_json("account", "get-access-token", "--resource", "https://graph.microsoft.com")
    if not graph or not graph.get("accessToken"):
        sys.exit(f"FAIL: Graph get-access-token returned {graph}")
    assert_app_only(graph["accessToken"], "https://graph.microsoft.com")
    print("   Graph-audience token: RS256, ver 2.0, tid and azp match the seed")

    print("-- 4. az account get-access-token for ARM")
    arm = az_json("account", "get-access-token", "--resource", "https://management.azure.com")
    if not arm or not arm.get("accessToken"):
        sys.exit(f"FAIL: ARM get-access-token returned {arm}")
    assert_app_only(arm["accessToken"], "https://management.azure.com")
    print("   ARM-audience token: same shape, well-known resource, no ARM companion")

    print("\nAZ CLI E2E: PASS — the real Azure CLI logged in against entra-emulator")


def main() -> int:
    if shutil.which("az") is None:
        sys.exit("FAIL: az is not on PATH (GitHub-hosted ubuntu-latest ships it)")

    work = Path(tempfile.mkdtemp(prefix="entra-az-cli-e2e."))
    azconfig = work / "azconfig"
    tls = work / "tls"
    azconfig.mkdir()
    tls.mkdir()

    AZ_ENV["AZURE_CONFIG_DIR"] = str(azconfig)
    # MSAL validates an authority against login.microsoftonline.com unless
    # instance discovery is off — the switch the CLI documents for private
    # and disconnected clouds.
    AZ_ENV["AZURE_CORE_INSTANCE_DISCOVERY"] = "false"

    emu = None
    log = None
    stub = None
    try:
        print("==> building emulator")
        emu_bin = work / "entra-emulator"
        subprocess.run(
            ["go", "build", "-o", str(emu_bin), "./cmd/entra-emulator"],
            cwd=ROOT, check=True,
        )

        print(f"==> starting emulator on :{PORT}")
        log = open(work / "server.log", "w")
        emu = subprocess.Popen(
            [str(emu_bin)], cwd=work, stdout=log, stderr=subprocess.STDOUT,
            env={**os.environ, "PORT": PORT, "ORIGIN_MODE": "compat",
                 "DB_PATH": str(work / "e2e.db"), "TLS_CERT_DIR": str(tls)},
        )
        deadline = time.time() + 15
        while time.time() < deadline and not healthy():
            time.sleep(0.2)
        if not healthy():
            print((work / "server.log").read_text(), file=sys.stderr)
            sys.exit("FAIL: emulator failed to start")

        cert = tls / "cert.pem"
        if not cert.is_file():
            sys.exit(f"FAIL: emulator did not write {cert}")
        AZ_ENV["REQUESTS_CA_BUNDLE"] = str(cert)

        stub = start_arm_stub(cert, tls / "key.pem")
        arm = f"https://localhost:{stub.server_address[1]}"
        driver(arm)
        return 0
    except subprocess.CalledProcessError as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return e.returncode or 1
    finally:
        az("cloud", "set", "--name", "AzureCloud", check=False)
        az("cloud", "unregister", "--name", CLOUD, check=False)
        if stub:
            stub.shutdown()
        if emu:
            emu.terminate()
            try:
                emu.wait(timeout=5)
            except subprocess.TimeoutExpired:
                emu.kill()
        if log:
            log.close()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
