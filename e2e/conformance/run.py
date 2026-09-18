#!/usr/bin/env python3
"""Run an OpenID Foundation conformance plan against entra-emulator.

Rung 0 of docs/23-oidf-conformance.md: the Config OP certification profile,
which is a pure discovery-document check and needs no browser and no login.

The point of this harness is that the oracle is external. Every other OIDC
check in this repo compares the emulator against an expectation we wrote:
golden_parity_test.go asserts the discovery document against
e2e/golden/oidc-discovery.golden.json, which is our capture of Entra. Here the
OIDF's own suite asserts it against the specification.

Stdlib only, like e2e/run.py.

Usage:
    uv run --no-project --python 3.12 python e2e/conformance/run.py [--keep]
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]

# Pinned to the multi-arch INDEX digest, not a per-arch manifest: a tag can be
# moved and a per-arch digest would pin the harness to one runner architecture.
# Verified 2026-09-19 to carry linux/amd64 and linux/arm64.
SUITE_VERSION = "release-v5.3.1"
SUITE_IMAGE = (
    "registry.gitlab.com/openid/conformance-suite@sha256:"
    "69495f453a920c262f66e5e72abd12501c33e05ce88051cddf300c00621a4d70"
)

PLAN_NAME = "oidcc-config-certification-test-plan"
# No variant is sent. The Config plan pins both of its variant parameters
# (server_metadata=discovery, client_registration=static_client) itself, and
# naming either one is rejected with "Variant '<name>' has been set by user, but
# test plan already sets this variant". Richer plans such as Basic OP do take
# variants, so rung 1 will need this to become a per-plan value.
PLAN_VARIANT = None

# Identity, not just cardinality. A plan that silently stopped shipping a module
# would otherwise run fewer tests and still exit 0 — the failure mode this whole
# harness is most likely to die of.
EXPECTED_MODULES = ["oidcc-discovery-endpoint-verification"]

CONFIG = HERE / "config" / "oidcc-config-op.json"
EXPECTED = HERE / "config" / "expected.json"
CERT_DIR = HERE / ".certs"
RESULTS = HERE / "results"

PORT = os.environ.get("CONFORMANCE_PORT", "8099")
API = f"http://localhost:{PORT}/api/"


def log(msg):
    print(f"[conformance] {msg}", flush=True)


def compose(*args, **kw):
    env = dict(os.environ, SUITE_IMAGE=SUITE_IMAGE, CONFORMANCE_PORT=PORT)
    return subprocess.run(
        ["docker", "compose", "-f", str(HERE / "docker-compose.yml"), *args],
        env=env, **kw,
    )


def api(path, method="GET", params=None, body=None, timeout=30):
    url = API + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    data = body.encode() if isinstance(body, str) else body
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    # The suite refuses any request it believes arrived over plain http, and
    # upstream solves that with an nginx terminating TLS in front of it. Tomcat's
    # RemoteIpValve is already in the suite's filter chain and trusts private
    # ranges, and a port-mapped request reaches the container from the docker
    # gateway (172.16/12), so declaring the scheme here is enough and saves
    # carrying a fourth container. Without it every call fails as HTTP 500 with
    # "A non-https request has been received by the conformance suite".
    req.add_header("X-Forwarded-Proto", "https")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        # The suite puts the actual reason in the body; a bare "HTTP Error 400"
        # says nothing and costs a debugging round trip every time.
        return e.code, {"error": e.read().decode(errors="replace")[:2000]}


def container_running(service):
    out = compose("ps", "-q", service, capture_output=True, text=True)
    cid = out.stdout.strip()
    if not cid:
        return False
    st = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", cid],
                        capture_output=True, text=True)
    return st.stdout.strip() == "true"


def wait_for(label, service, probe, timeout):
    """Wait for a service to answer, and give up early if it has died.

    The early exit matters: a container that crashes during startup would
    otherwise be waited on for the full timeout, and the reported symptom would
    be "not ready" rather than the stack trace that actually explains it.
    """
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        if not container_running(service):
            log(f"{label}: container exited during startup")
            return False
        try:
            if probe():
                log(f"{label}: ready")
                return True
        except Exception as e:  # noqa: BLE001 - any failure here just means "not yet"
            last = e
        time.sleep(2)
    log(f"{label}: NOT ready after {timeout}s (last error: {last})")
    return False


def emulator_ready():
    out = compose("exec", "-T", "entra-emulator", "/usr/local/bin/entra-emulator",
                  "healthcheck", capture_output=True)
    return out.returncode == 0


def suite_ready():
    status, _ = api("plan", params={"length": 1})
    return status == 200


def extract_cert():
    """Lift the emulator's self-signed CA out of its container.

    It is generated on first boot inside the container rather than into a bind
    mount, because the image runs as uid 65532 and could not write into a host
    directory owned by the CI runner.
    """
    CERT_DIR.mkdir(exist_ok=True)
    dest = CERT_DIR / "cert.pem"
    r = compose("cp", "entra-emulator:/app/data/tls/cert.pem", str(dest))
    if r.returncode != 0 or not dest.exists() or dest.stat().st_size == 0:
        raise SystemExit("could not extract the emulator's TLS certificate")
    log(f"certificate extracted ({dest.stat().st_size} bytes)")


def run_plan():
    plan_body = CONFIG.read_text()
    params = {"planName": PLAN_NAME}
    if PLAN_VARIANT:
        params["variant"] = json.dumps(PLAN_VARIANT)
    status, plan = api("plan", method="POST", params=params, body=plan_body)
    if status != 201:
        raise SystemExit(f"could not create the plan: HTTP {status}: {plan}")
    plan_id = plan["id"]
    log(f"plan {plan_id} ({PLAN_NAME})")

    modules = [m["testModule"] for m in plan.get("modules", [])]
    if modules != EXPECTED_MODULES:
        raise SystemExit(
            "the plan's module list changed.\n"
            f"  expected: {EXPECTED_MODULES}\n"
            f"  got     : {modules}\n"
            f"Upstream {SUITE_VERSION} may have altered the plan. Re-check the "
            "plan definition before widening EXPECTED_MODULES; a shrinking list "
            "means this harness is testing less than it claims to."
        )

    results = {}
    for module in modules:
        status, test = api("runner", method="POST",
                           params={"test": module, "plan": plan_id})
        if status != 201:
            raise SystemExit(f"could not create {module}: HTTP {status}: {test}")
        test_id = test["id"]
        log(f"running {module} ({test_id})")

        # INTERRUPTED is terminal too. A module that dies early never reaches
        # FINISHED, and waiting the full timeout for it turns a five-second
        # answer into a five-minute one that reports a stall instead of the
        # reason. Observed with a deliberately broken discovery document.
        terminal = {"FINISHED", "INTERRUPTED"}
        deadline = time.monotonic() + 300
        info = {}
        while time.monotonic() < deadline:
            _, info = api("info/" + test_id)
            if info.get("status") in terminal:
                break
            time.sleep(2)
        else:
            raise SystemExit(
                f"{module} never reached a terminal state "
                f"(last status {info.get('status')!r})"
            )

        results[module] = {
            "testId": test_id,
            "result": info.get("result"),
            "status": info.get("status"),
        }
        log(f"  {module}: {info.get('status')} / {info.get('result')}")

        RESULTS.mkdir(exist_ok=True)
        _, testlog = api("log/" + test_id, timeout=120)
        (RESULTS / f"{module}.json").write_text(json.dumps(testlog, indent=2))

    return plan_id, results


def judge(results):
    """Enumerate good, default deny: only PASSED is green unless declared."""
    declared = json.loads(EXPECTED.read_text()).get("modules", {})
    bad = []
    for module, r in results.items():
        if r["status"] != "FINISHED":
            bad.append(f"{module}: did not finish (status {r['status']})")
            continue
        if r["result"] == "PASSED":
            continue
        entry = declared.get(module)
        if entry and entry.get("result") == r["result"]:
            log(f"  {module}: {r['result']} is DECLARED — {entry.get('reason')}")
            continue
        bad.append(f"{module}: {r['result']} (declared: {entry})")
    return bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true",
                    help="leave the stack running for inspection at "
                         "http://localhost:$CONFORMANCE_PORT/")
    args = ap.parse_args()

    if shutil.which("docker") is None:
        raise SystemExit("docker is required")

    try:
        log("starting the emulator and mongo")
        compose("up", "-d", "--build", "entra-emulator", "mongodb", check=True)
        if not wait_for("emulator", "entra-emulator", emulator_ready, 120):
            compose("logs", "entra-emulator")
            raise SystemExit(1)

        extract_cert()

        log(f"building the suite image on {SUITE_VERSION}")
        compose("up", "-d", "--build", "conformance", check=True)
        if not wait_for("suite", "conformance", suite_ready, 300):
            compose("logs", "conformance")
            raise SystemExit(1)

        plan_id, results = run_plan()
        bad = judge(results)

        print()
        print(f"plan   : {PLAN_NAME} ({plan_id})")
        print(f"suite  : {SUITE_VERSION}")
        print(f"modules: {len(results)} run, {len(bad)} undeclared non-PASSED")
        print(f"logs   : {RESULTS}")
        if bad:
            print()
            for b in bad:
                print(f"  UNDECLARED: {b}")
            print()
            print("Either fix the emulator, or record the outcome with a reason "
                  f"in {EXPECTED.relative_to(ROOT)}.")
            return 1
        return 0
    finally:
        if args.keep:
            log(f"--keep: stack left up on http://localhost:{PORT}/")
        else:
            compose("down", "-v", capture_output=True)


if __name__ == "__main__":
    sys.exit(main())
