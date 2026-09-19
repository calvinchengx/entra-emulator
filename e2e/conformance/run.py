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
import ssl
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
# Upstream's TLS front end, published from the same release. The suite rejects
# any request it believes arrived over plain http, so this is not optional.
NGINX_IMAGE = (
    "registry.gitlab.com/openid/conformance-suite/nginx@sha256:"
    "6ea3f4b8854f1f3626c81350900962d9e5f86424791d8e72b378a26ee2f4c105"
)

# A plan names only the variants it does NOT pin itself. The Config plan pins
# both of its own, so it sends none; naming one is rejected with "Variant
# '<name>' has been set by user, but test plan already sets this variant". Basic
# OP pins response_type, client_auth_type and response_mode per module group and
# leaves client_registration to the caller.
#
# `modules` is identity, not just cardinality: a plan that silently stopped
# shipping a module would otherwise run fewer tests and still exit 0, which is
# the failure mode this harness is most likely to die of. The lists are captured
# from the plan the suite itself returns rather than transcribed from its source.
PLANS = {
    "config": {
        "plan": "oidcc-config-certification-test-plan",
        "variant": None,
        "config": "oidcc-config-op.json",
        "modules": ["oidcc-discovery-endpoint-verification"],
    },
    "basic": {
        "plan": "oidcc-basic-certification-test-plan",
        "variant": {"server_metadata": "discovery", "client_registration": "static_client"},
        "config": "oidcc-basic-op.json",
        "clients": True,
        "modules": [
            "oidcc-server",
            "oidcc-response-type-missing",
            "oidcc-userinfo-get",
            "oidcc-userinfo-post-header",
            "oidcc-userinfo-post-body",
            "oidcc-ensure-request-without-nonce-succeeds-for-code-flow",
            "oidcc-scope-profile",
            "oidcc-scope-email",
            "oidcc-scope-address",
            "oidcc-scope-phone",
            "oidcc-scope-all",
            "oidcc-alternate-happy-flow",
            "oidcc-display-page",
            "oidcc-display-popup",
            "oidcc-prompt-login",
            "oidcc-prompt-none-not-logged-in",
            "oidcc-prompt-none-logged-in",
            "oidcc-max-age-1",
            "oidcc-max-age-10000",
            "oidcc-ensure-request-with-unknown-parameter-succeeds",
            "oidcc-id-token-hint",
            "oidcc-login-hint",
            "oidcc-ui-locales",
            "oidcc-claims-locales",
            "oidcc-ensure-request-with-acr-values-succeeds",
            "oidcc-codereuse",
            "oidcc-codereuse-30seconds",
            "oidcc-ensure-registered-redirect-uri",
            "oidcc-ensure-post-request-succeeds",
            "oidcc-server-client-secret-post",
            "oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported",
            "oidcc-claims-essential",
            "oidcc-ensure-request-object-with-redirect-uri",
            "oidcc-refresh-token",
            "oidcc-ensure-request-with-valid-pkce-succeeds",
        ],
    },
}

EXPECTED = HERE / "config" / "expected.json"
CERT_DIR = HERE / ".certs"
RESULTS = HERE / "results"

PORT = os.environ.get("CONFORMANCE_PORT", "8443")
EMULATOR_PORT = os.environ.get("CONFORMANCE_EMULATOR_PORT", "8444")
API = f"https://localhost:{PORT}/api/"

# nginx generates a self-signed certificate for CN=localhost at image build
# time, so there is nothing to pin and nothing to trust. This context is for
# talking to the harness we just started on loopback, never to the emulator:
# the suite validates the emulator's certificate properly, out of the JDK
# truststore we imported it into.
TLS = ssl.create_default_context()
TLS.check_hostname = False
TLS.verify_mode = ssl.CERT_NONE


def log(msg):
    print(f"[conformance] {msg}", flush=True)


def compose(*args, **kw):
    env = dict(os.environ, SUITE_IMAGE=SUITE_IMAGE, NGINX_IMAGE=NGINX_IMAGE,
               CONFORMANCE_PORT=PORT, CONFORMANCE_EMULATOR_PORT=EMULATOR_PORT)
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
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=TLS) as r:
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


# What the suite calls itself on the compose network, and therefore the prefix
# of the callback it registers. Confirmed against the suite's own
# CreateRedirectUri output rather than assumed.
SUITE_BASE = "https://nginx:8443"


def emulator_admin(path, body):
    """POST to the emulator's admin API, through the suite's own network name.

    The admin API is unauthenticated by design (it is a local emulator), so
    there is no credential here to leak.
    """
    url = f"https://localhost:{EMULATOR_PORT}{path}"
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30, context=TLS) as r:
        return json.loads(r.read())


def seed_clients(alias):
    """Register the two confidential clients the Basic OP plan needs.

    Created per run rather than seeded into the emulator: the redirect URI
    depends on the plan alias, and a client id committed to a config file would
    go stale the moment the emulator's seed changed. `client2` exists because
    several modules check that one client cannot use another's code.
    """
    callback = f"{SUITE_BASE}/test/a/{alias}/callback"
    out = {}
    # `client2` exists because several modules check that one client cannot use
    # another's code. `client_secret_post` is a THIRD registration, not a
    # duplicate: OIDCCServerTestClientSecretPost copies that block over `client`
    # before running, because most real servers tie a client to one
    # authentication method. Omitting it fails the module at
    # GetStaticClientConfiguration with "the test configuration must contain a
    # client configuration", which reads as a missing `client` rather than a
    # missing `client_secret_post`.
    for key, name in (("client", "OIDF conformance client"),
                      ("client2", "OIDF conformance client 2"),
                      ("client_secret_post", "OIDF conformance client (secret post)")):
        app = emulator_admin("/admin/api/apps", {
            "displayName": name,
            # Confidential, or the emulator requires PKCE on every code request
            # ("Public clients must send a PKCE code_challenge") and every module
            # but the PKCE one fails at the authorization endpoint. The Basic OP
            # profile authenticates with client_secret_basic, which is precisely
            # what a confidential client is.
            "isConfidential": True,
            "redirectUris": [{"uri": callback, "type": "web"}],
        })
        secret = emulator_admin(f"/admin/api/apps/{app['id']}/secrets",
                                {"displayName": "conformance"})
        out[key] = {"client_id": app["id"], "client_secret": secret["secretText"]}
    log(f"registered {len(out)} client(s), redirect_uri {callback}")
    return out


# A 1x1 transparent PNG. Several Basic OP modules stop and ask a human to
# upload a screenshot of what the browser showed, and cannot reach a terminal
# state until one arrives. Certification is not the goal here (see
# docs/23-oidf-conformance.md), so the harness fills the placeholder to let the
# module finish, and the module then correctly ends as REVIEW rather than
# PASSED. That is the honest outcome: nobody looked at a screenshot, so nothing
# should claim otherwise. Every such module has to be declared in expected.json
# with that reason, and the run prints how many placeholders it filled.
MARKER_IMAGE = (
    "data:image/png;base64,"
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
)


def fill_placeholders(test_id):
    """Fill any screenshot placeholders this test is blocked on.

    Returns the number filled. An entry carries `upload` (the placeholder id)
    and gains `img` once filled, so an already-filled one is skipped and this is
    safe to call repeatedly.
    """
    _, entries = api("log/" + test_id, timeout=120)
    filled = 0
    for e in entries or []:
        if e.get("upload") and not e.get("img"):
            url = f"{API}log/{test_id}/images/{e['upload']}"
            req = urllib.request.Request(url, data=MARKER_IMAGE.encode(), method="POST")
            req.add_header("Content-Type", "text/plain")
            with urllib.request.urlopen(req, timeout=30, context=TLS):
                filled += 1
    return filled


# How long a module may sit in WAITING with no placeholder to fill before the
# harness gives up on it. Browser interactions take seconds, so this is
# generous; it exists so one unanswerable module cannot hide the rest.
STALL_SECONDS = 90


def save_log(module, test_id):
    RESULTS.mkdir(exist_ok=True)
    _, testlog = api("log/" + test_id, timeout=120)
    (RESULTS / f"{module}.json").write_text(json.dumps(testlog, indent=2))


def run_plan(spec, capture_modules=False):
    config = json.loads((HERE / "config" / spec["config"]).read_text())
    if spec.get("clients"):
        config.update(seed_clients(config["alias"]))
    plan_body = json.dumps(config)
    params = {"planName": spec["plan"]}
    if spec["variant"]:
        params["variant"] = json.dumps(spec["variant"])
    status, plan = api("plan", method="POST", params=params, body=plan_body)
    if status != 201:
        raise SystemExit(f"could not create the plan: HTTP {status}: {plan}")
    plan_id = plan["id"]
    log(f"plan {plan_id} ({spec['plan']})")

    # The module list is read back with GET rather than taken from the POST
    # response: the creation response carries `modules` for some plans and not
    # for others, and an absent key would read as "zero modules", which is
    # exactly the vacuous pass the identity check exists to prevent.
    _, record = api(f"plan/{plan_id}")
    modules = [m["testModule"] for m in (record.get("modules") or [])]
    if not modules:
        raise SystemExit(f"plan {plan_id} reports no modules at all")
    if capture_modules:
        # --capture-modules exists so the pinned list is DERIVED from the plan
        # the suite returns, never transcribed from its Java source by hand.
        print(json.dumps(modules, indent=4))
        raise SystemExit(0)
    if modules != spec["modules"]:
        missing = [m for m in spec["modules"] if m not in modules]
        added = [m for m in modules if m not in spec["modules"]]
        raise SystemExit(
            "the plan's module list changed.\n"
            f"  no longer present: {missing}\n"
            f"  newly present    : {added}\n"
            f"Upstream {SUITE_VERSION} may have altered the plan. Re-capture "
            "with --capture-modules and read the diff before accepting it; a "
            "shrinking list means this harness tests less than it claims to."
        )

    results = {}
    placeholders_filled = {}
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
        waiting_since = None
        stalled = False
        while time.monotonic() < deadline:
            _, info = api("info/" + test_id)
            if info.get("status") in terminal:
                break
            if info.get("status") == "WAITING":
                # Give the module a few seconds first: WAITING is also the
                # normal transient state while the scripted browser works, and
                # filling a placeholder the moment it appears would paper over a
                # genuine stall rather than expose it.
                waiting_since = waiting_since or time.monotonic()
                waited = time.monotonic() - waiting_since
                if waited > 10:
                    n = fill_placeholders(test_id)
                    if n:
                        placeholders_filled[module] = placeholders_filled.get(module, 0) + n
                        log(f"  {module}: filled {n} screenshot placeholder(s)")
                        waiting_since = None
                        continue
                if waited > STALL_SECONDS:
                    # Nothing left to unblock it. A module can wait forever when
                    # the OP answers the browser in a way the module has no task
                    # for, and one such module must not swallow the other 34, so
                    # record it and move on. STALLED is not PASSED, so the run
                    # still fails unless it is declared with a reason.
                    stalled = True
                    break
            else:
                waiting_since = None
            time.sleep(2)
        else:
            stalled = True

        if stalled:
            log(f"  {module}: STALLED in {info.get('status')} with nothing to fill")
            results[module] = {"testId": test_id, "result": "STALLED",
                               "status": info.get("status")}
            save_log(module, test_id)
            continue

        results[module] = {
            "testId": test_id,
            "result": info.get("result"),
            "status": info.get("status"),
        }
        log(f"  {module}: {info.get('status')} / {info.get('result')}")
        save_log(module, test_id)

    if placeholders_filled:
        total = sum(placeholders_filled.values())
        log(f"filled {total} screenshot placeholder(s) across "
            f"{len(placeholders_filled)} module(s); those modules end as REVIEW, "
            "which is not a pass")
    return plan_id, results


def judge(results, plan_key):
    """Enumerate good, default deny: only PASSED is green unless declared.

    Expectations are scoped per plan: the same module can legitimately be
    expected to pass under one plan and to fail under another, and a single flat
    table would quietly let a declaration leak across.
    """
    declared = json.loads(EXPECTED.read_text()).get("plans", {}).get(plan_key, {})
    bad = []
    for module, r in results.items():
        if r["result"] == "STALLED" or r["status"] != "FINISHED":
            label = ("STALLED" if r["result"] == "STALLED"
                     else f"did not finish (status {r['status']})")
            entry = declared.get(module)
            if entry and entry.get("result") == r["result"]:
                log(f"  {module}: {label} is DECLARED, {entry.get('reason')}")
                continue
            bad.append(f"{module}: {label}")
            continue
        if r["result"] == "PASSED":
            continue
        entry = declared.get(module)
        if entry and entry.get("result") == r["result"]:
            log(f"  {module}: {r['result']} is DECLARED, {entry.get('reason')}")
            continue
        bad.append(f"{module}: {r['result']} (declared: {entry})")

    # A declaration for a module that now passes is stale, and leaving it in
    # place would silently re-accept the failure if it ever came back.
    for module, entry in declared.items():
        if module not in results:
            bad.append(f"{module}: declared in expected.json but not in this plan")
        elif results[module]["result"] == "PASSED":
            bad.append(
                f"{module}: PASSES now, so the declaration is stale "
                f"(was: {entry.get('reason')}). Remove it."
            )
    return bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("plan", nargs="?", default="config", choices=sorted(PLANS),
                    help="which certification plan to run (default: config)")
    ap.add_argument("--keep", action="store_true",
                    help="leave the stack running for inspection at "
                         "https://localhost:$CONFORMANCE_PORT/")
    ap.add_argument("--capture-modules", action="store_true",
                    help="print the plan's module list and exit, for pinning")
    args = ap.parse_args()
    spec = PLANS[args.plan]

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
        compose("up", "-d", "--build", "conformance", "nginx", check=True)
        if not wait_for("suite", "conformance", suite_ready, 300):
            compose("logs", "conformance")
            raise SystemExit(1)

        plan_id, results = run_plan(spec, capture_modules=args.capture_modules)
        bad = judge(results, args.plan)

        print()
        print(f"plan   : {spec['plan']} ({plan_id})")
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
            log(f"--keep: stack left up on https://localhost:{PORT}/")
        else:
            compose("down", "-v", capture_output=True)


if __name__ == "__main__":
    sys.exit(main())
