"""Outbound SCIM provisioning witnessed by Microsoft's own reference server.

The emulator is the SCIM *client* here: it pushes the directory out the way the
Entra provisioning service does. Witnessing that needs a real SCIM service
provider on the other end, and for once Microsoft ships one —
AzureAD/SCIMReferenceCode, the reference implementation their own docs point
developers at. That makes this the only Microsoft-authored witness in the SCIM
cluster; the inbound suite has to settle for an independent third party, because
Microsoft's SCIM *client* is a cloud service that cannot be run locally.

Env: EMU_ORIGIN.

Caveats, all deliberate and pinned:
  * the reference sample targets netcoreapp3.1, which is out of support. It is
    built with the .NET 8 SDK and run with DOTNET_ROLL_FORWARD=LatestMajor, so
    no EOL runtime is installed. Not one line of it is patched.
  * it is built Debug and run with ASPNETCORE_ENVIRONMENT=Development, which is
    the sample's documented local-test mode. A Release build strips the JWT
    bypass and demands a real OIDC Authority, which no offline test can supply.
  * it is cloned at a pinned commit, never at master, so the witness cannot
    change under us.
"""

import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = "https://github.com/AzureAD/SCIMReferenceCode.git"
PIN = "cc63c4b15cd8ad6d1becf90182c5fcb682b2b9ba"
PORT = os.environ.get("SCIMREF_PORT", "5111")
REF_BASE = f"http://localhost:{PORT}"

ORIGIN = os.environ["EMU_ORIGIN"]
# resolve() matters, it is not tidiness. On macOS TMPDIR is /var/folders/...,
# and /var is a symlink to /private/var. Handing MSBuild the unresolved path
# makes it canonicalise the sample's ProjectReference to a different path than
# the one it was given, so the referenced library's restore assets never match
# and the build fails with CS0234 across every package namespace — while the
# identical commands run with a relative path, or from an already-canonical
# directory, succeed.
WORK = (Path(os.environ.get("TMPDIR", "/tmp")) / "entra-scimref").resolve()

failures = 0


def check(name: str, cond: bool, extra: str = "") -> None:
    global failures
    print(f"  {'ok  ' if cond else 'FAIL'} {name}" + (f" {extra}" if not cond and extra else ""))
    if not cond:
        failures += 1


def req(url: str, method: str = "GET", body=None, token: str | None = None, insecure=False):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        r.add_header("Content-Type", "application/scim+json")
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    ctx = None
    if url.startswith("https"):
        import ssl

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(r, context=ctx, timeout=30) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, {"raw": raw}


def build_reference() -> Path:
    """Clone at the pinned commit and build with the .NET 8 SDK."""
    src = WORK / "src"
    if not (src / ".git").exists():
        WORK.mkdir(parents=True, exist_ok=True)
        shutil.rmtree(src, ignore_errors=True)
        subprocess.run(["git", "init", "-q", str(src)], check=True)
        subprocess.run(["git", "remote", "add", "origin", REPO], cwd=src, check=True)
        subprocess.run(["git", "fetch", "-q", "--depth", "1", "origin", PIN], cwd=src, check=True)
        subprocess.run(["git", "checkout", "-q", "FETCH_HEAD"], cwd=src, check=True)

    proj = src / "Microsoft.SCIM.WebHostSample" / "Microsoft.SCIM.WebHostSample.csproj"

    # Building this sample from a cold tree is genuinely awkward, and both
    # failure modes are quiet, so the recipe below is deliberate:
    #
    #   * the first `dotnet build` on a fresh tree can fail with CS0234 across
    #     every package namespace, because the implicit restore has not yet
    #     covered the ProjectReference to Microsoft.SCIM. A second build then
    #     succeeds. We therefore attempt twice before giving up.
    #   * `--no-restore` must NOT be used. With it the build succeeds and copies
    #     Microsoft.SCIM.dll next to the host, but writes a deps.json with no
    #     `runtime` entry for it, and the app dies at startup with "Could not
    #     load file or assembly 'Microsoft.SCIM'" while the file sits in the
    #     same directory. That is asserted below rather than trusted.
    subprocess.run(["dotnet", "restore", str(src / "Microsoft.SCIM.sln"), "-v", "q", "--nologo"],
                   cwd=src, capture_output=True, text=True)
    build = ["dotnet", "build", str(proj), "-c", "Debug", "-v", "q", "--nologo"]
    for attempt in (1, 2):
        done = subprocess.run(build, cwd=src, capture_output=True, text=True)
        if done.returncode == 0:
            break
        if attempt == 2:
            # Surface the compiler output; a silenced build failure here is
            # indistinguishable from a missing SDK.
            sys.stderr.write(done.stdout[-4000:] + done.stderr[-2000:])
            sys.exit("dotnet build of the SCIM reference sample failed twice")

    out = src / "Microsoft.SCIM.WebHostSample" / "bin" / "Debug" / "netcoreapp3.1"
    dll = out / "Microsoft.SCIM.WebHostSample.dll"
    if not dll.exists():
        sys.exit(f"reference build produced no dll at {dll}")

    # Assert the manifest actually loads the library. Checking the file exists
    # is not enough — that was true in the broken case too.
    deps = json.loads((out / "Microsoft.SCIM.WebHostSample.deps.json").read_text())
    target = next(iter(deps["targets"].values()))
    if not target.get("Microsoft.SCIM/1.0.0", {}).get("runtime"):
        sys.exit("deps.json carries no runtime entry for Microsoft.SCIM; "
                 "the host would start and immediately fail to load it")
    return dll


def start_reference(dll: Path) -> subprocess.Popen:
    env = {
        **os.environ,
        "DOTNET_ROLL_FORWARD": "LatestMajor",
        "ASPNETCORE_ENVIRONMENT": "Development",
        "ASPNETCORE_URLS": REF_BASE,
        "Token__IssuerSigningKey": "entra-emulator-e2e-signing-key-not-a-secret-0123456789",
        "Token__TokenIssuer": ORIGIN,
        "Token__TokenAudience": "scim-e2e",
        "Token__TokenLifetimeInMins": "60",
    }
    log = WORK / "reference-server.log"
    handle = open(log, "w")
    proc = subprocess.Popen(["dotnet", str(dll)], cwd=dll.parent, env=env,
                            stdout=handle, stderr=subprocess.STDOUT)
    deadline = time.time() + 60
    last = ""
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        try:
            code, _ = req(f"{REF_BASE}/scim/token")
            if code == 200:
                return proc
            last = f"token endpoint returned {code}"
        except Exception as e:  # not listening yet
            last = str(e)
        time.sleep(0.5)
    proc.terminate()
    handle.close()
    # Never fail silently here: without the server's own output, "did not
    # start" is indistinguishable from a port clash, a missing runtime and a
    # config error.
    sys.stderr.write(f"last probe: {last}\n--- reference server log ---\n")
    sys.stderr.write(log.read_text()[-4000:] if log.exists() else "(no log)")
    sys.exit("Microsoft SCIM reference server did not start")


def main() -> int:
    dll = build_reference()
    proc = start_reference(dll)
    try:
        _, tok = req(f"{REF_BASE}/scim/token")
        token = tok["token"]
        check("reference server issued a token", bool(token))

        # Point the emulator's provisioning client at the reference server.
        code, _ = req(f"{ORIGIN}/admin/api/scim/target", "POST",
                      {"endpoint": f"{REF_BASE}/scim", "token": token})
        check("emulator accepted the target", code == 200, str(code))

        # Full sync: the emulator pushes its directory out.
        code, result = req(f"{ORIGIN}/admin/api/scim/sync", "POST", {"mode": "full"})
        check("full sync ran", code == 200, str(result))
        created = result.get("created", 0)
        check("full sync created users on the target", created > 0, str(result))

        # The witness: Microsoft's server holds what we pushed.
        code, users = req(f"{REF_BASE}/scim/Users", token=token)
        check("reference server lists provisioned users", code == 200, str(code))
        resources = users.get("Resources") or []
        names = {u.get("userName") for u in resources}

        # Compare identities, not counts. `len(names) >= created` would pass on
        # a target holding unrelated users, or on ours failing to land while
        # someone else's were present — it asserts the shape of the result
        # rather than the result. Name the users we expect and look for those.
        _, ours = req(f"{ORIGIN}/scim/v2/Users", token="scim-secret-token")
        expected = {u["userName"] for u in (ours.get("Resources") or [])
                    if u.get("active") is not False}
        missing = sorted(expected - names)
        check("every enabled directory user reached the target", not missing,
              f"missing from target: {missing}")
        check("the target holds no users we did not push", not (names - expected),
              f"unexpected on target: {sorted(names - expected)}")

        # Entra correlates by externalId; the reference server round-trips it.
        ext = [u for u in resources if u.get("externalId")]
        check("externalId reached the target", len(ext) > 0,
              "no provisioned resource carried externalId")

        # Deprovision: disabling a user must push active:false, not a delete.
        target_user = next((u for u in resources if u.get("userName")), None)
        check("a user is available to deprovision", target_user is not None)
        if target_user:
            upn = target_user["userName"]
            code, listing = req(f"{ORIGIN}/scim/v2/Users?filter=userName eq \"{upn}\"".replace(" ", "%20"),
                                token="scim-secret-token")
            local = (listing.get("Resources") or [None])[0] if code == 200 else None
            if local:
                # The watermark is Unix seconds and incremental sync skips
                # users whose updated_at is <= it. The whole flow above runs
                # well inside one second, so without this wait the disable is
                # correctly judged "not newer than the last sync" and never
                # pushed — the test would be measuring its own speed.
                time.sleep(1.1)
                req(f"{ORIGIN}/scim/v2/Users/{local['id']}", "PATCH", {
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                    "Operations": [{"op": "replace", "path": "active", "value": False}],
                }, token="scim-secret-token")
                code, result = req(f"{ORIGIN}/admin/api/scim/sync", "POST", {"mode": "incremental"})
                check("incremental sync ran", code == 200, str(result))

                code, after = req(f"{REF_BASE}/scim/Users", token=token)
                match = next((u for u in (after.get("Resources") or [])
                              if u.get("userName") == upn), None)
                check("deprovision pushed active:false to the target",
                      match is not None and match.get("active") is False,
                      json.dumps(match)[:200] if match else "user missing from target")

        # The emulator's own trail should show Entra's sequence, not just writes.
        code, log = req(f"{ORIGIN}/admin/api/scim/log")
        actions = {e.get("action") for e in (log.get("value") or [])}
        check("provisioning trail records Entra's sequence", "probe" in actions and "create" in actions,
              str(sorted(a for a in actions if a)))

        print("PASS" if failures == 0 else f"FAIL ({failures})")
        return 0 if failures == 0 else 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())
