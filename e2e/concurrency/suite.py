"""Concurrency contracts: single-use codes, refresh rotation and reuse detection.

The row this witnesses claims "real atomic SQL — not best-effort", and that is a
claim about what happens when the SAME credential is presented TWICE. A suite
that only walks the happy path cannot see it: every check here is a deliberate
second use.

WHY PART OF THIS IS RAW HTTP. Real MSAL does the legitimate half -- it initiates
the device flow, redeems the code, and rotates the refresh token, so the
credentials under test are ones a real client actually minted. The replays are
raw, because no client library will knowingly present a spent credential; asking
one to is asking it to be a different library. The raw half is a byte-level
repeat of the request MSAL itself just made.

THE RACES ARE THE POINT. Sequential replay catches a server that forgets to mark
a code spent. It does not catch a server that marks it spent without doing so
atomically -- that one only shows up when N requests arrive together and the
window between "check" and "mark" is open. So each credential is also presented
by several threads at once, and the suite asserts EXACTLY ONE winner. Best-effort
bookkeeping passes the sequential check and fails this one.

Measured, not assumed: replacing `ConsumeApprovedDeviceCode`'s single
`DELETE ... RETURNING` with a SELECT, a 5ms gap and a DELETE leaves
"spent device code refused" GREEN and turns the race red at 8 winners out of 8.
A stolen device code would mint unlimited tokens, and only the race sees it.
"""

import concurrent.futures
import http.cookiejar
import json
import os
import re
import ssl
import sys
import threading
import urllib.parse
import urllib.request

import msal

ORIGIN = os.environ["EMU_ORIGIN"]
TENANT = os.environ["EMU_TENANT"]
CERT = os.environ["EMU_CERT"]
AUTHORITY = f"{ORIGIN}/{TENANT}"
TOKEN_URL = f"{AUTHORITY}/oauth2/v2.0/token"
SPA_ID = "189c7070-78a3-4c13-aa18-20a2ca5755ca"
ALICE_ID = "df8ec5dd-1599-45ef-908b-4ae020cd1dbe"
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
RACERS = 8

ssl_ctx = ssl.create_default_context(cafile=CERT)
# The cert covers localhost; CI hosts vary. Same accommodation the sibling
# suites make, and unrelated to what is under test here.
ssl_ctx.check_hostname = False
STATE_RE = re.compile(r'name="__ee_state" value="([^"]+)"')
failures = []


def check(name, cond, extra=""):
    print(f"   {'ok  ' if cond else 'FAIL'}  {name}{'' if cond else ': ' + str(extra)[:200]}")
    if not cond:
        failures.append(name)


def post_form(url, fields):
    body = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, context=ssl_ctx, timeout=20) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw or b"{}")
        except ValueError:
            return e.code, {"raw": raw[:200].decode("utf-8", "replace")}


def approve_device_code(user_code):
    """Drive the emulator's device-approval pages, as the sibling suites do.

    Its OWN cookie jar: the three steps are one browser session, and this suite
    approves twice. A shared jar would carry the first approval's session into
    the second, which is precisely the kind of cross-talk this file is testing
    the server for.
    """
    verify = f"{AUTHORITY}/oauth2/v2.0/devicecode/verify"
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl_ctx),
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
    )

    def page(fields):
        data = urllib.parse.urlencode(fields).encode()
        with opener.open(urllib.request.Request(verify, data=data), timeout=20) as r:
            return r.read().decode()

    p = page({"__ee_step": "lookup", "user_code": user_code})
    p = page({"__ee_step": "signin", "__ee_state": STATE_RE.search(p).group(1),
              "__ee_user": ALICE_ID})
    p = page({"__ee_step": "decide", "__ee_state": STATE_RE.search(p).group(1),
              "__ee_decision": "approve"})
    assert "all set" in p, p[:300]


def race(fields, n=RACERS):
    """Present the same credential from n threads at once; return the responses."""
    barrier = threading.Barrier(n)

    def one(_):
        barrier.wait()          # release together, not staggered by thread start
        return post_form(TOKEN_URL, fields)

    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
        return list(pool.map(one, range(n)))


def approved_device_code():
    """A device_code that has been approved but not yet redeemed."""
    pca = msal.PublicClientApplication(
        SPA_ID, authority=AUTHORITY, instance_discovery=False, verify=CERT
    )
    flow = pca.initiate_device_flow(scopes=[])
    approve_device_code(flow["user_code"])
    return flow["device_code"]


def fresh_refresh_token():
    """A refresh token from its own complete device-code flow.

    Each scenario below needs an UNRELATED credential chain, because reuse
    detection revokes the whole family -- so reusing one chain across scenarios
    would have the server correctly killing a token the next check still wanted.
    """
    status, out = post_form(TOKEN_URL, {
        "grant_type": DEVICE_GRANT, "client_id": SPA_ID,
        "device_code": approved_device_code(),
    })
    assert "refresh_token" in out, out
    return out["refresh_token"]


def main():
    print("concurrency contracts against", AUTHORITY)

    # --- 1. A device code is single-use, and MSAL mints from it. -------------
    pca = msal.PublicClientApplication(
        SPA_ID, authority=AUTHORITY, instance_discovery=False, verify=CERT
    )
    flow = pca.initiate_device_flow(scopes=[])
    t = threading.Thread(target=approve_device_code, args=(flow["user_code"],))
    t.start()
    result = pca.acquire_token_by_device_flow(flow)
    t.join(timeout=30)
    check("msal minted tokens from the device code", "access_token" in result, result)
    refresh = result.get("refresh_token")

    status, again = post_form(TOKEN_URL, {
        "grant_type": DEVICE_GRANT, "client_id": SPA_ID, "device_code": flow["device_code"],
    })
    check(f"spent device code refused ({status})", status >= 400 and "error" in again, again)

    # --- 2. ...and the marking is ATOMIC, not merely eventual. ---------------
    code = approved_device_code()
    results = race({"grant_type": DEVICE_GRANT, "client_id": SPA_ID, "device_code": code})
    won = [r for _, r in results if "access_token" in r]
    check(f"exactly one of {RACERS} simultaneous redemptions won (got {len(won)})", len(won) == 1,
          [r for _, r in results])

    # --- 3. Refresh rotates, and reuse revokes the whole FAMILY. ------------
    check("device flow returned a refresh token", bool(refresh), result)
    rt0 = refresh

    def redeem(rt):
        return post_form(TOKEN_URL, {
            "grant_type": "refresh_token", "client_id": SPA_ID, "refresh_token": rt,
            "scope": "openid profile offline_access",
        })

    status, rot = redeem(rt0)
    check("refresh redeemed", "access_token" in rot, rot)
    rt1 = rot.get("refresh_token")
    check("refresh token rotated", bool(rt1) and rt1 != rt0,
          "the same refresh token came back, so nothing rotated")

    status, reused = redeem(rt0)
    check(f"reused refresh token refused ({status})", status >= 400 and "error" in reused, reused)

    # The part that makes it DETECTION rather than mere rejection: presenting a
    # spent token kills its successor too, so an attacker who replays a stolen
    # token cannot leave the legitimate holder working. Discovered by getting
    # this wrong -- the suite first assumed rt1 survived, and the emulator was
    # right to disagree.
    status, successor = redeem(rt1)
    check(f"reuse revoked the successor too ({status})",
          status >= 400 and "error" in successor,
          f"rt1 still worked after rt0 was replayed: {successor}")

    # --- 4. ...and rotation is atomic, on a chain of its own. ---------------
    racer = fresh_refresh_token()
    results = race({"grant_type": "refresh_token", "client_id": SPA_ID,
                    "refresh_token": racer, "scope": "openid profile offline_access"})
    won = [r for _, r in results if "access_token" in r]
    check(f"exactly one of {RACERS} simultaneous refreshes won (got {len(won)})", len(won) == 1,
          [r for _, r in results])

    if failures:
        print(f"\n{len(failures)} failure(s): {', '.join(failures)}")
        sys.exit(1)
    print("\nconcurrency contracts: spent credentials refused, exactly one winner under race")


if __name__ == "__main__":
    main()
