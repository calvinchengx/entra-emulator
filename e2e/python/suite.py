"""Real-MSAL-Python e2e suite against a running emulator (via e2e/run.sh).

Covers client credentials and the device-code flow, with the human approval
driven concurrently over HTTPS. Env: EMU_ORIGIN, EMU_TENANT, EMU_CERT.
"""

import base64
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
SPA_ID = "cccccccc-0000-0000-0000-000000000001"
DAEMON_ID = "cccccccc-0000-0000-0000-000000000002"
DAEMON_SECRET = "daemon-app-secret"
ALICE_ID = "aaaaaaaa-0000-0000-0000-000000000001"

failures = 0


def check(name, cond, extra=""):
    global failures
    if cond:
        print(f"  ok  {name}")
    else:
        print(f"  FAIL {name} {extra}")
        failures += 1


def decode_jwt(jwt):
    payload = jwt.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


# HTTPS driver for the approval pages (cookie jar + emulator CA).
ssl_ctx = ssl.create_default_context(cafile=CERT)
ssl_ctx.check_hostname = False  # cert covers localhost, but keep CI hosts simple
opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=ssl_ctx),
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
)
STATE_RE = re.compile(r'name="__el_state" value="([^"]+)"')


def post_form(url, fields):
    data = urllib.parse.urlencode(fields).encode()
    with opener.open(urllib.request.Request(url, data=data)) as resp:
        return resp.read().decode()


def approve_device_code(user_code):
    verify = f"{AUTHORITY}/oauth2/v2.0/devicecode/verify"
    page = post_form(verify, {"__el_step": "lookup", "user_code": user_code})
    state = STATE_RE.search(page).group(1)
    page = post_form(verify, {"__el_step": "signin", "__el_state": state, "__el_user": ALICE_ID})
    state = STATE_RE.search(page).group(1)
    page = post_form(verify, {"__el_step": "decide", "__el_state": state, "__el_decision": "approve"})
    assert "all set" in page, page[:300]


def main():
    print("msal (Python) flows against", AUTHORITY)

    # --- Client credentials ---
    cca = msal.ConfidentialClientApplication(
        DAEMON_ID,
        client_credential=DAEMON_SECRET,
        authority=AUTHORITY,
        instance_discovery=False,
        verify=CERT,
    )
    result = cca.acquire_token_for_client(scopes=[f"api://{DAEMON_ID}/.default"])
    check("client_credentials: token acquired", "access_token" in result, str(result))
    claims = decode_jwt(result["access_token"])
    check(
        "client_credentials: aud + roles + sub",
        claims.get("aud") == f"api://{DAEMON_ID}"
        and "Tasks.Read.All" in claims.get("roles", [])
        and claims.get("sub") == DAEMON_ID,
        str(claims),
    )
    check("client_credentials: no oid/scp", "oid" not in claims and "scp" not in claims)

    # Cached second call (MSAL returns from cache, no network).
    again = cca.acquire_token_for_client(scopes=[f"api://{DAEMON_ID}/.default"])
    check("client_credentials: cache hit", again.get("token_source") in (None, "cache")
          or again["access_token"] == result["access_token"])

    # --- Wrong secret → invalid_client ---
    bad = msal.ConfidentialClientApplication(
        DAEMON_ID, client_credential="wrong", authority=AUTHORITY,
        instance_discovery=False, verify=CERT,
    )
    err = bad.acquire_token_for_client(scopes=[f"api://{DAEMON_ID}/.default"])
    check("wrong secret -> invalid_client", err.get("error") == "invalid_client", str(err))

    # --- Device code ---
    pca = msal.PublicClientApplication(
        SPA_ID, authority=AUTHORITY, instance_discovery=False, verify=CERT,
    )
    # MSAL Python adds the reserved OIDC scopes itself and rejects them as input.
    flow = pca.initiate_device_flow(scopes=[])
    check("device flow initiated", "user_code" in flow, str(flow))
    approver = threading.Thread(target=approve_device_code, args=(flow["user_code"],))
    approver.start()
    result = pca.acquire_token_by_device_flow(flow)
    approver.join(timeout=30)
    check("device code: tokens issued", "access_token" in result, str(result))
    idc = decode_jwt(result["id_token"])
    check("device code: approving user is alice",
          idc.get("preferred_username") == "alice@entralocal.dev", str(idc))
    check("device code: refresh token present", "refresh_token" in result)

    if failures:
        print(f"\n{failures} failure(s)")
        sys.exit(1)
    print("\nPython (msal) e2e: all checks passed")


if __name__ == "__main__":
    main()
