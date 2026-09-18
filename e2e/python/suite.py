"""Real-MSAL-Python e2e suite against a running emulator (via e2e/run.sh).

Covers client credentials, the device-code flow, and OIDC `max_age` +
`auth_time`, with the human approval and the sign-in page driven over HTTPS.
Env: EMU_ORIGIN, EMU_TENANT, EMU_CERT.
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
SPA_ID = "189c7070-78a3-4c13-aa18-20a2ca5755ca"
DAEMON_ID = "00d88624-f0d7-46f6-a641-6232c2608928"
DAEMON_SECRET = "daemon-app-secret"
ALICE_ID = "df8ec5dd-1599-45ef-908b-4ae020cd1dbe"
SPA_REDIRECT = "https://localhost:3000"

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
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=ssl_ctx),
    urllib.request.HTTPCookieProcessor(jar),
)
STATE_RE = re.compile(r'name="__ee_state" value="([^"]+)"')


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


def new_browser():
    """An opener with its OWN cookie jar that does not chase redirects.

    Its own jar because an SSO session established elsewhere in this suite (the
    device-code approval signs Alice in) would otherwise make the first
    authorize request below reuse a session instead of authenticating, which is
    the very distinction max_age turns on. No redirect-following because the
    authorization response is a 302 to https://localhost:3000, where nothing is
    listening: reading the Location off the response is what a browser-less
    client does.
    """
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl_ctx),
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        _NoRedirect,
    )


def post_form(url, fields):
    data = urllib.parse.urlencode(fields).encode()
    with opener.open(urllib.request.Request(url, data=data)) as resp:
        return resp.read().decode()


def approve_device_code(user_code):
    verify = f"{AUTHORITY}/oauth2/v2.0/devicecode/verify"
    page = post_form(verify, {"__ee_step": "lookup", "user_code": user_code})
    state = STATE_RE.search(page).group(1)
    page = post_form(verify, {"__ee_step": "signin", "__ee_state": state, "__ee_user": ALICE_ID})
    state = STATE_RE.search(page).group(1)
    page = post_form(verify, {"__ee_step": "decide", "__ee_state": state, "__ee_decision": "approve"})
    assert "all set" in page, page[:300]


# ---- OIDC max_age / auth_time, driven by MSAL Python's own validation ----
#
# MSAL is the oracle here, not our assertions: obtain_token_by_auth_code_flow
# REFUSES a result when max_age was requested and the ID token carries no
# auth_time ("13. max_age was requested, ID token should contain auth_time"),
# and refuses again when the auth_time it does carry is older than the max_age
# asked for. So a token that comes back at all is a third party agreeing that
# the emulator honoured OIDC Core 3.1.2.1.


def set_clock(body):
    """Move the emulator's controllable clock, so a max_age boundary can be
    crossed without the suite sleeping through it."""
    data = json.dumps(body).encode()
    req = urllib.request.Request(f"{ORIGIN}/admin/api/clock", data=data,
                                 headers={"Content-Type": "application/json"})
    with opener.open(req) as resp:
        return json.loads(resp.read())


def reset_clock():
    req = urllib.request.Request(f"{ORIGIN}/admin/api/clock", method="DELETE")
    with opener.open(req) as resp:
        resp.read()


def authorize(browser, auth_uri):
    """GET an authorization URI. Returns (signed_state, auth_response).

    Exactly one of the two is set: signed_state when the emulator demanded
    credentials, auth_response when it answered from the existing SSO session.
    """
    try:
        with browser.open(auth_uri) as resp:
            body = resp.read().decode()
            loc = resp.headers.get("Location")
    except urllib.error.HTTPError as e:
        body, loc = e.read().decode(), e.headers.get("Location")
    if loc:
        return None, dict(urllib.parse.parse_qsl(urllib.parse.urlparse(loc).query))
    m = STATE_RE.search(body)
    if not m:
        raise AssertionError(f"neither a redirect nor a sign-in page: {body[:300]}")
    return m.group(1), None


def sign_in(browser, state):
    """Complete the interactive POST; returns the authorization response."""
    data = urllib.parse.urlencode({"__ee_state": state, "__ee_user": ALICE_ID}).encode()
    req = urllib.request.Request(f"{AUTHORITY}/oauth2/v2.0/authorize", data=data)
    try:
        with browser.open(req) as resp:
            loc = resp.headers.get("Location")
    except urllib.error.HTTPError as e:
        loc = e.headers.get("Location")
    if not loc:
        raise AssertionError("sign-in did not redirect")
    return dict(urllib.parse.parse_qsl(urllib.parse.urlparse(loc).query))


def max_age_checks(pca):
    browser = new_browser()
    # 1. First authentication establishes the SSO session.
    flow = pca.initiate_auth_code_flow(scopes=[], redirect_uri=SPA_REDIRECT)
    state, response = authorize(browser, flow["auth_uri"])
    check("max_age: first request asks for credentials", state is not None)
    result = pca.acquire_token_by_auth_code_flow(flow, sign_in(browser, state))
    check("max_age: auth code flow completed", "id_token" in result, str(result))
    check("auth_time absent without max_age",
          "auth_time" not in result.get("id_token_claims", {}),
          str(result.get("id_token_claims")))

    # 2. A generous ceiling reuses that session — and MSAL still requires
    #    auth_time, because max_age was on the request.
    set_clock({"advanceSeconds": 300})
    flow = pca.initiate_auth_code_flow(scopes=[], redirect_uri=SPA_REDIRECT, max_age=10000)
    state, response = authorize(browser, flow["auth_uri"])
    check("max_age=10000: session reused, no re-authentication", state is None)
    if state is None:
        result = pca.acquire_token_by_auth_code_flow(flow, response)
        claims = result.get("id_token_claims", {})
        check("max_age=10000: msal accepted the id_token", "id_token" in result, str(result))
        check("max_age=10000: auth_time present", "auth_time" in claims, str(claims))
        # The reused session reports the ORIGINAL authentication. The clock
        # moved 300s between the two, so an auth_time tracking issuance would
        # sit on top of iat instead of behind it.
        check("auth_time is the original authentication, not this issuance",
              claims.get("iat", 0) - claims.get("auth_time", 0) >= 300, str(claims))

    # 2b. A REFRESH must describe the same authentication, not a new one. MSAL
    #     drives this itself: acquire_token_silent with force_refresh redeems
    #     the refresh token over the wire. The claim to check is agreement — an
    #     amr or auth_time that changes across a refresh means the emulator is
    #     contradicting its own earlier token about how and when the user
    #     signed in, and the user did nothing in between.
    if state is None and "id_token_claims" in result:
        before = result["id_token_claims"]
        accounts = pca.get_accounts()
        check("refresh: msal has an account to refresh", bool(accounts))
        if accounts:
            set_clock({"advanceSeconds": 600})
            refreshed = pca.acquire_token_silent(
                scopes=[], account=accounts[0], force_refresh=True)
            check("refresh: msal redeemed the refresh token",
                  bool(refreshed) and "id_token_claims" in (refreshed or {}),
                  str(refreshed))
            if refreshed and "id_token_claims" in refreshed:
                after = refreshed["id_token_claims"]
                check("refresh: amr survives and is unchanged",
                      after.get("amr") == before.get("amr"),
                      f"{before.get('amr')} -> {after.get('amr')}")
                # This app has not opted into auth_time via optionalClaims, and
                # the refresh request carries no max_age, so auth_time is
                # correctly ABSENT here. Asserting the absence keeps the rule
                # honest: it is the same rule the code exchange follows, not a
                # claim that quietly went missing.
                check("refresh: auth_time absent without an opt-in (matches Entra)",
                      "auth_time" not in after, str(after))
                check("refresh: still the same user and issuer",
                      after.get("oid") == before.get("oid")
                      and after.get("iss") == before.get("iss"), str(after))

    # 3. Past the ceiling, the emulator must re-authenticate rather than reuse.
    flow = pca.initiate_auth_code_flow(scopes=[], redirect_uri=SPA_REDIRECT, max_age=1)
    state, response = authorize(browser, flow["auth_uri"])
    check("max_age=1 against a 300s-old session: re-authentication forced",
          state is not None)
    if state is not None:
        result = pca.acquire_token_by_auth_code_flow(flow, sign_in(browser, state))
        claims = result.get("id_token_claims", {})
        # MSAL raises rather than returning if auth_time is missing or stale,
        # so reaching here at all is the third-party verdict.
        check("max_age=1: msal accepted the re-authenticated id_token",
              "id_token" in result, str(result))
        check("max_age=1: auth_time is the fresh authentication",
              claims.get("iat", 0) - claims.get("auth_time", 1) <= 1, str(claims))
    reset_clock()


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
          idc.get("preferred_username") == "alice@entraemulator.dev", str(idc))
    check("device code: refresh token present", "refresh_token" in result)

    # --- OIDC max_age + auth_time ---
    # A fresh PublicClientApplication so the device-code tokens above are not in
    # the cache; the auth-code legs must really go to the wire.
    max_age_checks(msal.PublicClientApplication(
        SPA_ID, authority=AUTHORITY, instance_discovery=False, verify=CERT,
    ))

    if failures:
        print(f"\n{failures} failure(s)")
        sys.exit(1)
    print("\nPython (msal) e2e: all checks passed")


if __name__ == "__main__":
    main()
