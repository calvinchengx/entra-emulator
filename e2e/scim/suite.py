"""Real-SCIM-client e2e suite against a running emulator (via e2e/run.py).

Drives the emulator's SCIM service provider with scim2-tester, an independent
RFC 7643/7644 compliance checker, rather than with our own client. Microsoft
ships no runnable SCIM client: their provisioning service is a cloud service,
their SCIM Validator is hosted and cannot reach localhost, and SCIMReferenceCode
is a server. So the strongest available witness here is a third party, not a
Microsoft library.

Env: EMU_ORIGIN.

The checker's own count is the assertion. Five checks are expected failures and
are pinned by name below: each is a place the emulator's directory model — which
mirrors Entra's — cannot represent what unconstrained SCIM allows. Pinning them
by name rather than by count means a NEW failure fails the suite, while the known
boundaries stay green and stay documented.
"""

import collections
import os
import sys

from httpx import Client
from scim2_client.engines.httpx import SyncSCIMClient
from scim2_tester import check_server

ORIGIN = os.environ["EMU_ORIGIN"]
TOKEN = os.environ.get("EMU_SCIM_TOKEN", "scim-secret-token")

# Known, documented boundaries — see docs/10-scim-provisioning.md.
#
#   emails.type / emails.primary   the directory keeps one mail address, as
#                                  Entra's user does; it is not a typed
#                                  multi-valued SCIM collection, so a patched
#                                  type/primary round-trips as work/true.
#   members.display                membership display is derived from the
#                                  member's displayName, not stored per edge,
#                                  so a caller cannot set it independently.
#   active removal                 accountEnabled is non-nullable in the
#                                  directory, exactly as in Entra, so remove
#                                  resets it to the default rather than unsetting.
EXPECTED_FAILURES = {
    ("check_add_attribute", "emails"),
    ("check_replace_attribute", "emails"),
    ("check_add_attribute", "members"),
    ("check_replace_attribute", "members"),
    ("check_remove_attribute", "active"),
}


def attribute_of(reason: str) -> str:
    """The attribute a failure is about, for matching against EXPECTED_FAILURES."""
    for attr in ("emails", "members", "active", "displayName", "name", "externalId"):
        if f"'{attr}'" in reason:
            return attr
    return ""


def main() -> int:
    client = Client(
        base_url=f"{ORIGIN}/scim/v2",
        headers={"Authorization": f"Bearer {TOKEN}"},
        verify=False,  # the emulator serves a self-signed dev cert
        timeout=30.0,
    )
    scim = SyncSCIMClient(client)
    scim.discover()
    results = check_server(scim)

    tally = collections.Counter(r.status.name for r in results)
    print(f"scim2-tester: {dict(tally)}")

    unexpected = []
    matched = set()
    for r in results:
        if r.status.name != "ERROR":
            continue
        reason = (getattr(r, "reason", "") or "").split("\n")[0]
        key = (r.title, attribute_of(reason))
        if key in EXPECTED_FAILURES:
            matched.add(key)
            continue
        unexpected.append(f"{r.title}: {reason}")

    for line in unexpected:
        print(f"  FAIL {line}")

    # A boundary that starts passing is also news: it means the code moved and
    # the pin is now lying about what the emulator cannot do.
    stale = EXPECTED_FAILURES - matched
    for title, attr in sorted(stale):
        print(f"  STALE expected-failure now passes: {title} / {attr}")

    if tally.get("SUCCESS", 0) == 0:
        print("  FAIL checker produced no successes at all")
        return 1

    ok = not unexpected and not stale
    print("PASS" if ok else f"FAIL ({len(unexpected)} unexpected, {len(stale)} stale)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
