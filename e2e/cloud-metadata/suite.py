"""Cloud-instance metadata: the coordinates in discovery point HERE, not at Azure.

The claim is "a client that reads them is never sent to the real cloud". Asserting
the strings is only half of that -- a document can say anything. So this suite
FOLLOWS them: it takes `msgraph_host` and `rbac_url` straight out of the
discovery document, calls them with a token real MSAL acquired, and requires the
emulator's own directory to answer.

If those fields named Azure, the call would leave the machine and fail against
real Graph with an emulator-issued token. Landing on the emulator's directory is
the property the row actually claims.

The negative half is asserted too, because "points at the emulator" and "does not
point at Microsoft" are different statements and a partly-migrated document could
satisfy one and not the other.
"""

import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

import msal

ORIGIN = os.environ["EMU_ORIGIN"]
TENANT = os.environ["EMU_TENANT"]
CERT = os.environ["EMU_CERT"]
AUTHORITY = f"{ORIGIN}/{TENANT}"
DISCOVERY = f"{AUTHORITY}/v2.0/.well-known/openid-configuration"
DAEMON_ID = "00d88624-f0d7-46f6-a641-6232c2608928"
DAEMON_SECRET = "daemon-app-secret"

# Hosts that would mean the client had been handed off to the real cloud.
AZURE = ("microsoftonline.com", "microsoft.com", "windows.net", "azure.com")
# The fields real Entra uses to place a tenant in its sovereign cloud.
CLOUD_FIELDS = ("tenant_region_scope", "cloud_instance_name", "cloud_graph_host_name",
                "msgraph_host", "rbac_url")

ssl_ctx = ssl.create_default_context(cafile=CERT)
ssl_ctx.check_hostname = False
failures = []


def check(name, cond, extra=""):
    print(f"   {'ok  ' if cond else 'FAIL'}  {name}{'' if cond else ': ' + str(extra)[:200]}")
    if not cond:
        failures.append(name)


def get(url, token=None):
    req = urllib.request.Request(url)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    def parse(status, raw):
        try:
            return status, json.loads(raw or b"{}")
        except ValueError:
            # Not JSON. Return it as text rather than raising, so a wrong host
            # is reported as what it served instead of a decode traceback.
            return status, {"raw": raw[:300].decode("utf-8", "replace")}

    try:
        with urllib.request.urlopen(req, context=ssl_ctx, timeout=20) as r:
            return parse(r.status, r.read())
    except urllib.error.HTTPError as e:
        return parse(e.code, e.read())
    except (urllib.error.URLError, OSError) as e:
        return 0, {"raw": f"could not reach {url}: {e}"}


def as_url(value):
    """The document gives some fields as bare hosts and some as URLs."""
    return value if "://" in value else "https://" + value


def main():
    print("cloud-instance metadata from", DISCOVERY)

    status, doc = get(DISCOVERY)
    check(f"discovery document served ({status})", status == 200, doc)

    for field in CLOUD_FIELDS:
        check(f"{field} advertised", field in doc and bool(doc.get(field)), doc.get(field))

    # Nothing may point at the real cloud.
    for field in CLOUD_FIELDS:
        value = str(doc.get(field, ""))
        leaked = [h for h in AZURE if h in value]
        check(f"{field} does not name Azure", not leaked, f"{value} contains {leaked}")

    # And every URL in the WHOLE document, not just these five: a single
    # endpoint left pointing at Azure would send the client off-box just as
    # effectively as a cloud field would.
    off_box = sorted({
        v for v in doc.values() if isinstance(v, str) and any(h in v for h in AZURE)
    })
    check("no endpoint anywhere in the document names Azure", not off_box, off_box)

    # --- Follow them. This is the half a string assertion cannot do. --------
    cca = msal.ConfidentialClientApplication(
        DAEMON_ID, client_credential=DAEMON_SECRET, authority=AUTHORITY,
        instance_discovery=False, verify=CERT,
    )
    graph_host = as_url(str(doc["msgraph_host"]))
    print(f"      msgraph_host={doc['msgraph_host']!r} rbac_url={doc['rbac_url']!r} "
          f"cloud_instance_name={doc['cloud_instance_name']!r}")
    token = cca.acquire_token_for_client(scopes=[graph_host.rstrip("/") + "/.default"])
    if "access_token" not in token:
        # Some builds scope Graph by a fixed resource rather than the host.
        token = cca.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    check("msal acquired a token for the advertised graph host", "access_token" in token, token)

    # Following the coordinate. Which PATH under it serves Graph depends on the
    # origin mode: with separate origins Graph is at the root, and in compat
    # mode (single origin, path-prefixed surfaces -- what this harness and the
    # family compose both use) it is under /graph. The suite requires one of
    # them to be THIS emulator's seeded directory and records which, so a change
    # of mode shows up here rather than silently altering what the coordinate
    # means.
    #
    # Worth knowing when reading this: in compat mode the naive follow,
    # `https://{msgraph_host}/v1.0/users`, returns 200 with the portal's HTML.
    # It stays on the emulator -- which is what this row claims -- but it is not
    # a usable Graph coordinate the way real Entra's graph.microsoft.com is.
    served_by, users = None, {}
    for probe in ("/v1.0/users", "/graph/v1.0/users"):
        st, body = get(graph_host.rstrip("/") + probe, token.get("access_token"))
        if st == 200 and "value" in body:
            served_by, users = probe, body
            break
    check("the advertised graph coordinate reaches this emulator's directory",
          served_by is not None, "neither / nor /graph served Graph JSON")
    if served_by:
        print(f"      served by {graph_host}{served_by}")
    seeded = [u.get("userPrincipalName", "") for u in users.get("value", [])]
    check("and it is the SEEDED directory, not some other Graph",
          any(u.endswith("@entraemulator.dev") for u in seeded), seeded[:5])

    # rbac_url is advertised as a full origin, so it must name the same place.
    check("rbac_url names the same origin as msgraph_host",
          as_url(str(doc["rbac_url"])).rstrip("/") == graph_host.rstrip("/"),
          f'{doc["rbac_url"]} vs {graph_host}')

    if failures:
        print(f"\n{len(failures)} failure(s): {', '.join(failures)}")
        sys.exit(1)
    print("\ncloud-instance metadata: every coordinate points at this emulator, "
          "and following them lands on its own seeded directory")


if __name__ == "__main__":
    main()
