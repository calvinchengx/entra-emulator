"""Minimal MSAL Python sample: acquire an app-only (client-credentials) token
from the emulator and call the emulated Microsoft Graph with it.

  1. Start the emulator:  ORIGIN_MODE=compat ./entra-emulator
  2. Run this sample:     pip install -r requirements.txt && python main.py

Every value defaults to a seeded dev constant; override via env if needed.
"""

import base64
import json
import os
import ssl
import urllib.request

import msal

ORIGIN = os.environ.get("EMU_ORIGIN", "https://localhost:8443")
TENANT = os.environ.get("EMU_TENANT", "11111111-1111-1111-1111-111111111111")
CLIENT_ID = os.environ.get("EMU_CLIENT_ID", "cccccccc-0000-0000-0000-000000000002")
CLIENT_SECRET = os.environ.get("EMU_CLIENT_SECRET", "daemon-app-secret")
# Path to the emulator's self-signed cert (entra-emulator cert-path).
CERT = os.environ.get("EMU_CERT", "../../data/tls/cert.pem")

AUTHORITY = f"{ORIGIN}/{TENANT}"


def decode_jwt(jwt: str) -> dict:
    payload = jwt.split(".")[1]
    payload += "=" * (-len(payload) % 4)  # pad base64url
    return json.loads(base64.urlsafe_b64decode(payload))


app = msal.ConfidentialClientApplication(
    CLIENT_ID,
    client_credential=CLIENT_SECRET,
    authority=AUTHORITY,
    instance_discovery=False,  # emulator isn't a real cloud; skip AAD metadata probe
    verify=CERT,               # trust the emulator's self-signed cert
)

result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
if "access_token" not in result:
    raise SystemExit(f"token request failed: {result.get('error_description', result)}")

claims = decode_jwt(result["access_token"])
print(f"✓ token acquired — aud={claims['aud']} appid={claims.get('appid')} exp={claims['exp']}")

# Call the emulated Graph with the token, trusting the same cert.
ctx = ssl.create_default_context(cafile=CERT)
req = urllib.request.Request(
    f"{ORIGIN}/graph/v1.0/users",
    headers={"Authorization": f"Bearer {result['access_token']}"},
)
with urllib.request.urlopen(req, context=ctx) as resp:
    users = json.loads(resp.read()).get("value", [])
print(f"✓ GET /graph/v1.0/users → {len(users)} users:")
for u in users:
    print(f"    - {u['displayName']} <{u['userPrincipalName']}>")
