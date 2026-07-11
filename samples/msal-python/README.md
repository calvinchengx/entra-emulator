# MSAL Python sample

App-only (client-credentials) token acquisition with
[`msal`](https://pypi.org/project/msal/), then a call to the emulated
Microsoft Graph.

```sh
# 1. Start the emulator (compat mode keeps everything on https://localhost:8443)
ORIGIN_MODE=compat ./entra-emulator          # from the repo root

# 2. Run the sample
cd samples/msal-python
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python main.py
```

Expected output:

```
✓ token acquired — aud=https://graph.microsoft.com appid=cccccccc-… exp=…
✓ GET /graph/v1.0/users → 2 users:
    - Alice Example <alice@entraemulator.dev>
    - Bob Example <bob@entraemulator.dev>
```

MSAL Python trusts the emulator's self-signed cert via `verify="<cert>"`; the
sample defaults to `../../data/tls/cert.pem`. Override any default with an env
var: `EMU_ORIGIN`, `EMU_TENANT`, `EMU_CLIENT_ID`, `EMU_CLIENT_SECRET`,
`EMU_CERT`.
