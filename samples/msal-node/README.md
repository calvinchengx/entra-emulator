# MSAL Node sample

App-only (client-credentials) token acquisition with
[`@azure/msal-node`](https://www.npmjs.com/package/@azure/msal-node), then a
call to the emulated Microsoft Graph.

```sh
# 1. Start the emulator (compat mode keeps everything on https://localhost:8443)
ORIGIN_MODE=compat ./entra-emulator          # from the repo root

# 2. Run the sample (trust the emulator's self-signed cert via NODE_EXTRA_CA_CERTS)
cd samples/msal-node
npm install
NODE_EXTRA_CA_CERTS=$(../../entra-emulator cert-path) npm start
```

Expected output:

```
✓ token acquired — aud=https://graph.microsoft.com appid=cccccccc-… exp=…
✓ GET /graph/v1.0/users → 200, 2 users:
    - Alice Example <alice@entraemulator.dev>
    - Bob Example <bob@entraemulator.dev>
```

Override any default with an env var: `EMU_ORIGIN`, `EMU_TENANT`,
`EMU_CLIENT_ID`, `EMU_CLIENT_SECRET`. See the
[quickstart](https://calvinchengx.github.io/entra-emulator/01-quickstart/) for
the delegated (user sign-in) flow.
