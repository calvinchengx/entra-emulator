# MSAL Go sample

App-only (client-credentials) token acquisition with
[MSAL Go](https://github.com/AzureAD/microsoft-authentication-library-for-go),
then a call to the emulated Microsoft Graph.

```sh
# 1. Start the emulator (compat mode keeps everything on https://localhost:8443)
ORIGIN_MODE=compat ./entra-emulator          # from the repo root

# 2. Run the sample
cd samples/msal-go
go run .
```

Expected output:

```
✓ token acquired — aud=https://graph.microsoft.com appid=cccccccc-… exp=…
✓ GET /graph/v1.0/users → 200, 2 users:
    - Alice Example <alice@entraemulator.dev>
    - Bob Example <bob@entraemulator.dev>
```

This is a **separate Go module** so the MSAL dependency never reaches the
emulator binary. MSAL Go requires HTTPS, so the sample builds an `http.Client`
that trusts the emulator's self-signed cert (`EMU_CERT`, default
`../../data/tls/cert.pem`) and passes it via `confidential.WithHTTPClient`.

> For Go **integration tests**, prefer the embeddable library
> (`emulator.StartT`) — it runs the emulator in-process with no ports or certs
> to manage. See the
> [quickstart](https://calvinchengx.github.io/entra-emulator/00-quickstart/#go-teams-zero-external-process).

Override any default with an env var: `EMU_ORIGIN`, `EMU_TENANT`,
`EMU_CLIENT_ID`, `EMU_CLIENT_SECRET`, `EMU_CERT`.
