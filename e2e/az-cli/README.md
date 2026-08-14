# Azure CLI witness

Microsoft's own `az` CLI completing `az cloud register` and
`az login --service-principal` against **this** entra checkout. MSAL-in-process
already covers client-credentials; this is the packaged CLI a developer runs,
verifying TLS like any real client.

```sh
python3 e2e/az-cli/run.py
```

The script builds the emulator, points `REQUESTS_CA_BUNDLE` at its cert, and
uses a private `AZURE_CONFIG_DIR` so it never touches your real `az` profile.
`AZURE_CORE_INSTANCE_DISCOVERY=false` is the switch the CLI documents for
private clouds. A one-route HTTPS stub (same localhost cert as the emulator) answers
`GET /subscriptions` with `{"value":[]}` so `az login` can finish without
arm-emulator; it is not a witness of ARM.

## What it witnesses

| claim | how |
|---|---|
| `client_credentials` | `az login --service-principal` with the seeded daemon app |
| TLS wildcard cert | the CLI verifies HTTPS; the harness does not pass `--insecure` |
| RS256 / v2.0 claim shape | `az account get-access-token` for Graph and ARM; JWT `alg`, `kid`, `tid`, `ver`, `azp` |
| Well-known ARM audience | ARM token minted with no arm-emulator running |

Needs `az` on `PATH` (GitHub-hosted `ubuntu-latest` ships it) and Go to build
the emulator.
