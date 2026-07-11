# Samples

Runnable, copy-paste examples against the Entra Emulator. Start the emulator
first (`ORIGIN_MODE=compat ./entra-emulator` keeps everything on
`https://localhost:8443`), then follow a sample's README.

| Sample | SDK / language | Shows |
|---|---|---|
| [msal-node](msal-node/) | `@azure/msal-node` (Node.js) | Client credentials → call Graph |
| [msal-python](msal-python/) | `msal` (Python) | Client credentials → call Graph |
| [msal-go](msal-go/) | MSAL Go | Client credentials → call Graph (isolated module) |
| [externalized-authz](externalized-authz/) | Go | Validate emulator tokens + a tiny externalized-authorization (PDP) pattern |

Each MSAL sample defaults to the seeded dev constants and accepts `EMU_*` env
overrides. For the delegated (user sign-in) flow, mobile, and the embeddable Go
test library, see the
[quickstart](https://calvinchengx.github.io/entra-emulator/00-quickstart/). The
CI-tested end-to-end suites (which also cover MSAL Python's device-code flow and
a Flutter app) live under [`e2e/`](../e2e/).
