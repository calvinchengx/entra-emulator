# 11 — E2E testing with real Entra SDKs

The e2e suites prove that **unmodified Microsoft client libraries** complete real flows
against the emulator. Reference: `entra-docs/docs/identity-platform/`
(`msal-client-application-configuration.md`, `msal-authentication-flows.md`).

## Shared harness contract

Every language suite follows the same lifecycle, driven by `e2e/run.py`:

1. Build the emulator; start it on a fixed port with an ephemeral `DB_PATH`,
   `ORIGIN_MODE=compat` (CI has no hosts entries), and TLS enabled.
2. Poll `/health` until ready; export `EMU_ORIGIN`, `EMU_TENANT`, `EMU_CERT` (path to
   `cert.pem`) to the suite.
3. Run the suite against the **seeded** apps/users (fixed GUIDs, docs/03).
4. Tear down; non-zero exit fails the run.

Two knobs make custom authorities work in every Microsoft SDK:

| Concern | Setting |
|---|---|
| Instance discovery | Must be **disabled** (the emulator is not in Microsoft's cloud metadata): msal-js `knownAuthorities`; MSAL Go `WithInstanceDiscovery(false)`; MSAL Python `instance_discovery=False`; MSAL.NET `.WithInstanceDiscovery(false)`; MSAL4J `.instanceDiscovery(false)`; azure-identity `DisableInstanceDiscovery` |
| TLS trust | Node `NODE_EXTRA_CA_CERTS`; Go custom `http.Client` with the cert in `RootCAs`; Python `verify=<cert>` (msal) / `connection_verify` (azure-identity); .NET cert-trusting `HttpClient` via `WithHttpClientFactory`; Java: load the cert into a trust store and set the default `SSLContext`; browsers via Playwright `ignoreHTTPSErrors` |

## Language matrix

| Language | SDK(s) | Flows covered | Interaction driver |
|---|---|---|---|
| TypeScript | `@azure/msal-node` | client credentials, auth code + PKCE, refresh, device code | cookie-jar HTTPS sequence against the sign-in/approval pages |
| TypeScript (Graph) | `@microsoft/microsoft-graph-client` + `@azure/msal-node` | stateful directory: user create/patch, role assignment, consent grants, auth methods, soft-delete → recycle bin → restore → purge (docs/19) | Graph SDK request pipeline against `/graph` |
| TypeScript (browser) | `@azure/msal-browser` | auth code + PKCE, silent renewal, logout | Playwright headless Chromium (opt-in, heavier) |
| Go | `microsoft-authentication-library-for-go` + `azidentity` | client credentials (both layers), device code | HTTP approval sequence |
| Python | `msal` (+ optional `azure-identity`) | client credentials, device code | HTTP approval sequence in a thread |
| C# / .NET | `Microsoft.Identity.Client` (MSAL.NET) | client credentials (+ token-cache hit) | — (no interactive flow) |
| Java | `com.microsoft.azure:msal4j` (MSAL4J) | client credentials | — (no interactive flow) |
| Flutter/Dart | Dart `http` (automated) + `flutter_appauth` (manual screen) | device code end-to-end on-device; auth code + PKCE manually | `integration_test` on Android emulator / iOS simulator — **nightly, not PR gate** |

Notes per language:

- **TypeScript** is the reference suite. The
  msal-node auth-code test uses `getAuthCodeUrl` → drive the account picker over HTTPS
  with a cookie jar → `acquireTokenByCode`, then asserts `client_info`-derived account
  identity and JWKS verification.
- **Go** tests two layers deliberately: raw MSAL Go (what the emulator's protocol
  surface promises) and `azidentity` (what real Go services use —
  `ClientSecretCredential` with `Cloud.ActiveDirectoryAuthorityHost` pointed at the
  emulator). The roadmap's embeddable library will wrap this harness for downstream
  consumers.
- **Python**: `ConfidentialClientApplication(..., instance_discovery=False,
  verify=EMU_CERT)`; device flow via `initiate_device_flow` +
  `acquire_token_by_device_flow` with the approval driven concurrently. The suite
  provisions its own venv.
- **.NET** (`e2e/dotnet/`): `ConfidentialClientApplicationBuilder` with
  `.WithAuthority(authority, validateAuthority: false).WithInstanceDiscovery(false)`
  and a cert-trusting `HttpClient` supplied via `WithHttpClientFactory`. Asserts the
  app-only claim shape (`aud`, `roles`, no `scp`/`oid`) and that a second call is served
  from MSAL's token cache. Built and run with `dotnet run`.
- **Java** (`e2e/java/`): `ConfidentialClientApplication.builder(...)
  .authority(authority).validateAuthority(false).instanceDiscovery(false)`; the suite
  loads `EMU_CERT` into a fresh trust store and sets it as the default `SSLContext` so
  msal4j's HTTP client accepts the TLS connection. Built and run with Maven
  (`mvn compile exec:java`).
- **Flutter** (`e2e/flutter/`, run by `.github/workflows/flutter-e2e.yml`): no
  official MSAL exists for Dart. The **automated** on-device test drives the
  device-code flow end-to-end with Dart `http` (device authorization → pending poll →
  approval pages → tokens → Graph `/me`) — device code needs no browser, so it is
  fully automatable. The `flutter_appauth` Authorization Code + PKCE flow opens an
  *external system browser* that `integration_test` cannot drive; it ships as a
  manual screen in the same app. Device-emulator specifics: the authority is the
  address the device sees (`10.0.2.2` from the Android emulator, `localhost` from the
  iOS simulator — pass `--dart-define=EMU_ORIGIN=...`), the CI emulator runs
  `TLS_ENABLED=false` (Android manifest allows cleartext; iOS has the
  local-networking ATS exception). **CI runners:** Android emulator on
  `ubuntu-latest` (KVM) — modern macOS runners are arm64 without nested
  virtualization and cannot boot it; iOS simulator on `macos-latest`. Nightly +
  manual dispatch, not a PR gate.

## Assertions common to every suite

- Access/ID tokens verify against the live JWKS; `iss` equals the discovery issuer.
- Claim shapes per docs/04 (`tid`, `oid`, `scp`/`roles`, pairwise `sub`, `ver: "2.0"`).
- `client_info` present on delegated responses; absent on client credentials.
- Negative paths: wrong secret → `invalid_client`; replayed code / reused refresh
  token → `invalid_grant`; device poll before approval → `authorization_pending`.
