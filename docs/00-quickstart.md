# Quickstart: your first token in 5 minutes

Point a real MSAL client at the emulator and acquire a working token — no cloud
tenant, no app registration, no waiting. Every value below is a **seeded dev
constant**, so the snippets are copy-paste runnable.

By the end you'll have: the emulator running, a client-credentials token from
`curl` and from MSAL (Node / Python / Go / azidentity), and a Microsoft Graph call
authorized by that token.

## 1. Run the emulator

The simplest MSAL-friendly setup is **compat mode** (every surface on one
origin) with the default TLS on — so everything lives at
`https://localhost:8443`.

```sh
# from a clone:
go build ./cmd/entra-emulator
ORIGIN_MODE=compat ./entra-emulator

# …or with Docker (defaults to compat):
docker run -p 8443:8443 ghcr.io/calvinchengx/entra-emulator:latest
```

Prefer Homebrew, a pre-built binary (incl. Windows), or `go install`? See
[Installation](13-installation.md) for every method.

First run creates `./data/` with a SQLite store, a **persisted self-signed TLS
certificate** (stable fingerprint), a persisted RSA signing key (stable `kid`),
and the deterministic seed directory below.

:::note[Trust the cert]
MSAL rejects untrusted TLS. Either trust the emulator cert once —
`./entra-emulator trust` prints the platform command — or point each client at
the cert file, whose path `./entra-emulator cert-path` prints (default
`./data/tls/cert.pem`). The snippets below use the cert file so nothing touches
your system trust store.
:::

Sanity check:

```sh
curl --cacert ./data/tls/cert.pem \
  https://localhost:8443/11111111-1111-1111-1111-111111111111/v2.0/.well-known/openid-configuration
```

## 2. Your first token (one command)

The seeded **daemon** app is a confidential client. Ask for a Graph-audience
token with client credentials:

```sh
curl --cacert ./data/tls/cert.pem \
  https://localhost:8443/11111111-1111-1111-1111-111111111111/oauth2/v2.0/token \
  -d grant_type=client_credentials \
  -d client_id=cccccccc-0000-0000-0000-000000000002 \
  -d client_secret=daemon-app-secret \
  -d 'scope=https://graph.microsoft.com/.default'
```

You get a normal `access_token` (an RS256 JWT). Paste it into
[jwt.ms](https://jwt.ms) or decode the middle segment: `aud` is
`https://graph.microsoft.com`, `tid` is the seeded tenant, `appid` is the
daemon.

## 3. The same, from MSAL

Real MSAL SDKs work unchanged — you only override the **authority** (and, for
non-Microsoft hosts, mark it known and skip instance discovery).

:::caution[Two knobs every SDK needs]
1. **Authority** = `{origin}/{tenantId}` — here
   `https://localhost:8443/11111111-1111-1111-1111-111111111111`.
2. **Trust the host**: `knownAuthorities` (MSAL.js/Node),
   `instance_discovery=False` (MSAL Python), `WithInstanceDiscovery(false)`
   (MSAL Go), or a cloud-config override (azidentity) — otherwise the SDK tries
   to validate the authority against `login.microsoftonline.com`.
:::

### MSAL Node (`@azure/msal-node`)

```js
process.env.NODE_EXTRA_CA_CERTS = './data/tls/cert.pem'; // trust the emulator cert
import * as msal from '@azure/msal-node';

const cca = new msal.ConfidentialClientApplication({
  auth: {
    clientId: 'cccccccc-0000-0000-0000-000000000002',
    clientSecret: 'daemon-app-secret',
    authority: 'https://localhost:8443/11111111-1111-1111-1111-111111111111',
    knownAuthorities: ['localhost:8443'],
  },
});

const res = await cca.acquireTokenByClientCredential({
  scopes: ['https://graph.microsoft.com/.default'],
});
console.log(res.accessToken);
```

### MSAL Python (`msal`)

```python
import msal

app = msal.ConfidentialClientApplication(
    "cccccccc-0000-0000-0000-000000000002",       # client id
    client_credential="daemon-app-secret",
    authority="https://localhost:8443/11111111-1111-1111-1111-111111111111",
    instance_discovery=False,                     # don't probe the real AAD metadata
    verify="./data/tls/cert.pem",                 # trust the emulator cert
)

result = app.acquire_token_for_client(
    scopes=["https://graph.microsoft.com/.default"])
print(result["access_token"])   # or result["error_description"] on failure
```

### MSAL Go (`microsoft-authentication-library-for-go`)

```go
cred, _ := confidential.NewCredFromSecret("daemon-app-secret")
client, _ := confidential.New(
    "https://localhost:8443/11111111-1111-1111-1111-111111111111",
    "cccccccc-0000-0000-0000-000000000002", cred,
    confidential.WithInstanceDiscovery(false), // don't call the real AAD metadata endpoint
    // confidential.WithHTTPClient(certTrustingClient), // or trust the cert system-wide
)
res, _ := client.AcquireTokenByCredential(ctx,
    []string{"https://graph.microsoft.com/.default"})
fmt.Println(res.AccessToken)
```

### azidentity (`DefaultAzureCredential` family)

```go
cred, _ := azidentity.NewClientSecretCredential(
    "11111111-1111-1111-1111-111111111111",           // tenant
    "cccccccc-0000-0000-0000-000000000002",           // client id
    "daemon-app-secret",
    &azidentity.ClientSecretCredentialOptions{
        ClientOptions: azcore.ClientOptions{
            Cloud: cloud.Configuration{ActiveDirectoryAuthorityHost: "https://localhost:8443"},
        },
    })
tok, _ := cred.GetToken(ctx, policy.TokenRequestOptions{
    Scopes: []string{"https://graph.microsoft.com/.default"}})
```

## 4. Call Graph with the token

The emulator serves a minimal read-only Microsoft Graph. Use the token from any
step above:

```sh
TOKEN=... # the access_token from step 2 or 3
curl --cacert ./data/tls/cert.pem -H "Authorization: Bearer $TOKEN" \
  https://localhost:8443/graph/v1.0/users
```

You'll get the seeded users (Alice, Bob). See [Graph API](06-graph-api.md) for
the full surface (`/me`, `/me/memberOf`, `$select`/`$filter`, writes).

## 5. Go teams: zero external process

For Go integration tests, embed the emulator in-process — no ports, no
`docker`, no cleanup. This is [roadmap #1](10-roadmap.md):

```go
func TestSignIn(t *testing.T) {
    emu := emulator.StartT(t, emulator.WithTLS()) // in-process; auto-closed

    cred, _ := confidential.NewCredFromSecret(emulator.DaemonSecret)
    client, _ := confidential.New(emu.Authority(), emulator.DaemonClientID, cred,
        confidential.WithHTTPClient(emu.HTTPClient()), // trusts the instance cert
        confidential.WithInstanceDiscovery(false))

    res, _ := client.AcquireTokenByCredential(context.Background(),
        []string{"api://" + emulator.DaemonClientID + "/.default"})
    // assert on res.AccessToken …
}
```

`emu.Authority()`, `emu.HTTPClient()`, and the seeded IDs/secrets are all
exported, so tests need no hard-coded fixtures.

## Seeded identities

| Thing | Value |
|---|---|
| Tenant | `11111111-1111-1111-1111-111111111111` |
| SPA (public, PKCE) | `cccccccc-0000-0000-0000-000000000001`, redirect `https://localhost:3000` |
| Daemon (confidential) | `cccccccc-0000-0000-0000-000000000002`, secret `daemon-app-secret` |
| User: Alice | `alice@entraemulator.dev` / `Password1!` |
| User: Bob | `bob@entraemulator.dev` / `Password1!` |
| Group | `Engineering` (Alice + Bob) |

Full details, plus how to add your own, are in
[Data model & seed](03-data-model-and-seed.md).

## User sign-in (interactive)

To exercise a **user** flow (authorization code + PKCE, device code, ROPC,
passkeys), use the seeded SPA (`cccccccc-0000-0000-0000-000000000001`) as a
public client and sign in as Alice at the emulator's sign-in page. The exact
request/response shapes are in [OIDC endpoints](05-oidc-endpoints.md).

:::tip[Need a token with weird claims?]
Skip the flow entirely: the **token forge** mints any token you want — expired,
wrong-audience, custom scopes/roles — in one call. See the Admin API's
`POST /admin/api/tokens` in [Admin REST API](07-admin-api.md), or the **Token
forge** panel in the portal.
:::

### Mobile (Flutter)

There's no first-party MSAL package for Flutter, so mobile apps use a generic
AppAuth client. Point [`flutter_appauth`](https://pub.dev/packages/flutter_appauth)
at the emulator's endpoints — it's just OIDC authorization code + PKCE:

```dart
final result = await const FlutterAppAuth().authorizeAndExchangeCode(
  AuthorizationTokenRequest(
    'cccccccc-0000-0000-0000-000000000001',      // seeded SPA client id
    'com.example.app://auth',                     // your registered redirect
    serviceConfiguration: AuthorizationServiceConfiguration(
      authorizationEndpoint: '$authority/oauth2/v2.0/authorize',
      tokenEndpoint:         '$authority/oauth2/v2.0/token',
      endSessionEndpoint:    '$authority/oauth2/v2.0/logout',
    ),
    scopes: ['openid', 'profile', 'email', 'offline_access'],
  ),
);
```

:::note[Reaching the host from a device]
The **Android emulator** reaches your machine at `10.0.2.2`, not `localhost`;
the **iOS simulator** shares the host network, so `localhost` works. So
`authority` is `http://10.0.2.2:8443/{tenant}` on Android and
`https://localhost:8443/{tenant}` on iOS. A full working app (plus an automated
device-code integration test) lives in [`e2e/flutter/`](https://github.com/calvinchengx/entra-emulator/tree/main/e2e/flutter).
:::

## Troubleshooting

- **`invalid_authority` / instance-discovery errors** — set `knownAuthorities`
  (MSAL.js/Node), `instance_discovery=False` (MSAL Python), or
  `WithInstanceDiscovery(false)` (MSAL Go); the SDK is trying to reach
  `login.microsoftonline.com`.
- **TLS / self-signed errors** — trust the cert (`entra-emulator trust`), set
  `NODE_EXTRA_CA_CERTS` (Node), pass `verify="<cert>"` (MSAL Python), or use a
  cert-aware HTTP client (Go). MSAL Go **requires** https and won't accept an
  `http://` authority.
- **`AADSTS500011` (resource not found)** — client credentials needs exactly one
  `<resource>/.default` scope; check the resource matches a registered app or
  the Graph resource id.
- **Subdomain URLs won't resolve** — `ORIGIN_MODE=compat` keeps everything on
  `localhost`; otherwise run `entra-emulator hosts --apply`. See
  [TLS & origins](08-tls-and-origins.md).

## Next steps

- [Configuration](02-configuration.md) — origins, TLS, lifetimes, seeding.
- [Token service](04-token-service.md) — claims, signing, optional/group claims.
- [Testing](09-testing.md) & [E2E SDK matrix](11-e2e-sdk-matrix.md) — how the
  real-SDK suites are wired.
- [Roadmap](10-roadmap.md) — everything the emulator does and doesn't do.
