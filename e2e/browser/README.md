# msal-browser witness

A real browser running an **unmodified** [`@azure/msal-browser`](https://www.npmjs.com/package/@azure/msal-browser)
against the emulator, completing the authorization-code + PKCE redirect flow and
the RP-initiated logout it would use against cloud Entra. No emulator-specific
shims.

```sh
npm install && npx playwright install chromium
npx playwright test
```

`global-setup.mjs` boots the emulator over TLS, finds the seeded public client,
registers this app's origin and its post-logout page as redirect URIs, and makes
the app a front-channel logout relying party. `serve.mjs` serves the SPA plus the
msal-browser UMD bundle straight out of `node_modules`, so the browser runs the
real library with no bundler in between; it also plays the RP, recording the
front-channel logout callbacks the browser makes.

## What it witnesses

| claim | how |
|---|---|
| Auth code + PKCE | `loginRedirect` → the emulator's account picker → `handleRedirectPromise` |
| CORS on the OIDC surface | implicit in every request MSAL.js makes cross-origin |
| RP-initiated logout | `logoutRedirect` with `id_token_hint`, landing on a **registered** post-logout URI |
| Front-channel logout | the emulator's hidden iframe is actually fetched, carrying `iss` and `sid` |

The front-channel row is the one only a browser can reach. Server-side a test can
assert the logout page *contains* an iframe; it cannot assert anything ever
fetched it. Here the RP endpoint is a real server that records its hits.

## Why it exists

The other SDK suites (msal-node, MSAL Go, .NET, Java, Python) all run
**server-side**, so none of them is subject to the browser's same-origin policy.
Building this witness immediately found a defect they could never catch: the
emulator sent **no CORS headers**, so MSAL.js could not fetch discovery, the
JWKS or the token endpoint, and *no browser SPA could authenticate at all*.

## Two constraints worth knowing

- **MSAL.js refuses a plain-http authority** (`authority_uri_insecure`), even on
  `localhost` — so the emulator must serve TLS here. Its self-signed cert is
  accepted via `ignoreHTTPSErrors`, the same trust step a developer makes.
- The SPA is served over `http://localhost`, which browsers treat as a **secure
  context**, so `crypto.subtle` (and therefore PKCE) works without TLS on the
  app itself.

## What this harness cannot witness

- **Implicit / hybrid flow.** msal-browser is authorization-code + PKCE only;
  it never emits `response_type=id_token` or `code id_token`. The browser path
  is [`e2e/implicit`](../implicit): Chromium follows those authorize redirects
  itself.
- **Passkey / WebAuthn.** WebAuthn pins the ceremony to the origin of the page
  that calls `navigator.credentials`, and the emulator sets `RPOrigins` to its
  own origin (`internal/identity/webauthn.go`). This SPA therefore cannot
  complete a ceremony against it. The browser path is
  [`e2e/passkey`](../passkey): Chromium on the emulator origin, with a CDP
  virtual authenticator. This harness still witnesses the password half of
  `amr` (`["pwd"]`) after the account-picker click.
