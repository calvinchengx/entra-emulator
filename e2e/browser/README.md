# msal-browser witness

A real browser running an **unmodified** [`@azure/msal-browser`](https://www.npmjs.com/package/@azure/msal-browser)
against the emulator, completing the authorization-code + PKCE redirect flow it
would use against cloud Entra. No emulator-specific shims.

```sh
npm install && npx playwright install chromium
npx playwright test
```

`global-setup.mjs` boots the emulator over TLS, finds the seeded public client,
and registers this app's origin as a redirect URI. `serve.mjs` serves the SPA
plus the msal-browser UMD bundle straight out of `node_modules`, so the browser
runs the real library with no bundler in between.

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
