# Implicit / hybrid witness

Chromium completing `response_type=id_token` and `response_type=code id_token`
against the emulator. That is the path msal-browser cannot take: the library
only emits authorization-code + PKCE.

```sh
npm install && npx playwright install chromium
npx playwright test
```

`global-setup.mjs` boots the emulator over TLS and registers a same-origin
redirect URI so the 302 lands where Playwright can read the fragment.

## What it witnesses

| claim | how |
|---|---|
| Implicit | account picker → redirect `#id_token=…` (not the query string); nonce echoed |
| Hybrid | account picker → redirect `#code=…&id_token=…`; the code exchanges at `/token` |
| Discovery | `response_types_supported` lists `code`, `id_token`, `code id_token` |
| OIDC rule | `response_mode=query` with an id_token is refused |
