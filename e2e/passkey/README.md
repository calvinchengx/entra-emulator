# Passkey / WebAuthn witness

Chromium completing the emulator's WebAuthn ceremonies on the **emulator's own
origin**, using CDP `WebAuthn.addVirtualAuthenticator` and
`navigator.credentials`. That is the path the msal-browser harness cannot take:
WebAuthn pins the relying party to the page origin, and the SPA lives elsewhere.

```sh
npm install && npx playwright install chromium
npx playwright test
```

`global-setup.mjs` boots the emulator over TLS on `localhost` (default port
18444) so the browser origin and the emulator's Host-derived RP ID both resolve
to `localhost`.

## What it witnesses

| claim | how |
|---|---|
| Passkey / WebAuthn sign-in | `register/begin` → `navigator.credentials.create` → `register/finish` → `assert/begin` → `navigator.credentials.get` → `assert/finish` |
| `amr: ["fido"]` | the `ee_session` cookie from assert drives SSO `/authorize`; the ID token carries the passkey method |

The password half of `amr` (`["pwd"]`) is witnessed by `e2e/browser` after the
account-picker click, not here.
