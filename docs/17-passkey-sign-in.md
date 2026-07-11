# How-to: test a passkey (FIDO2/WebAuthn) sign-in

Passkeys (FIDO2/WebAuthn) are a phishing-resistant sign-in method: the user
proves possession of a private key held by an authenticator instead of typing a
password. The emulator implements both WebAuthn ceremonies — **registration**
(enroll a passkey) and **assertion** (sign in with one) — so you can build and
test passkey flows entirely locally, with **no cloud tenant and no hardware
security key** ([roadmap #11](10-roadmap.md)).

A passkey sign-in yields an ID token whose `amr` claim is `["fido"]` (versus
`["pwd"]` for password sign-in), so your app — or a resource API — can tell *how*
the user authenticated and require the stronger method.

## The ceremonies

Four endpoints on the **login** surface, per tenant:

| Endpoint | Does |
|---|---|
| `POST /{tenant}/webauthn/register/begin` | `{ "upn": "…" }` → `PublicKeyCredentialCreationOptions` |
| `POST /{tenant}/webauthn/register/finish` | the authenticator's attestation → stores the credential |
| `POST /{tenant}/webauthn/assert/begin` | `{ "upn": "…" }` → `PublicKeyCredentialRequestOptions` (`400` if the user has no passkey) |
| `POST /{tenant}/webauthn/assert/finish` | the authenticator's assertion → `{ "amr": "fido", "userId": "…" }`, and sets an `ee_session` cookie tagged `fido` |

The **relying party is built per request from the `Host` header** (RP ID = host
without port, origin = `scheme://host`), so passkeys work on whichever origin you
reach the emulator on — no static RP configuration. Ceremony state is held
server-side, keyed by a short-lived `ee_webauthn` cookie, so drive each ceremony
with a **cookie jar**.

## Headless: register + assert with a virtual authenticator

You need neither a browser nor a hardware key. A virtual authenticator
([`github.com/descope/virtualwebauthn`](https://github.com/descope/virtualwebauthn))
does the crypto, so the whole flow runs in a Go program or test:

```go
import vwa "github.com/descope/virtualwebauthn"

origin := "https://localhost:8443" // compat mode
tenant := "11111111-1111-1111-1111-111111111111"
base := origin + "/" + tenant + "/webauthn"

jar, _ := cookiejar.New(nil) // carries the ee_webauthn ceremony cookie
client := &http.Client{Jar: jar}

// RP ID is the host without the port: "localhost" in compat mode, or
// "login.entra.localhost" on the subdomain surface.
rp := vwa.RelyingParty{Name: "Entra Emulator", ID: "localhost", Origin: origin}
authr := vwa.NewAuthenticator()
cred := vwa.NewCredential(vwa.KeyTypeEC2)

// 1. Register a passkey for Alice.
opts := postJSON(client, base+"/register/begin", map[string]string{"upn": "alice@entraemulator.dev"})
att, _ := vwa.ParseAttestationOptions(opts)
postJSON(client, base+"/register/finish", vwa.CreateAttestationResponse(rp, authr, cred, *att))
authr.AddCredential(cred)

// 2. Sign in with it.
opts = postJSON(client, base+"/assert/begin", map[string]string{"upn": "alice@entraemulator.dev"})
asr, _ := vwa.ParseAssertionOptions(opts)
out := postJSON(client, base+"/assert/finish", vwa.CreateAssertionResponse(rp, authr, cred, *asr))
// out → {"amr":"fido","userId":"aaaaaaaa-0000-0000-0000-000000000001"}
// client's jar now holds an ee_session cookie tagged fido.
```

(`postJSON` is any helper that POSTs a JSON body and returns the response body.)
The emulator's own suite drives exactly this flow — see
[`internal/server/webauthn_test.go`](https://github.com/calvinchengx/entra-emulator/blob/main/internal/server/webauthn_test.go).

## From a passkey session to a token with `amr:["fido"]`

The `ee_session` cookie the assertion set is a normal SSO session. Reusing the
same cookie jar, a standard authorization-code + PKCE `/authorize` request skips
the account picker (SSO) and issues a code whose ID token carries the passkey
`amr`:

```go
authorize := origin + "/" + tenant + "/oauth2/v2.0/authorize?" + url.Values{
    "client_id":             {"cccccccc-0000-0000-0000-000000000001"}, // seeded SPA
    "response_type":         {"code"},
    "redirect_uri":          {"https://localhost:3000"},
    "scope":                 {"openid profile"},
    "code_challenge":        {pkceS256(verifier)}, // public client → PKCE
    "code_challenge_method": {"S256"},
}.Encode()
// GET authorize (same jar) → 302 redirect_uri?code=…
// exchange the code at /oauth2/v2.0/token → id_token with "amr": ["fido"]
```

Password or account-picker sign-in yields `amr: ["pwd"]` instead — so you can
test both branches of a rule that requires passkey (`fido`) authentication.

## Manage a user's passkeys

```sh
# list (never returns key material)
curl -k https://localhost:8443/admin/api/users/<user-id>/passkeys

# revoke one
curl -k -X DELETE https://localhost:8443/admin/api/users/<user-id>/passkeys/<credential-id>
```

Once a user's last passkey is removed, `assert/begin` returns `400` — there is no
passkey to sign in with.

## In a real browser

The same endpoints back a browser ceremony: call `register/begin` /
`assert/begin`, hand the returned options to `navigator.credentials.create()` /
`.get()`, and POST the result to `…/finish`. Because the RP ID follows the `Host`
header, this works on any origin the emulator serves — a
[trusted certificate](08-tls-and-origins.md) is the prerequisite, since
`navigator.credentials` requires a secure context on non-`localhost` origins.

---

Reference: [Passkey / WebAuthn ceremonies](05-oidc-endpoints.md) · implemented as
[roadmap #11](10-roadmap.md).
