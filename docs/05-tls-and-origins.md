# 08 — TLS, origins & host routing

## Certificate

Auto-generated, persisted self-signed **wildcard leaf** (no local CA):

- RSA-2048; CN = `entra.localhost` (the base domain), OU = `Entra Emulator`.
- SANs: apex + `*.<baseDomain>` + `localhost` + `127.0.0.1` + `::1`, plus every
  `LOCAL_DOMAINS` apex + its wildcard.
- Persisted at `TLS_CERT_DIR` (`data/tls/cert.pem`, `key.pem` chmod 600); loaded on later
  boots → **stable fingerprint**.
- **Regenerated when SAN drift is detected** (persisted cert doesn't cover the configured
  domain set); unchanged config never regenerates.
- `TLS_CERT`/`TLS_KEY` override the pair entirely (both or neither).
- `TLS_ENABLED=false` → plain HTTP on loopback.

Exposed for trust workflows via `/admin/api/certificate` (+ `/pem`), and the
`entra-emulator cert-path | show-cert | trust | hosts` CLI subcommands (print-by-default,
`--apply` to execute; `hosts` writes an idempotent `# entra-emulator BEGIN/END` block
mapping each subdomain to 127.0.0.1).

## Trusted local HTTPS with `step`

By default the emulator trusts nothing for you — the browser (portal) and any client
see a self-signed cert. Two ways to get warning-free HTTPS:

- **Built-in (zero tools):** `entra-emulator trust --apply` installs the emulator's own
  **leaf** into the OS/browser trust stores. Simplest, but the trusted item is a specific
  leaf — a regenerated cert (SAN drift) must be re-trusted.
- **Local CA via [`step`](https://github.com/smallstep/cli)** (`smallstep/cli`): trust a
  CA **once**, then re-issue leaves freely without re-trusting — closer to real PKI. Feed
  the leaf through the `TLS_CERT`/`TLS_KEY` override:

```sh
brew install step   # or from smallstep/cli releases

# Create a local dev CA once, and trust the ROOT (not the leaf):
step certificate create "Entra Emulator Dev CA" ca.crt ca.key \
  --profile root-ca --no-password --insecure
step certificate install ca.crt          # OS + browser trust stores (sudo/admin)

# Issue a leaf covering every name/IP the emulator serves:
step certificate create entra.localhost entra.crt entra.key \
  --profile leaf --ca ca.crt --ca-key ca.key \
  --san 'entra.localhost' --san '*.entra.localhost' \
  --san localhost --san 127.0.0.1 --san ::1 \
  --not-after 8760h --no-password --insecure

TLS_CERT=./entra.crt TLS_KEY=./entra.key entra-emulator
```

- The trusted anchor is the **CA**, so re-issuing the leaf (new SANs, later expiry) needs
  **no** re-trust — just restart with the new pair.
- Match the SANs to the host-routing set (apex + `*.<baseDomain>` wildcard + loopback, plus
  any `LOCAL_DOMAINS`) or you trade cert warnings for SNI mismatches.
- The pair is loaded **once at startup** (no hot-reload), so restart after re-issuing.

## Origins & host routing

One TLS listener; the `Host` header selects the surface:

| Host | Role | Serves |
|---|---|---|
| `login.<baseDomain>` | login | discovery, JWKS, authorize, token, devicecode(+page), logout |
| `graph.<baseDomain>` | graph | `/v1.0/*`, `/oidc/userinfo` |
| `portal.<baseDomain>` | portal | portal SPA, `/admin/api/*`, `/health` |
| anything else (incl. `localhost`, `127.0.0.1`) | **compat** | ALL routes (graph/userinfo under the `/graph` prefix) |

- A request for a path outside its host's slice → JSON 404 (compat is unrestricted).
- `login`/`graph` root path returns a small JSON descriptor; portal/compat root serves
  the SPA.
- Reserved API prefixes (`/{tenant}/...` allowlisted, `/graph/...`, `/admin/...`,
  `/health`) are never shadowed by the SPA fallback; unmatched paths under them return
  JSON 404, never HTML.
- Discovery/JWKS/token URLs derive from the **login** origin; `userinfo_endpoint` and
  Graph `@odata.*` from the **graph** origin; MSAL snippets from login+graph.
- `ORIGIN_MODE=compat` (Docker default) collapses all advertised origins to
  `https://localhost:<port>`; `PUBLIC_ORIGIN` collapses to an arbitrary origin;
  per-surface `*_ORIGIN` overrides win over both. Bind (`HOST:PORT`) is independent of
  advertisement.

## Boot logging

On listen, log the three advertised origins, the issuer, and — when the subdomains are
in play — a hint to run `entra-emulator hosts --apply` if the names don't resolve.
