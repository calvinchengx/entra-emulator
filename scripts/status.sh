#!/bin/sh
# One view of "is the emulator actually serving?" — which "the container is
# running" does not answer. It probes the surfaces every client depends on, in
# the order a client meets them: discovery, JWKS, then a real token mint.
#
# Works against a container (`make up`) or a native process (`make run`); it
# only talks HTTP, so it does not care which. Point it elsewhere with
# ENTRA_URL=… (e.g. a non-default port, or TLS disabled).
#
# Exit 0 = everything checked is good, 1 = at least one problem (usable in CI).
set -eu

# The null device is not spelled the same everywhere. Under Git for Windows the
# SHELL understands /dev/null, but curl.exe is a native Windows binary that does
# not: `-o /dev/null` fails to open its output file and curl exits 23 AFTER
# already printing the status code, which corrupts any `curl … || fallback`.
# NUL is the Windows spelling and creates no file.
NULDEV=/dev/null
case "$(uname -s 2>/dev/null || echo unknown)" in
  MINGW*|MSYS*|CYGWIN*) NULDEV=NUL ;;
esac

ENTRA="${ENTRA_URL:-https://localhost:8443}"
TENANT="${TENANT_ID:-6f89cf12-978b-4d23-ac18-9ef0c127cf87}"
# ENTRA_NAME, not NAME: a bare `NAME` is a common thing to have exported in a
# shell, and inheriting it would send this looking for the wrong container.
ENTRA_NAME="${ENTRA_NAME:-entra-emulator}"
CLIENT_ID="${CLIENT_ID:-00d88624-f0d7-46f6-a641-6232c2608928}"
CLIENT_SECRET="${CLIENT_SECRET:-daemon-app-secret}"
RC=0

say() { printf '%s\n' "$*"; }
bad() { RC=1; }

# HTTP probe: prints the status code, or "---" when unreachable. curl's exit
# status is deliberately not chained with `||` — it prints the code on stdout
# and can still exit non-zero for unrelated reasons (see NULDEV above), and
# inside `$(...)` a fallback would be APPENDED to the code, not replace it.
code() {
  c=$(curl -sk -o "$NULDEV" -w '%{http_code}' --max-time 5 "$@" 2>/dev/null)
  case "$c" in
    ''|000|*[!0-9]*) printf '%s' "---" ;;
    *)               printf '%s' "$c" ;;
  esac
}

check_http() { # label expected curl-args...
  label="$1"; want="$2"; shift 2
  c=$(code "$@")
  if [ "$c" = "$want" ]; then
    printf '  ok    %-24s %s\n' "$label" "HTTP $c"
  else
    printf '  FAIL  %-24s %s (want %s)\n' "$label" "HTTP $c" "$want"; bad
  fi
}

# The container is optional: `make run` serves natively with no container at
# all, so its absence is reported as information, never as a failure.
say 'container (optional — "make run" serves natively with none)'
# Anchored: docker's `name` filter is a SUBSTRING (really a regex) match, not an
# equality test. Unanchored, `entra-emulator` also matches
# `fabric-emulator-entra-emulator-1` — the entra container belonging to the
# fabric stack — so this reported a sibling project's container as its own and
# said "ok" while nothing of this repo's was running.
line=$(docker ps -a --filter "name=^${ENTRA_NAME}$" --format '{{.Names}}	{{.State}}	{{.Status}}' 2>/dev/null || printf '')
if [ -z "$line" ]; then
  say "  none  no container named '$ENTRA_NAME' (fine if running natively)"
else
  st=$(printf '%s' "$line" | cut -f2)
  detail=$(printf '%s' "$line" | cut -f3)
  case "$st" in
    running) printf '  ok    %-24s %s\n' "$ENTRA_NAME" "$detail" ;;
    *)       printf '  warn  %-24s %s\n' "$ENTRA_NAME" "$detail" ;;
  esac
fi

say ""
say "endpoints"
check_http "health" 200 "$ENTRA/health"
check_http "openid-configuration" 200 "$ENTRA/$TENANT/v2.0/.well-known/openid-configuration"
check_http "jwks" 200 "$ENTRA/$TENANT/discovery/v2.0/keys"
check_http "portal" 200 "$ENTRA/"

# Serving the metadata is not the same as being able to ISSUE. This is the
# check that matters to any client: a real client-credentials grant against the
# seeded daemon app, which exercises the signing key and the token pipeline.
say ""
say "token issuance (the seeded daemon app, client credentials)"
body=$(curl -sk --max-time 5 "$ENTRA/$TENANT/oauth2/v2.0/token" \
  -d grant_type=client_credentials \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" \
  -d 'scope=https://graph.microsoft.com/.default' 2>/dev/null || printf '')
case "$body" in
  *access_token*) printf '  ok    %-24s minted a Graph-audience token\n' "client_credentials" ;;
  '')             printf '  FAIL  %-24s no response\n' "client_credentials"; bad ;;
  *)              printf '  FAIL  %-24s no access_token in response\n' "client_credentials"; bad ;;
esac

say ""
if [ "$RC" = "0" ]; then say "emulator OK"; else say "emulator has problems (see FAIL above)"; fi
exit "$RC"
