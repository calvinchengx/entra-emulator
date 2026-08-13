#!/usr/bin/env bash
# Capture real Entra responses as normalised fixtures.
#
# This is the step the rest of this directory existed to enable: seed.sh makes
# the capture tenant match the emulator's seed, and this records what Azure
# actually answers so the emulator's answer can be diffed against it.
#
# WHY NORMALISATION HAPPENS HERE AND NOT AT DIFF TIME
# The emulator-id <-> azure-id map lives in .capture-identity.json, which is
# gitignored because it also holds a client secret and two passwords. CI never
# has it. So a fixture must arrive already normalised — an id left raw here can
# never be reconciled later, and a fixture is only useful if a machine with no
# access to the capture tenant can check it.
#
# WHAT IS DELIBERATELY NOT RECORDED
# Access tokens. A captured JWT is a live credential for the capture tenant
# until it expires, and committing one starts a habit that eventually commits a
# production one. The envelope records that `access_token` was present and its
# shape; the token's decoded header and claim NAMES are recorded because that is
# the diffable part, while the signature and volatile values are not.
set -euo pipefail
cd "$(dirname "$0")"
. ./tenant-guard.sh

IDENTITY_FILE="./.capture-identity.json"
FIXTURES="./testdata/fixtures"
MANIFEST="./testdata/fixture-manifest.json"

if [ ! -s "$IDENTITY_FILE" ]; then
  echo "error: $IDENTITY_FILE missing — run ./seed.sh first" >&2
  exit 1
fi

require_capture_tenant

AUTHORITY="https://login.microsoftonline.com"
TENANT_ID=$(jq -r .tenantId "$IDENTITY_FILE")
DAEMON_APPID=$(jq -r .azure.daemon.appId "$IDENTITY_FILE")
DAEMON_SECRET=$(jq -r .azure.daemon.secret "$IDENTITY_FILE")
TOKEN_URL="$AUTHORITY/$TENANT_ID/oauth2/v2.0/token"

mkdir -p "$FIXTURES"
# A recapture replaces the previous token fixtures rather than mixing dates
# (a leftover 401 "happy path" from a raced secret must not survive).
rm -f "$FIXTURES"/token-*.json

# normalise: fold every volatile or tenant-identifying value into a stable
# placeholder. The list here MUST stay in step with `normalizations` in the
# manifest — the diff harness reads that array to decide what it may ignore, and
# a value normalised here but absent there is a difference nobody will ever see.
#
# Ordering matters: the tenant GUID is substituted before the generic GUID rule,
# or it would be flattened into {guid} and stop being recognisable.
normalise() {
  jq --arg tenant "$TENANT_ID" --arg app "$DAEMON_APPID" '
    walk(
      if type == "string" then
          gsub($tenant; "{tenant-id}")
        | gsub($app; "{daemon-app-id}")
        # request-scoped identifiers: different on every call, never a difference
        | gsub("(?<a>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"; "{guid}")
        | gsub("(?<t>\\d{4}-\\d{2}-\\d{2}[ T]\\d{2}:\\d{2}:\\d{2}Z?)"; "{timestamp}")
      else . end
    )
    # Absolute lifetimes are a property of the tenant policy, not the protocol.
    | if has("expires_in") then .expires_in = "{seconds}" else . end
    | if has("ext_expires_in") then .ext_expires_in = "{seconds}" else . end
    # A real bearer token must never land in the repo. Record presence, not value.
    | if has("access_token") then .access_token = "{redacted-jwt}" else . end
  '
}

# record <scenario-id> <http-status> <body-json>
record() {
  local id="$1" status="$2" body="$3"
  jq -n --arg id "$id" --arg status "$status" \
        --arg capturedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --argjson body "$(printf '%s' "$body" | normalise)" \
    '{scenario: $id, capturedAt: $capturedAt, response: {status: ($status|tonumber), body: $body}}' \
    > "$FIXTURES/$id.json"
  echo "  captured $id (HTTP $status)"
}

# post_token <form-args...> -> sets HTTP_STATUS and HTTP_BODY
post_token() {
  local out
  out=$(curl -s -w '\n%{http_code}' -X POST "$TOKEN_URL" \
        -H 'Content-Type: application/x-www-form-urlencoded' "$@")
  HTTP_STATUS="${out##*$'\n'}"
  HTTP_BODY="${out%$'\n'*}"
}

echo "capturing from $EXPECTED_DOMAIN"

# ---- the happy path ------------------------------------------------------
# Records the envelope's field set. The claim comparison is a separate scenario
# because it needs the token decoded, and the token itself is never stored.
#
# A newly-reset client secret is not immediately valid: Entra answers
# AADSTS7000215 for a few seconds after `az ad app credential reset`. Poll
# until the happy path is actually happy, otherwise this scenario records the
# same envelope as token-error-invalid-client and the claims fixture is never
# written — which is what the first capture run did.
# Graph's .default, requested at the v2 endpoint, still mints a *v1* token
# (`ver: "1.0"`, `iss: https://sts.windows.net/{tid}/`, a pile of `xms_*`
# claims). This emulator is a v2.0 STS, so the happy-path resource is the
# daemon's own API — the envelope field set is the same, and the claims
# fixture is something the emulator actually claims to implement.
happy_scope="api://${DAEMON_APPID}/.default"
HTTP_STATUS=""
HTTP_BODY=""
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  post_token \
    --data-urlencode "grant_type=client_credentials" \
    --data-urlencode "client_id=$DAEMON_APPID" \
    --data-urlencode "client_secret=$DAEMON_SECRET" \
    --data-urlencode "scope=$happy_scope"
  if [ "$HTTP_STATUS" = "200" ]; then
    echo "  secret replicated on attempt $attempt"
    break
  fi
  echo "  happy path HTTP $HTTP_STATUS (attempt $attempt) — waiting for secret replication"
  sleep 3
done
if [ "$HTTP_STATUS" != "200" ]; then
  echo "error: client_credentials against $happy_scope never returned 200 (last HTTP $HTTP_STATUS)" >&2
  echo "$HTTP_BODY" >&2
  echo "refusing to record a 401 as the happy-path fixture; error scenarios still follow" >&2
  HAPPY_FAILED=1
else
  record "token-client-credentials" "$HTTP_STATUS" "$HTTP_BODY"
fi

# The access token's header and claim NAMES, which is what an emulator has to
# get right and what our own tests cannot tell us we got wrong. Values are
# dropped except the few that are structural (ver, token typ/alg).
if [ "$HTTP_STATUS" = "200" ]; then
  jwt=$(printf '%s' "$HTTP_BODY" | jq -r .access_token)
  # base64url -> base64, re-padded. Written as an `if` rather than
  # `[ cond ] && assignment`: that idiom returns non-zero when the condition is
  # false, which is harmless here only because another command follows it. Were
  # it ever the last line of the function, the function would return 1 on the
  # no-padding input and `set -e` would abort the capture — a failure that
  # appears for some tokens and not others. The `if` cannot acquire that
  # property by a later edit.
  b64() {
    local s="$1" pad
    pad=$(( ${#s} % 4 ))
    if [ "$pad" -ne 0 ]; then
      s="${s}$(printf '=%.0s' $(seq $((4 - pad))))"
    fi
    printf '%s' "$s" | tr '_-' '/+' | base64 -d 2>/dev/null
  }
  hdr=$(b64 "$(cut -d. -f1 <<<"$jwt")")
  pay=$(b64 "$(cut -d. -f2 <<<"$jwt")")
  jq -n --arg capturedAt "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --argjson header "$(printf '%s' "$hdr" | jq '{alg, typ, kid: (if .kid then "{kid}" else null end), x5t: (if .x5t then "{x5t}" else null end)}')" \
        --argjson claimNames "$(printf '%s' "$pay" | jq -c '[keys[]] | sort')" \
        --argjson structural "$(printf '%s' "$pay" | jq --arg t "$TENANT_ID" --arg a "$DAEMON_APPID" \
            '{ver,
              iss: (.iss | gsub($t; "{tenant-id}") | gsub($a; "{daemon-app-id}")),
              aud: (.aud | tostring | gsub($t; "{tenant-id}") | gsub($a; "{daemon-app-id}")),
              tid: (if .tid == $t then "{tenant-id}" else .tid end),
              appid: (if .appid == $a then "{daemon-app-id}" else .appid end),
              idtyp}')" \
    '{scenario: "token-claims-client-credentials", capturedAt: $capturedAt,
      note: "Claim NAMES and structural values only. The token itself is never stored.",
      header: $header, claimNames: $claimNames, structural: $structural}' \
    > "$FIXTURES/token-claims-client-credentials.json"
  echo "  captured token-claims-client-credentials (claim names + structural)"
fi

# ---- the error envelopes -------------------------------------------------
# The richest differential surface, and the safest: no secret is returned, and
# error shape is exactly where an emulator drifts without any local test
# noticing. Entra's envelope carries error_codes/trace_id/correlation_id that a
# naive implementation omits entirely.
post_token \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "client_id=$DAEMON_APPID" \
  --data-urlencode "client_secret=deliberately-wrong" \
  --data-urlencode "scope=https://graph.microsoft.com/.default"
record "token-error-invalid-client" "$HTTP_STATUS" "$HTTP_BODY"

post_token \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "client_id=$DAEMON_APPID" \
  --data-urlencode "client_secret=$DAEMON_SECRET" \
  --data-urlencode "scope=api://not-a-registered-resource/.default"
record "token-error-invalid-scope" "$HTTP_STATUS" "$HTTP_BODY"

post_token \
  --data-urlencode "grant_type=no_such_grant" \
  --data-urlencode "client_id=$DAEMON_APPID" \
  --data-urlencode "client_secret=$DAEMON_SECRET" \
  --data-urlencode "scope=https://graph.microsoft.com/.default"
record "token-error-unsupported-grant-type" "$HTTP_STATUS" "$HTTP_BODY"

post_token \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "client_id=00000000-0000-0000-0000-000000000000" \
  --data-urlencode "client_secret=$DAEMON_SECRET" \
  --data-urlencode "scope=https://graph.microsoft.com/.default"
record "token-error-unknown-client" "$HTTP_STATUS" "$HTTP_BODY"

# ---- stamp the manifest --------------------------------------------------
# capturedAt drives the staleness rule: the harness reports STALE rather than
# passing once a fixture ages out, so an old recording cannot silently certify
# behaviour that has since drifted.
#
# Only mark a scenario captured when its fixture file exists. The first run
# stamped token-claims-client-credentials captured after a 401 happy path
# skipped the claims write, and the harness then failed "claimed fixture
# which does not exist".
ids_json=$(find "$FIXTURES" -name '*.json' -type f -exec basename {} .json \; \
  | jq -R . | jq -s .)
tmp=$(mktemp)
jq --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson ids "$ids_json" '
  .capturedAt = $at
  | .scenarios = (.scenarios | map(
      .id as $sid |
      if ($ids | index($sid)) != null
        then .status = "captured" | .fixture = ($sid + ".json")
        elif ($sid | startswith("token-"))
        then .status = "planned" | del(.fixture)
        else . end))
' "$MANIFEST" > "$tmp" && mv "$tmp" "$MANIFEST"

echo
echo "wrote $(find "$FIXTURES" -name '*.json' -type f | wc -l | tr -d ' ') fixture(s) to $FIXTURES"
echo "these are normalised and safe to commit; .capture-identity.json is not"
if [ "${HAPPY_FAILED:-0}" = "1" ]; then
  exit 1
fi
