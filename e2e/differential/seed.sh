#!/usr/bin/env bash
# Seed the capture tenant to mirror the emulator's own seed directory.
#
# Why mirror it: differential capture compares an emulator response with a real
# Entra response for the SAME operation. If the two directories hold different
# shapes, every diff is dominated by content differences and the protocol
# differences — the only ones that matter — are buried. So the objects here are
# deliberate counterparts of internal/store/seed.go, not arbitrary test data.
#
# What CANNOT be mirrored: object ids. Entra assigns its own GUIDs, so the
# emulator's seeded ids have no counterpart. That is why this script writes
# .capture-identity.json — the emulator-id ↔ azure-id map every later diff must
# normalise through. Without it, every comparison drowns in GUID mismatch.
set -euo pipefail
cd "$(dirname "$0")"
. ./tenant-guard.sh

require_capture_tenant

DOMAIN="$EXPECTED_DOMAIN"
IDENTITY_FILE="./.capture-identity.json"

# Refuse to seed on top of an existing seed. Running twice would create a second
# set of apps with the same display names and leave the identity map pointing at
# whichever the query happened to return first.
if [ -s "$IDENTITY_FILE" ]; then
  echo "error: $IDENTITY_FILE already exists — run ./teardown.sh first" >&2
  exit 1
fi

echo "seeding ${PREFIX}* into $DOMAIN"

# ---- confidential app: counterpart of the seeded daemon -------------------
# Exposes BOTH an app role (app-only, -> the roles claim) and a delegated scope
# (-> the scp claim), because the emulator's daemon does and the two claims take
# different code paths on both sides.
SCOPE_ID=$(uuidgen | tr 'A-Z' 'a-z')
ROLE_ID=$(uuidgen | tr 'A-Z' 'a-z')

daemon_app=$(az ad app create --display-name "${PREFIX}-daemon" \
  --sign-in-audience AzureADMyOrg -o json)
DAEMON_APPID=$(echo "$daemon_app" | jq -r .appId)
DAEMON_OBJID=$(echo "$daemon_app" | jq -r .id)
echo "  app      ${PREFIX}-daemon  appId=$DAEMON_APPID"

# The App ID URI has to exist before scopes can be addressed as api://<id>/<name>.
az ad app update --id "$DAEMON_APPID" --identifier-uris "api://$DAEMON_APPID" >/dev/null
az rest --method PATCH --url "https://graph.microsoft.com/v1.0/applications/$DAEMON_OBJID" \
  --headers 'Content-Type=application/json' --body "$(jq -nc \
    --arg sid "$SCOPE_ID" --arg rid "$ROLE_ID" '{
    api: { oauth2PermissionScopes: [{
      id: $sid, value: "access_as_user", type: "User", isEnabled: true,
      adminConsentDisplayName: "Access as the signed-in user",
      adminConsentDescription: "Allows the app to act as the signed-in user.",
      userConsentDisplayName: "Access as you",
      userConsentDescription: "Allows the app to act as you."
    }]},
    appRoles: [{
      id: $rid, value: "Tasks.Read.All", isEnabled: true,
      allowedMemberTypes: ["Application"],
      displayName: "Read all tasks", description: "Read all tasks."
    }]
  }')" >/dev/null
echo "           + scope access_as_user, + app role Tasks.Read.All"

# A service principal is what actually receives role assignments and consent;
# an application alone is only a registration.
az ad sp create --id "$DAEMON_APPID" >/dev/null 2>&1 || true
DAEMON_SECRET=$(az ad app credential reset --id "$DAEMON_APPID" \
  --display-name "capture" --years 1 --query password -o tsv)
echo "           + client secret"

# ---- public app: counterpart of the seeded SPA ----------------------------
spa_app=$(az ad app create --display-name "${PREFIX}-spa" \
  --sign-in-audience AzureADMyOrg \
  --is-fallback-public-client true \
  --public-client-redirect-uris "http://localhost:3000/callback" -o json)
SPA_APPID=$(echo "$spa_app" | jq -r .appId)
SPA_OBJID=$(echo "$spa_app" | jq -r .id)
az ad sp create --id "$SPA_APPID" >/dev/null 2>&1 || true
# An `spa`-typed redirect URI is a distinct platform from a public-client one,
# and it is what gates token-endpoint CORS — the emulator gates on exactly this.
az rest --method PATCH --url "https://graph.microsoft.com/v1.0/applications/$SPA_OBJID" \
  --headers 'Content-Type=application/json' \
  --body '{"spa":{"redirectUris":["http://localhost:4400/"]}}' >/dev/null
echo "  app      ${PREFIX}-spa     appId=$SPA_APPID  (+ spa redirect URI)"

# ---- users ---------------------------------------------------------------
# Passwords are generated per run and never committed. They are written to the
# identity file, which .gitignore excludes — capture needs them for ROPC-style
# sign-ins, and a fixed password in a repo is a habit worth not starting.
make_user() { # $1 = short name -> prints "<objectId> <upn> <password>"
  local upn="${PREFIX}-$1@${DOMAIN}"
  local pw; pw="$(openssl rand -base64 18)Aa1!"
  local id
  id=$(az ad user create --display-name "${PREFIX} $1" \
        --user-principal-name "$upn" --password "$pw" \
        --force-change-password-next-sign-in false \
        --query id -o tsv)
  echo "$id $upn $pw"
}
read -r ALICE_ID ALICE_UPN ALICE_PW < <(make_user alice)
echo "  user     $ALICE_UPN"
read -r BOB_ID BOB_UPN BOB_PW < <(make_user bob)
echo "  user     $BOB_UPN"

# ---- group, with alice in it --------------------------------------------
GROUP_ID=$(az ad group create --display-name "${PREFIX}-engineering" \
  --mail-nickname "${PREFIX}engineering" --query id -o tsv)
az ad group member add --group "$GROUP_ID" --member-id "$ALICE_ID" >/dev/null
echo "  group    ${PREFIX}-engineering (alice is a member)"

# ---- the identity map ----------------------------------------------------
# Emulator ids are the constants in internal/store/seed.go. Pairing them here is
# what lets a diff normalise ids instead of reporting every one as a difference.
jq -n \
  --arg tenant "$(az rest --url 'https://graph.microsoft.com/v1.0/organization' \
                    --query 'value[0].id' -o tsv)" \
  --arg domain "$DOMAIN" \
  --arg captured "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg daemonApp "$DAEMON_APPID" --arg daemonObj "$DAEMON_OBJID" --arg daemonSecret "$DAEMON_SECRET" \
  --arg scopeId "$SCOPE_ID" --arg roleId "$ROLE_ID" \
  --arg spaApp "$SPA_APPID" --arg spaObj "$SPA_OBJID" \
  --arg aliceId "$ALICE_ID" --arg aliceUpn "$ALICE_UPN" --arg alicePw "$ALICE_PW" \
  --arg bobId "$BOB_ID" --arg bobUpn "$BOB_UPN" --arg bobPw "$BOB_PW" \
  --arg groupId "$GROUP_ID" \
  '{
     capturedAt: $captured, tenantId: $tenant, domain: $domain,
     note: "emulator id <-> azure id. Normalise through this before diffing.",
     map: {
       "00d88624-f0d7-46f6-a641-6232c2608928": { azure: $daemonApp, what: "daemon app (appId)" },
       "189c7070-78a3-4c13-aa18-20a2ca5755ca": { azure: $spaApp,    what: "spa app (appId)" },
       "df8ec5dd-1599-45ef-908b-4ae020cd1dbe": { azure: $aliceId,   what: "alice (objectId)" },
       "0d4ba1f9-cab1-4200-b516-d4cb8b340930": { azure: $bobId,     what: "bob (objectId)" },
       "54a9d08c-889d-489e-b534-336fe19dbfce": { azure: $groupId,   what: "engineering group" }
     },
     azure: {
       daemon: { appId: $daemonApp, objectId: $daemonObj, secret: $daemonSecret,
                 appIdUri: ("api://" + $daemonApp), scopeId: $scopeId, appRoleId: $roleId },
       spa:    { appId: $spaApp, objectId: $spaObj },
       alice:  { objectId: $aliceId, upn: $aliceUpn, password: $alicePw },
       bob:    { objectId: $bobId, upn: $bobUpn, password: $bobPw },
       group:  { objectId: $groupId }
     }
   }' > "$IDENTITY_FILE"
chmod 600 "$IDENTITY_FILE"

echo
echo "wrote $IDENTITY_FILE (secrets inside, gitignored, mode 600)"
echo "run ./teardown.sh to remove everything above"
