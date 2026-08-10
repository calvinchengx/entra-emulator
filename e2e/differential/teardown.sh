#!/usr/bin/env bash
# Remove everything seed.sh creates, and leave a tenant that can be deleted.
#
# Written and RUN BEFORE seed.sh, deliberately. A teardown script that has never
# executed is a belief about reversibility, not a capability — the same defect
# as a URL asserted to look right and never fetched. Running it against an empty
# tenant proves it is at least well-formed and idempotent.
#
# Soft-delete is not enough: Entra keeps deleted users, groups and apps in a
# recycle bin, and leftover soft-deleted applications are one of the documented
# blockers on deleting a tenant. So every object is purged from deletedItems too.
set -euo pipefail
cd "$(dirname "$0")"
. ./tenant-guard.sh

require_capture_tenant
echo "tearing down objects prefixed '${PREFIX}'"

removed=0

purge() { # permanently remove a soft-deleted directory object
  az rest --method DELETE \
    --url "https://graph.microsoft.com/v1.0/directory/deletedItems/$1" >/dev/null 2>&1 || true
}

# --- applications (also removes their service principals) ---
while read -r id name; do
  [ -z "$id" ] && continue
  echo "  app      $name"
  az ad app delete --id "$id" 2>/dev/null || true
  purge "$id"
  removed=$((removed + 1))
done < <(az ad app list --filter "startswith(displayName,'${PREFIX}')" \
           --query '[].[id,displayName]' -o tsv 2>/dev/null || true)

# --- groups ---
while read -r id name; do
  [ -z "$id" ] && continue
  echo "  group    $name"
  az ad group delete --group "$id" 2>/dev/null || true
  purge "$id"
  removed=$((removed + 1))
done < <(az ad group list --filter "startswith(displayName,'${PREFIX}')" \
           --query '[].[id,displayName]' -o tsv 2>/dev/null || true)

# --- users ---
# Matched on userPrincipalName, not displayName: the UPN is what the seed
# controls exactly, and it is what a stray match would otherwise hinge on.
while read -r id upn; do
  [ -z "$id" ] && continue
  echo "  user     $upn"
  az ad user delete --id "$id" 2>/dev/null || true
  purge "$id"
  removed=$((removed + 1))
done < <(az ad user list --filter "startswith(userPrincipalName,'${PREFIX}')" \
           --query '[].[id,userPrincipalName]' -o tsv 2>/dev/null || true)

rm -f ./.capture-identity.json

if [ "$removed" -eq 0 ]; then
  echo "nothing to remove — tenant is already clean"
else
  echo "removed $removed object(s), purged from the recycle bin"
fi

# Report anything left that would block deleting the tenant, rather than
# claiming success on the basis of our own objects being gone.
echo
echo "remaining in tenant (must be near-empty before the tenant can be deleted):"
printf '  users : %s\n' "$(az ad user list --query 'length(@)' -o tsv 2>/dev/null || echo '?')"
printf '  groups: %s\n' "$(az ad group list --query 'length(@)' -o tsv 2>/dev/null || echo '?')"
printf '  apps  : %s\n' "$(az ad app list --query 'length(@)' -o tsv 2>/dev/null || echo '?')"
