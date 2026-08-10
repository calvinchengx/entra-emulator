#!/usr/bin/env bash
# Refuse to touch any tenant but the capture tenant.
#
# This is the most important file here. Everything else creates or deletes
# directory objects, and the failure that actually matters is doing that in the
# WRONG directory — a production tenant looks identical to `az` once you are
# signed into it. So no script runs a single mutation before this passes.
#
# Sourced, not executed. Callers do: . "$(dirname "$0")/tenant-guard.sh"
set -euo pipefail

# The capture tenant, by verified domain. A domain is used rather than a tenant
# GUID because it is human-checkable: a wrong GUID looks like any other GUID.
EXPECTED_DOMAIN="${EMU_DIFF_DOMAIN:-entraemulatordiff.onmicrosoft.com}"

require_capture_tenant() {
  local actual
  if ! actual=$(az rest --url 'https://graph.microsoft.com/v1.0/organization' \
      --query 'value[0].verifiedDomains[0].name' -o tsv 2>/dev/null); then
    echo "error: no usable az session. Run:" >&2
    echo "  az login --allow-no-subscriptions --tenant $EXPECTED_DOMAIN" >&2
    exit 1
  fi
  if [ "$actual" != "$EXPECTED_DOMAIN" ]; then
    echo "REFUSING TO RUN." >&2
    echo "  expected tenant: $EXPECTED_DOMAIN" >&2
    echo "  signed in to   : $actual" >&2
    echo "This script creates and deletes directory objects. Switch tenants:" >&2
    echo "  az login --allow-no-subscriptions --tenant $EXPECTED_DOMAIN" >&2
    exit 1
  fi
  echo "tenant guard ok: $actual"
}

# Everything the seed creates carries this prefix, and teardown only ever
# removes objects that carry it. A teardown that deleted "all users" would work
# on a fresh tenant and be catastrophic on any other — the prefix is what makes
# the blast radius a property of the code rather than of who ran it.
PREFIX="emudiff"
