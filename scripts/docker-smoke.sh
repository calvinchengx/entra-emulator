#!/usr/bin/env bash
# Build the Docker image, boot it, and assert the emulator serves. Used by CI
# (docker-smoke job) and runnable locally: ./scripts/docker-smoke.sh
set -euo pipefail

IMAGE="entra-emulator:smoke"
NAME="entra-emulator-smoke"
PORT="${SMOKE_PORT:-8459}"
TENANT="11111111-1111-1111-1111-111111111111"

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "==> building image"
docker build -q -t "$IMAGE" --build-arg VERSION=smoke . >/dev/null

echo "==> running container"
cleanup
docker run -d --name "$NAME" -p "$PORT:8443" -e TLS_ENABLED=false "$IMAGE" >/dev/null

echo "==> waiting for /health"
for _ in $(seq 1 50); do
  if curl -sf "http://localhost:$PORT/health" >/dev/null 2>&1; then break; fi
  sleep 0.3
done

fail=0
check() { # name  expected-code  curl-args...
  local name="$1" want="$2"; shift 2
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' "$@")
  if [ "$code" = "$want" ]; then echo "  ok  $name ($code)"; else echo "  FAIL $name: want $want got $code"; fail=1; fi
}

check "health" 200 "http://localhost:$PORT/health"
check "discovery" 200 "http://localhost:$PORT/$TENANT/v2.0/.well-known/openid-configuration"
check "jwks" 200 "http://localhost:$PORT/$TENANT/discovery/v2.0/keys"
check "client_credentials" 200 -X POST "http://localhost:$PORT/$TENANT/oauth2/v2.0/token" \
  -d "grant_type=client_credentials&client_id=cccccccc-0000-0000-0000-000000000002&client_secret=daemon-app-secret&scope=https://graph.microsoft.com/.default"
check "portal" 200 "http://localhost:$PORT/"

echo "==> in-container healthcheck subcommand"
if docker exec "$NAME" entra-emulator healthcheck; then echo "  ok  healthcheck exit 0"; else echo "  FAIL healthcheck nonzero"; fail=1; fi

if [ "$fail" -ne 0 ]; then echo "docker smoke test FAILED"; docker logs "$NAME" | tail -20; exit 1; fi
echo "docker smoke test passed (image $(docker images "$IMAGE" --format '{{.Size}}'))"
