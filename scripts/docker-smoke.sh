#!/usr/bin/env bash
# Build the Docker image, boot it, and assert the emulator serves. Used by CI
# (docker-smoke job) and runnable locally: ./scripts/docker-smoke.sh
set -euo pipefail

IMAGE="entra-emulator:smoke"
NAME="entra-emulator-smoke"
PORT="${SMOKE_PORT:-8459}"
TENANT="6f89cf12-978b-4d23-ac18-9ef0c127cf87"

# The null device is not spelled the same everywhere. Under Git for Windows the
# SHELL understands /dev/null, but curl.exe is a native Windows binary that does
# not: `-o /dev/null` fails to open its output file and curl exits 23 AFTER
# already printing the status code. With `set -e` and a command substitution
# that aborted the whole script on the first check. NUL is the Windows spelling
# and creates no file.
NULDEV=/dev/null
case "$(uname -s 2>/dev/null || echo unknown)" in
  MINGW*|MSYS*|CYGWIN*) NULDEV=NUL ;;
esac

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
  # `|| true`: curl can exit non-zero having already printed a perfectly good
  # status code, and `set -e` would abort the run instead of reporting it.
  code=$(curl -s -o "$NULDEV" -w '%{http_code}' "$@" || true)
  if [ "$code" = "$want" ]; then echo "  ok  $name ($code)"; else echo "  FAIL $name: want $want got $code"; fail=1; fi
}

check "health" 200 "http://localhost:$PORT/health"
check "discovery" 200 "http://localhost:$PORT/$TENANT/v2.0/.well-known/openid-configuration"
check "jwks" 200 "http://localhost:$PORT/$TENANT/discovery/v2.0/keys"
check "client_credentials" 200 -X POST "http://localhost:$PORT/$TENANT/oauth2/v2.0/token" \
  -d "grant_type=client_credentials&client_id=00d88624-f0d7-46f6-a641-6232c2608928&client_secret=daemon-app-secret&scope=https://graph.microsoft.com/.default"
check "portal" 200 "http://localhost:$PORT/"

echo "==> in-container healthcheck subcommand"
if docker exec "$NAME" entra-emulator healthcheck; then echo "  ok  healthcheck exit 0"; else echo "  FAIL healthcheck nonzero"; fail=1; fi

if [ "$fail" -ne 0 ]; then echo "docker smoke test FAILED"; docker logs "$NAME" | tail -20; exit 1; fi
echo "docker smoke test passed (image $(docker images "$IMAGE" --format '{{.Size}}'))"
