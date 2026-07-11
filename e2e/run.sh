#!/usr/bin/env bash
# E2E runner: boots the emulator with an ephemeral store, then runs the
# per-language SDK suites (docs/11-e2e-sdk-matrix.md).
# Usage: ./e2e/run.sh [ts|go|python|dotnet|java ...]   (default: ts go python)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${E2E_PORT:-9743}"
TENANT="11111111-1111-1111-1111-111111111111"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/entra-e2e.XXXXXX")"
trap 'kill "$EMU_PID" 2>/dev/null || true; rm -rf "$WORK"' EXIT

echo "==> building emulator"
(cd "$ROOT" && go build -o "$WORK/entra-emulator" ./cmd/entra-emulator)

echo "==> starting emulator on :$PORT"
# exec so $! is the emulator itself (not a subshell) and the trap can kill it.
(cd "$WORK" && exec env PORT="$PORT" ORIGIN_MODE=compat DB_PATH="$WORK/e2e.db" \
  TLS_CERT_DIR="$WORK/tls" "$WORK/entra-emulator" >"$WORK/server.log" 2>&1) &
EMU_PID=$!

for _ in $(seq 1 50); do
  curl -sk "https://localhost:$PORT/health" >/dev/null 2>&1 && break
  sleep 0.2
done
curl -sk "https://localhost:$PORT/health" >/dev/null || {
  echo "emulator failed to start"; cat "$WORK/server.log"; exit 1; }

export EMU_ORIGIN="https://localhost:$PORT"
export EMU_TENANT="$TENANT"
export EMU_CERT="$WORK/tls/cert.pem"

suites=("$@")
[ ${#suites[@]} -eq 0 ] && suites=(ts go python)
fail=0

for s in "${suites[@]}"; do
  echo
  echo "=== e2e: $s ==="
  case "$s" in
    ts)
      (cd "$ROOT/e2e/ts" && [ -d node_modules ] || (cd "$ROOT/e2e/ts" && npm install --silent)
       cd "$ROOT/e2e/ts" && NODE_EXTRA_CA_CERTS="$EMU_CERT" node suite.mjs) || fail=1 ;;
    go)
      (cd "$ROOT/e2e/go" && go mod download 2>/dev/null; cd "$ROOT/e2e/go" && go test ./... -count=1) || fail=1 ;;
    python)
      (cd "$ROOT/e2e/python" && [ -d .venv ] || python3 -m venv .venv
       cd "$ROOT/e2e/python" && ./.venv/bin/pip install -q msal && ./.venv/bin/python suite.py) || fail=1 ;;
    dotnet)
      (cd "$ROOT/e2e/dotnet" && dotnet run -c Release) || fail=1 ;;
    java)
      (cd "$ROOT/e2e/java" && mvn -q -B compile exec:java) || fail=1 ;;
    *) echo "unknown suite: $s"; fail=1 ;;
  esac
done

exit $fail
