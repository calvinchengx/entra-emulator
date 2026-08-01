#!/bin/sh
# Is this machine able to build and run the emulator at all?
#
# Separate from status.sh on purpose: status.sh answers "is it serving?" and
# assumes the toolchain works. This answers the question that comes before it,
# because on Windows those failures are silent and misattributed. Three of them
# cost real time:
#
#   * `python3` resolves to the Microsoft Store alias stub. It is on PATH, so
#     every `command -v python3` check passes, and it exits 49 when run.
#   * GNU Make falls back to cmd.exe when sh.exe is not on PATH, and every
#     recipe here is POSIX shell.
#   * The `docker` CLI can be one vendor's while the ACTIVE CONTEXT points at
#     another vendor's daemon that is not running (Docker Desktop's CLI first
#     on PATH, Rancher Desktop actually serving). The error is a raw named-pipe
#     failure that names neither.
#
# Docker is OPTIONAL here, unlike in the sibling repos: `make run` builds and
# serves natively with no container involved. Only `make up` and `make smoke`
# need a daemon, so a missing one is a warning, not a blocker.
#
# Exit 0 = ready, 1 = at least one blocker.
set -eu

RC=0
ok()   { printf '  ok    %-22s %s\n' "$1" "$2"; }
warn() { printf '  warn  %-22s %s\n' "$1" "$2"; }
bad()  { printf '  FAIL  %-22s %s\n' "$1" "$2"; RC=1; }

printf 'shell tools\n'
printf '  (recipes and scripts/*.sh are POSIX shell; on Windows these come from Git for Windows)\n'
# bash as well as sh: scripts/docker-smoke.sh (behind `make smoke`) declares
# bash and uses `set -o pipefail`, which dash does not implement.
for t in sh bash grep awk cut curl; do
  p=$(command -v "$t" 2>/dev/null || true)
  if [ -n "$p" ]; then ok "$t" "$p"; else bad "$t" "not on PATH"; fi
done

printf '\ngo (make build, run, test)\n'
if command -v go >/dev/null 2>&1; then
  ok "go" "$(go version 2>/dev/null)"
else
  bad "go" "not on PATH; needed for make build/run/test (>= 1.25)"
fi

printf '\npython (only needed by `make e2e`)\n'
PY="${PY:-}"
if [ -z "$PY" ]; then
  for c in python3 python py; do
    if "$c" -c '' >/dev/null 2>&1; then PY="$c"; break; fi
  done
fi
if [ -n "$PY" ]; then
  ok "$PY" "$("$PY" -c 'import sys; print(sys.version.split()[0], "at", sys.executable)')"
  # Name the trap explicitly when it is present but shadowing a working python.
  if [ "$PY" != "python3" ] && command -v python3 >/dev/null 2>&1; then
    warn "python3" "on PATH but not runnable (Microsoft Store alias stub); using $PY"
  fi
else
  warn "python" 'none of python3/python/py runs; only "make e2e" needs it'
fi

printf '\ndocker (optional — only make up / make smoke need it)\n'
if ! command -v docker >/dev/null 2>&1; then
  warn "docker" 'no docker CLI; "make run" still works natively'
else
  # Take one line and reject anything that is not a bare context name. A broken
  # `docker` on PATH is a real case — inside WSL without Docker Desktop's
  # integration, the shim prints a multi-line "could not be found in this WSL 2
  # distro" advert on STDOUT, not stderr, so redirecting stderr does not stop it
  # from being captured and pasted into the middle of our own message.
  ctx=$(docker context show 2>/dev/null | head -n 1 | tr -d '\r')
  case "$ctx" in
    ''|*[!A-Za-z0-9_.-]*) ctx=unknown ;;
  esac
  if docker info >/dev/null 2>&1; then
    ok "context" "$ctx"
    ok "daemon" "$(docker info --format '{{.ServerVersion}} ({{.OSType}}/{{.Architecture}}), {{.NCPU}} cpu' 2>/dev/null)"
  else
    warn "daemon" "context '$ctx' is not reachable"
    printf '        contexts available:\n'
    docker context ls --format '          {{.Name}}  {{.DockerEndpoint}}' 2>/dev/null \
      | grep -E '^ +[A-Za-z0-9_.-]+ ' || printf '          (none — the docker CLI itself is not working)\n'
    printf '        if another runtime (Rancher Desktop, Colima, podman) is serving, select it:\n'
    printf '          docker context use <name>\n'
  fi
fi

# Port 8443 in use is worth knowing but is not a blocker: it is very often
# another member of this family (the keyvault or fabric compose file publishes
# entra on the same port), which means the thing you want may already be up.
printf '\nhost port\n'
if [ -n "$PY" ]; then
  # `|| true` because of `set -eu` above: this section is advisory, and a python
  # that dies here must not abort the report before its verdict line.
  "$PY" - <<'EOF' || true
import os, socket
port = int(os.environ.get("ENTRA_PORT", "8443"))
s = socket.socket()
s.settimeout(0.4)
taken = s.connect_ex(("127.0.0.1", port)) == 0
s.close()
if taken:
    print("  warn  %-22s port %d already answering — often this family's" % ("entra-emulator", port))
    print("        keyvault or fabric compose stack already publishing entra there.")
else:
    print("  ok    %-22s port %d free" % ("entra-emulator", port))
EOF
else
  warn "port" "skipped (needs python)"
fi

printf '\n'
if [ "$RC" = "0" ]; then
  printf 'ready — run: make run   (native)   or   make up   (container)\n'
else
  printf 'not ready (see FAIL above)\n'
fi
exit "$RC"
