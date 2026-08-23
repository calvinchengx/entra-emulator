#!/usr/bin/env bash
# Self-test for changed-files.sh, run in CI beside it.
#
# A gate that decides what NOT to check is the one script whose silent failure
# looks exactly like a speedup: a filter that stops matching skips every job
# and reports a fast green build. So each case below is a way this has gone
# wrong somewhere, and the fail-open cases matter more than the happy path.
#
# `gh` and the event payload are stubbed; nothing here touches the network.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNDER_TEST="$HERE/changed-files.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
pass=0; fail=0

# A `gh` stub on PATH, whose output (and exit status) each case controls.
mkdir -p "$TMP/bin"
cat > "$TMP/bin/gh" <<'STUB'
#!/usr/bin/env bash
[ -n "${STUB_GH_FAIL:-}" ] && exit 1
cat "$STUB_GH_FILES"
STUB
chmod +x "$TMP/bin/gh"
export PATH="$TMP/bin:$PATH"

# want=true|false  name  event  files(newline-separated)  [extra env assignments]
check() {
  local want="$1" name="$2" event="$3" filelist="$4"; shift 4
  printf '%s' "$filelist" > "$TMP/files"
  : > "$TMP/out"
  local before="1111111111111111111111111111111111111111"
  local num=7
  local ref="refs/heads/main"
  for kv in "$@"; do
    case "$kv" in
      before=*) before="${kv#before=}" ;;
      num=*) num="${kv#num=}" ;;
      ref=*) ref="${kv#ref=}" ;;
    esac
  done
  printf '{"before":"%s","pull_request":{"number":%s}}' "$before" "$num" > "$TMP/event.json"

  local ghfail=""
  for kv in "$@"; do [ "$kv" = "ghfail=1" ] && ghfail=1; done

  local got
  got=$(
    STUB_GH_FILES="$TMP/files" STUB_GH_FAIL="$ghfail" \
    GITHUB_REPOSITORY="calvinchengx/entra-emulator" \
    GITHUB_EVENT_NAME="$event" GITHUB_EVENT_PATH="$TMP/event.json" \
    GITHUB_SHA="2222222222222222222222222222222222222222" GITHUB_REF="$ref" \
    GITHUB_OUTPUT="$TMP/out" GITHUB_STEP_SUMMARY="" \
    bash "$UNDER_TEST" >/dev/null 2>&1
    grep -o 'code=[a-z]*' "$TMP/out" | tail -1
  )
  if [ "$got" = "code=$want" ]; then
    pass=$((pass+1)); printf '  ok    %-52s %s\n' "$name" "$got"
  else
    fail=$((fail+1)); printf '  FAIL  %-52s got %s, wanted code=%s\n' "$name" "${got:-<nothing>}" "$want"
  fi
}

echo "changed-files self-test"

# --- the case the gate exists for ---
check false "docs-only pull request" pull_request \
  'docs/01-quickstart.md
docs/parity.md
README.md
'
check false "the landing page and the docs site" pull_request \
  'site/index.html
website/astro.config.mjs
website/scripts/sync-docs.mjs
'

# --- one code file among many docs must run everything ---
check true "one Go file hidden among docs" pull_request \
  'docs/01-quickstart.md
README.md
internal/identity/token.go
docs/parity.md
'
check true "a workflow change is not a docs change" pull_request \
  'README.md
.github/workflows/ci.yml
'
check true "a script the docs gate runs is code" pull_request \
  'docs/parity.md
scripts/check_witnesses.py
'
check true "the Makefile is code" push 'README.md
Makefile
'

# --- prefix matching must not be a substring match ---
check true "a path merely starting with a doc name" pull_request \
  'docsy/thing.go
'
check true "README-alike is not README.md" pull_request \
  'README.md.go
'
check true "a file named like a doc dir, at another depth" pull_request \
  'internal/docs/loader.go
'

# --- every way of not knowing must run everything ---
check true "first push or force-push (zero before-sha)" push 'docs/x.md
' before=0000000000000000000000000000000000000000
check true "before-sha is null" push 'docs/x.md
' before=null
check true "the API call failed" pull_request 'docs/x.md
' ghfail=1
check true "the API returned nothing" pull_request ''
check true "the API returned only whitespace" pull_request '

'
check true "an event with no change set (schedule)" schedule 'docs/x.md
'
check true "an event with no change set (dispatch)" workflow_dispatch 'docs/x.md
'

# --- a release must never be thinned out ---
check true "a tag push runs everything" push 'docs/x.md
' ref=refs/tags/v1.2.3 before=1111111111111111111111111111111111111111

# --- a list that may be truncated is not trusted ---
big=$(for i in $(seq 1 300); do echo "docs/page-$i.md"; done)
check true "300 docs files, at the page cap" pull_request "$big
"
almost=$(for i in $(seq 1 299); do echo "docs/page-$i.md"; done)
check false "299 docs files, under the cap" pull_request "$almost
"

echo
if [ "$fail" -ne 0 ]; then
  echo "changed-files self-test: $pass passed, $fail FAILED"
  exit 1
fi
echo "changed-files self-test: $pass passed"
