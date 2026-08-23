#!/usr/bin/env bash
# Decide whether this event changed anything a code job could test.
#
# Emits `code=true|false` on $GITHUB_OUTPUT and explains itself in the job
# summary. Callers gate their jobs with:
#
#     needs: changes
#     if: needs.changes.outputs.code == 'true'
#
# WHY A JOB-LEVEL `if:` AND NOT `paths-ignore:` ON THE WORKFLOW.
# A workflow that never triggers leaves its check permanently "Expected —
# waiting for status", so under branch protection the pull request can never
# merge. A job skipped by an `if:` condition reports as successful to branch
# protection. This repository has no protection today, which is exactly what
# makes paths-ignore the dangerous choice: it is a landmine armed later, by a
# settings change nobody would connect to CI.
#
# THIS FAILS OPEN, ALWAYS. `github.event.before` is all zeros on a first push
# and unreliable after a force-push; both file endpoints cap a page at 300; a
# network blip is a network blip. Every one of those emits code=true and runs
# the full suite. A gate that failed closed would turn "I could not tell" into
# a green CI, which is the one outcome worth engineering against.
#
# Needs GH_TOKEN in the environment. No checkout: the change set comes from the
# API, which is why the job costs a couple of seconds.
set -euo pipefail

# Paths that cannot change how the code behaves. Anything NOT listed here is
# treated as code. That direction is deliberate: a new docs folder nobody adds
# here makes CI run when it need not, never skip when it must not.
DOC_PATHS=(
  'docs/'
  'site/'
  'website/'
  '.github/ISSUE_TEMPLATE/'
  'README.md'
  'SECURITY.md'
  'NOTICE'
  'LICENSE'
)

# Both endpoints cap one page at 300 files. gh --paginate follows the Link
# header, but a truncated list read as complete is the one way this gate could
# wrongly skip, so a change set at or past the cap is not trusted to be whole.
PAGE_CAP=300

emit() {
  echo "code=$1" >> "${GITHUB_OUTPUT:-/dev/stdout}"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n' "$2" >> "$GITHUB_STEP_SUMMARY"
  fi
  printf '%s\n' "$2"
}

run_everything() {
  emit true "**Running every job.** $1"
  exit 0
}

count_lines() {
  printf '%s\n' "$1" | sed '/^[[:space:]]*$/d' | wc -l | tr -d '[:space:]'
}

repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is unset}"
files=""

# A tag is a release. make-targets.yml is called by release.yml as its gate, so
# nothing here may ever thin out what a release runs -- and a tag push happens
# to arrive with a zero before-sha, which would fail open by luck rather than
# by decision. This says it on purpose.
case "${GITHUB_REF:-}" in
  refs/tags/*) run_everything "This is a tag (${GITHUB_REF}); a release runs everything." ;;
esac

case "${GITHUB_EVENT_NAME:-}" in
  pull_request | pull_request_target)
    num=$(jq -r '.pull_request.number' "$GITHUB_EVENT_PATH")
    if ! files=$(gh api --paginate "repos/$repo/pulls/$num/files" --jq '.[].filename'); then
      run_everything "The pull request's file list could not be read."
    fi
    ;;
  push)
    before=$(jq -r '.before' "$GITHUB_EVENT_PATH")
    case "$before" in
      0000000000000000000000000000000000000000 | null | "")
        run_everything "First push or force-push: there is no previous commit to compare against."
        ;;
    esac
    if ! files=$(gh api --paginate "repos/$repo/compare/$before...${GITHUB_SHA:?}" --jq '.files[].filename'); then
      run_everything "The comparison $before...$GITHUB_SHA could not be read."
    fi
    ;;
  *)
    run_everything "Event ${GITHUB_EVENT_NAME:-unknown} carries no change set, so nothing can be ruled out."
    ;;
esac

# An empty list from a call that succeeded means the API listed no files. That
# is not evidence of a docs-only change; it is evidence of nothing.
if [ -z "${files//[[:space:]]/}" ]; then
  run_everything "The change set came back empty, which proves nothing about what changed."
fi

total=$(count_lines "$files")
if [ "$total" -ge "$PAGE_CAP" ]; then
  run_everything "This change touches $total files, at or past the $PAGE_CAP-file page cap, so the list may be truncated."
fi

code_files=""
while IFS= read -r f; do
  [ -z "$f" ] && continue
  inert=false
  for p in "${DOC_PATHS[@]}"; do
    case "$p" in
      */)
        case "$f" in "$p"*) inert=true; break ;; esac
        ;;
      *)
        if [ "$f" = "$p" ]; then inert=true; break; fi
        ;;
    esac
  done
  if [ "$inert" = false ]; then
    code_files="$code_files$f"$'\n'
  fi
done <<< "$files"

if [ -n "${code_files//[[:space:]]/}" ]; then
  n=$(count_lines "$code_files")
  emit true "$(printf '**Running every job.** %s of %s changed file(s) are outside the docs set:\n\n```\n%s\n```' \
    "$n" "$total" "$(printf '%s' "$code_files" | sed '/^$/d' | head -20)")"
else
  emit false "$(printf '**Docs-only change, so the code jobs are skipped.** All %s changed file(s) are inert:\n\n```\n%s\n```' \
    "$total" "$(printf '%s\n' "$files" | sed '/^$/d' | head -20)")"
fi
