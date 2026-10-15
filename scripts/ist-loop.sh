#!/usr/bin/env bash
# ist-loop — rung 4: take the top todo intent from BACKLOG.md, run one
# Intent→Spec→Test cycle headless, open a PR, stop. One item per run.
#
# Run it from cron/launchd, a scheduled task, or by hand:  ./scripts/ist-loop.sh
# Guardrails (the agent's own must-nevers):
#   - never on main; never pushes to main; never merges
#   - one item at a time (WIP limit 1): exits if a BL item is already "running" or "pr"
#   - hard token/time budget via --max-turns and timeout
#   - hidden tests are never readable (mod + settings hook + this script never checks them out)
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

MAX_TURNS="${IST_MAX_TURNS:-60}"
TIMEOUT_SECS="${IST_TIMEOUT_SECS:-2700}"  # 45 minutes

# macOS has neither GNU timeout nor bash 4, and this runs from launchd there.
run_with_timeout() {
  local secs="$1"; shift
  if command -v timeout >/dev/null; then timeout "$secs" "$@"
  elif command -v gtimeout >/dev/null; then gtimeout "$secs" "$@"
  else perl -e 'alarm shift; exec @ARGV' "$secs" "$@"
  fi
}

if grep -Eq '^- \[(running|pr)\]' BACKLOG.md; then
  echo "ist-loop: an item is already running or awaiting PR review (WIP limit 1). Exiting."; exit 0
fi
ITEM=$(grep -E '^- \[todo\] BL-[0-9]+' BACKLOG.md | head -1 || true)
[ -z "$ITEM" ] && { echo "ist-loop: backlog empty."; exit 0; }
ID=$(echo "$ITEM" | grep -oE 'BL-[0-9]+' | head -1)
RISK=$(echo "$ITEM" | grep -oE '\((low|medium|high)\)' | tr -d '()')

git fetch -q origin main
BRANCH="ist/$(printf %s "$ID" | tr "[:upper:]" "[:lower:]")"
git switch -c "$BRANCH" origin/main 2>/dev/null || git switch "$BRANCH"
sed -i.bak "s/^- \[todo\] $ID /- [running] $ID /" BACKLOG.md && rm -f BACKLOG.md.bak
git add BACKLOG.md && git commit -qm "ist: start $ID"

echo "ist-loop: running /ist $ID ($RISK) on $BRANCH, max $MAX_TURNS turns"
set +e
run_with_timeout "$TIMEOUT_SECS" claude -p "/ist $ID" \
  --max-turns "$MAX_TURNS" \
  --permission-mode acceptEdits \
  --allowedTools "Read,Edit,Write,Grep,Glob,Bash(npm test*),Bash(node scripts/*),Bash(git add*),Bash(git commit*),Agent" \
  > ".ist/run-$ID.log" 2>&1
RC=$?
set -e

node scripts/ist-link-check.mjs . || { echo "ist-loop: links broken after run; leaving branch for a human."; sed -i.bak "s/^- \[running\] $ID /- [blocked: links broken] $ID /" BACKLOG.md; rm -f BACKLOG.md.bak; git add -A; git commit -qm "ist: $ID blocked"; git push -u origin "$BRANCH"; exit 1; }

sed -i.bak "s/^- \[running\] $ID /- [pr] $ID /" BACKLOG.md && rm -f BACKLOG.md.bak
git add -A && git commit -qm "ist: $ID ready for review" || true
git push -u origin "$BRANCH"
if command -v gh >/dev/null; then
  gh pr create --fill --base main --head "$BRANCH" --body-file ".ist/run-$ID.log" >/dev/null 2>&1 \
    && echo "ist-loop: PR opened for $ID" || echo "ist-loop: pushed $BRANCH; open the PR by hand."
fi
echo "ist-loop: done ($ID, rc=$RC). Human: review the spec diff, write/confirm hidden tests, merge when CI is green."
