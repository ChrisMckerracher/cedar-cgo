#!/usr/bin/env bash
# Require a complete successful main CI run for the exact release commit.
set -euo pipefail
repository=${1:?repository is required}
commit=${2:?source commit is required}
record=$(gh api --method GET "repos/$repository/actions/workflows/ci.yml/runs" \
 -f event=push -f branch=main -f head_sha="$commit" -f per_page=1 \
 --jq '.workflow_runs[0] | [.id, .head_sha, .head_branch, .event, .status, .conclusion] | @tsv')
read -r run_id source branch event status conclusion <<< "$record"
test "$source" = "$commit"
test "$branch" = main
test "$event" = push
test "$status" = completed
test "$conclusion" = success
jobs=$(mktemp)
trap 'rm -f "$jobs"' EXIT
gh api --paginate "repos/$repository/actions/runs/$run_id/jobs?filter=latest&per_page=100" \
 --jq '.jobs[] | [.name,.status,.conclusion] | @tsv' > "$jobs"
python3 "$PWD/scripts/release/verify-jobs.py" "$jobs"
printf '%s\n' "$run_id"
