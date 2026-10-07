#!/usr/bin/env bash
# Prints live GitHub data for every tool in catalog.toml: stars, last push,
# whether it is archived, and its status here. Optionally filtered by status
# or category, for example: plan/tools/refresh.sh to-study
set -euo pipefail

dir="$(cd "$(dirname "$0")" && pwd)"
gh=~/.local/bin/gh
[[ -x "$gh" ]] || gh=gh
filter="${1:-}"

printf '%-30s %-18s %-10s %7s  %-10s %s\n' TOOL CATEGORY STATUS STARS PUSHED ARCHIVED
yq -p toml -o json '.tool' "$dir/catalog.toml" |
  jq -r --arg f "$filter" '.[] | select($f == "" or .status == $f or .category == $f) | [.name, .repo, .category, .status] | @tsv' |
  while IFS=$'\t' read -r name repo category status; do
    if info="$("$gh" api "repos/$repo" --jq '[.stargazers_count, .pushed_at[:10], .archived] | @tsv' 2>/dev/null)"; then
      IFS=$'\t' read -r stars pushed archived <<<"$info"
    else
      stars="-" pushed="missing" archived="-"
    fi
    printf '%-30s %-18s %-10s %7s  %-10s %s\n' "${name:0:30}" "$category" "$status" "$stars" "$pushed" "$archived"
  done
