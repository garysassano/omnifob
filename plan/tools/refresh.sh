#!/usr/bin/env bash
# Prints live GitHub data for every tool listed in README.md next to it: stars,
# last push and whether it is archived. Optionally filtered by status
# (studied, to-study, reference): plan/tools/refresh.sh to-study
set -euo pipefail

dir="$(cd "$(dirname "$0")" && pwd)"
gh=~/.local/bin/gh
[[ -x "$gh" ]] || gh=gh
filter="${1:-}"

printf '%-32s %-10s %7s  %-10s %s\n' TOOL STATUS STARS PUSHED ARCHIVED
# Table rows look like: | [name](https://github.com/owner/repo) | covers | why | status | look at |
sed -nE 's/^\| \[([^]]+)\]\(https:\/\/github\.com\/([^)]+)\) \|[^|]*\|.*\| ([^|]+) \|[^|]*\|$/\1\t\2\t\3/p' "$dir/README.md" |
  while IFS=$'\t' read -r name repo status; do
    status="$(tr -d '*' <<<"$status" | tr ' ' '-')"
    [[ -z "$filter" || "$status" == "$filter" ]] || continue
    if info="$("$gh" api "repos/$repo" --jq '[.stargazers_count, .pushed_at[:10], .archived] | @tsv' 2>/dev/null)"; then
      IFS=$'\t' read -r stars pushed archived <<<"$info"
    else
      stars="-" pushed="missing" archived="-"
    fi
    printf '%-32s %-10s %7s  %-10s %s\n' "${name:0:32}" "$status" "$stars" "$pushed" "$archived"
  done
