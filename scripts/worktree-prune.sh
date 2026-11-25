#!/usr/bin/env bash
# Retire the worktrees whose work has already landed.
#
# A tree is removed only when both hold: its HEAD is an ancestor of
# origin/master, and it has no uncommitted changes to tracked files. The main
# checkout and the tree this runs from are never touched. Untracked files
# (.venv, .env) are expected in a worktree and do not block removal; the branch
# is deleted only after its commits are confirmed present in origin/master, so
# nothing here depends on remembering.
#
# A tree touched recently is skipped: parallel sessions share the repository,
# and two trees appeared during the hour this script was written. Merged and
# clean is necessary, not sufficient.
#
#   scripts/worktree-prune.sh [--dry-run] [--no-fetch] [--min-age MIN]
set -euo pipefail

dry_run=0
do_fetch=1
min_age=15
while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) dry_run=1; shift ;;
    --no-fetch) do_fetch=0; shift ;;
    --min-age) min_age="${2:-15}"; shift 2 ;;
    --min-age=*) min_age="${1#*=}"; shift ;;
    -h|--help) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

repo=$(git rev-parse --show-toplevel)
cd "$repo"
here=$(pwd -P)

if [ "$do_fetch" = 1 ]; then
  git fetch origin --quiet
fi
base=origin/master
if ! git rev-parse --verify --quiet "$base" >/dev/null; then
  echo "no $base; refusing to guess what is merged" >&2
  exit 1
fi

main_tree=$(git worktree list --porcelain | sed -n 's/^worktree //p' | head -1)
main_real=$(cd "$main_tree" && pwd -P)

removed=0
kept=0

printf '%-34s %-6s %-7s %s\n' worktree dirty merged action

delete_branch() {
  local branch=$1
  if [ "$dry_run" = 1 ]; then
    echo "would delete branch $branch"
    return 0
  fi
  if git branch -d "$branch" >/dev/null 2>&1; then
    echo "deleted branch $branch"
    return 0
  fi
  # A squash-merged branch is not an ancestor, but every commit can still have
  # an equivalent patch in the base. Ask that question rather than assume it.
  if [ -z "$(git cherry "$base" "$branch" | grep '^+' || true)" ]; then
    git branch -D "$branch" >/dev/null
    echo "deleted branch $branch (every commit equivalent in $base)"
  else
    echo "kept branch $branch (commits not in $base)"
  fi
}

while IFS= read -r path; do
  [ -n "$path" ] || continue
  real=$(cd "$path" 2>/dev/null && pwd -P) || continue

  if [ "$real" = "$main_real" ]; then
    printf '%-34s %-6s %-7s %s\n' "$(basename "$path")" "-" "-" "kept (main checkout)"
    continue
  fi
  if [ "$real" = "$here" ]; then
    printf '%-34s %-6s %-7s %s\n' "$(basename "$path")" "-" "-" "kept (running from here)"
    continue
  fi

  branch=$(git -C "$real" branch --show-current 2>/dev/null || true)
  if [ -z "$branch" ]; then
    printf '%-34s %-6s %-7s %s\n' "$(basename "$path")" "-" "-" "kept (detached HEAD)"
    continue
  fi

  if [ -f "$real/.git" ]; then
    touched=$(stat -c %Y "$real/.git" 2>/dev/null || echo 0)
  else
    touched=$(stat -c %Y "$real" 2>/dev/null || echo 0)
  fi
  age_min=$(( ($(date +%s) - touched) / 60 ))
  if [ "$age_min" -lt "$min_age" ]; then
    printf '%-34s %-6s %-7s %s\n' "$(basename "$path")" "-" "-" \
      "kept (active: touched ${age_min}m ago)"
    kept=$((kept + 1))
    continue
  fi

  dirty=$(git -C "$real" status --porcelain --untracked-files=no 2>/dev/null | wc -l | tr -d ' ')
  if git -C "$real" merge-base --is-ancestor HEAD "$base" 2>/dev/null; then
    merged=yes
  else
    merged=no
  fi

  if [ "$merged" = yes ] && [ "$dirty" = 0 ]; then
    if [ "$dry_run" = 1 ]; then
      action="would remove"
    elif git worktree remove --force "$real" >/dev/null 2>&1; then
      action="removed"
    else
      action="kept (remove failed)"
    fi
    if [ "$action" != "kept (remove failed)" ]; then
      removed=$((removed + 1))
      printf '%-34s %-6s %-7s %s\n' "$(basename "$path")" "$dirty" "$merged" "$action"
      delete_branch "$branch"
      continue
    fi
  else
    action="kept (unmerged work)"
    if [ "$dirty" != 0 ]; then
      action="kept ($dirty uncommitted file(s))"
    fi
  fi
  kept=$((kept + 1))
  printf '%-34s %-6s %-7s %s\n' "$(basename "$path")" "$dirty" "$merged" "$action"
done < <(git worktree list --porcelain | sed -n 's/^worktree //p')

if [ "$dry_run" = 1 ]; then
  echo
  echo "dry run: $removed worktree(s) would be removed, $kept kept"
else
  git worktree prune
  echo
  echo "$removed worktree(s) removed, $kept kept"
fi
