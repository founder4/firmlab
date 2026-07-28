#!/usr/bin/env bash
#
# Refuse a literal NUL byte in a tracked source file.
#
# This is the third trap in CLAUDE.md, and it is here because it caught two real instances the day it was written:
# one introduced by `compmap.ts` in 8b159f6 (`\`${from}\0${to}\`` as a composite map key) and one in
# `run-summary.ts` (a sentinel for the image-wide bucket). Both had shipped through every gate the project has.
#
# What makes it worth its own check is that NOTHING ELSE catches it. tsc compiles it, biome formats it, vitest runs
# it and the tests pass — the code is CORRECT. What breaks is everything around it: `file` reports the source as
# `data`, and grep skips a binary file WITHOUT SAYING SO, so a large and perfectly good change looks like it was
# never made. It arrives naturally, because a NUL genuinely is the right separator for a key whose fields must not
# collide. The rule is not "never use one" — it is "write it as \u0000, never as the byte".
#
# It scans tracked AND new-but-not-ignored files, which is not a detail: the first version listed only tracked
# ones, ran clean, and was itself carrying a NUL in this very comment block — it had not been `git add`ed yet, so
# it never looked at itself. A file is at its most dangerous before its first commit, which is exactly the window
# `git ls-files` alone leaves open.
#
# The guard's OWN success path was wrong for as long as it existed, which is the fourth instance of CLAUDE.md's
# "a guard is only as good as its SUCCESS path" trap. The file list was fed in through a process substitution —
# `done < <(git ls-files …)` — and a process substitution's exit status is DISCARDED. With `git` unavailable or
# failing for any reason the loop read nothing, `found` stayed 0, and this script printed "no literal NUL bytes in
# tracked sources" and exited 0. Verified by shadowing `git` with a stub that exits 128: the clean line printed.
# A guard that cannot look must say so and must NOT exit 0, so the listing is now captured and checked, the tools
# it shells out to are verified to exist first (the `pkill` lesson), and the success line states HOW MANY files it
# scanned — because "found nothing" and "looked at nothing" are only the same sentence when the count is visible.
#
#   scripts/check-nul.sh          check sources, tracked or newly added
set -Eeuo pipefail

# Parameter expansion, not `dirname`: this runs BEFORE the tool check below, so it must not depend on an external
# binary. With a stripped PATH the old form failed here first and reported the wrong thing.
self="${BASH_SOURCE[0]}"
cd "${self%/*}/.." || exit 2

for tool in git tr wc cat grep sed sort; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf '\033[1;31m[x]\033[0m %s is not on PATH — this check cannot look. Refusing to exit 0.\n' "$tool" >&2
    exit 2
  fi
done

if ! files="$(git ls-files --cached --others --exclude-standard \
  '*.ts' '*.tsx' '*.js' '*.mjs' '*.cjs' '*.json' '*.css' '*.md' '*.sh' '*.py' | sort -u)"; then
  printf '\033[1;31m[x]\033[0m listing the sources failed — this check cannot look. Refusing to exit 0.\n' >&2
  exit 2
fi

if [ -z "$files" ]; then
  printf '\033[1;31m[x]\033[0m matched 0 source files — nothing was examined, so this is not a clean result.\n' >&2
  exit 2
fi

scanned=0
found=0
while IFS= read -r f; do
  [ -f "$f" ] || continue
  scanned=$((scanned + 1))
  n="$(tr -d -c '\000' < "$f" | wc -c | tr -d ' ')"
  if [ "$n" != "0" ]; then
    printf '\033[1;31m[x]\033[0m %s carries %s literal NUL byte(s)\n' "$f" "$n" >&2
    # Name the lines, since grep cannot: it treats the file as binary and stays silent about it. `cat -v` renders
    # a NUL as `^@`, which IS greppable and is portable across BSD and GNU — no -P, no locale surprises.
    cat -v "$f" | grep -n '\^@' | head -5 | sed 's/^/      line /' >&2 || true
    found=$((found + 1))
  fi
done <<< "$files"

if [ "$found" -gt 0 ]; then
  printf '\033[1;33m[!]\033[0m Write it as \\u0000 instead. The byte passes tsc, biome and vitest, and breaks grep.\n' >&2
  exit 1
fi
printf '\033[1;36m==>\033[0m no literal NUL bytes: %s source file(s) scanned\n' "$scanned"
