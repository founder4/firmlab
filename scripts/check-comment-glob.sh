#!/usr/bin/env bash
#
# Refuse a `*/` that a block comment did not mean as its terminator.
#
# A path glob written inside a doc comment — `locales/*/coverage.ts`, `apps/web/src/**/*.tsx` — contains the
# two characters that CLOSE the comment. The comment ends there, mid-sentence, and every word after it is parsed
# as code. Nothing about the diagnosis points at the glob: tsc reports TS1443/TS1434/TS1160 wherever the wreckage
# first fails to parse, which is routinely dozens of lines below, and esbuild simply refuses to transform the
# module, so vitest cannot even LOAD the file. It hit three files in one session, blocked every agent's test run,
# and passed review by eye all three times — because a glob in prose is exactly what it looks like it is.
#
# Two rules, because they fail differently and neither one subsumes the other.
#
#   A. Inside a block comment, a `*/` that is GLUED to its surroundings — preceded by `/` (the `/*/` in
#      `locales/*/coverage.ts`) or followed immediately by a path-ish character (the `**/` in `src/**/*.tsx`, the
#      `*/5` of a cron line). This is the one that names the mistake at the character that caused it.
#   B. A line whose entire content is `*/` while NOT inside a block comment. That line cannot be valid code in any
#      of these languages, so it is a certainty rather than a heuristic: it is the abandoned closer of a doc block
#      that something earlier terminated for it. It catches the early terminations rule A's SHAPE does not
#      describe, and it needs no notion of what a glob looks like.
#
# The shapes were chosen from the tree, not from imagination. Every block-comment terminator in the repo was
# enumerated first: 2934 of them across 385 files, and exactly two forms exist — ` */` at end of line and ` */}`
# from JSX's `{/* … */}`. No terminator anywhere is preceded by `/` or followed by an alphanumeric, so rule A's
# character set has no overlap at all with legitimate code here. A guard with false positives gets disabled, and
# a disabled guard is worth less than none.
#
# What this does NOT claim. The scanner tracks block comments, line comments and quoted strings; it does not
# understand regular-expression literals, so a `/*` inside a character class would confuse it, and a `//` inside
# an unquoted CSS `url()` makes it skip the rest of that line. Both directions of that error make it look at LESS,
# never at more — it cannot invent an offender, only miss one. Files are the units it is honest about, which is
# why the success line states how many it read and how many block comments it walked.
#
# Its own SUCCESS path is the part that took the care. `grep` exits 1 when it matches nothing, and under
# `set -e` that is how four of this project's guards died on a CLEAN tree; there is no grep here at all, awk's
# exit status is checked as a real answer, an empty file list is a failure to look rather than a pass, every
# binary is verified present before it is relied on (the `pkill` lesson), and an abort that never reached a
# verdict is forced non-zero by the EXIT trap. A guard that could not look must never read as "clean".
#
#   scripts/check-comment-glob.sh      check sources, tracked or newly added
set -Eeuo pipefail

# The backstop for an abort no branch below handled. Every deliberate outcome sets `verdict` first, so this only
# speaks when control left by a path nobody wrote. It is an EXIT trap, not ERR: `set -E` propagates ERR into
# command substitutions, where `if ! x="$(git …)"` is a HANDLED failure, and a backstop that cries over a working
# branch teaches its reader to ignore it. `exit "$rc"` on the last line is not tidiness either — bash hands the
# shell the status of the LAST COMMAND RUN IN THE TRAP, so without it a `printf` that succeeded would return 0
# and `pnpm biome` would walk straight past an aborted guard.
verdict=0
on_exit() {
  local rc=$?
  if [ "$verdict" -eq 0 ]; then
    printf '\033[1;31m[x]\033[0m check-comment-glob.sh exited before reaching a verdict — a bug in the guard, NOT a clean tree\n' >&2
    [ "$rc" -eq 0 ] && rc=2
  fi
  exit "$rc"
}
trap on_exit EXIT

# Checked BEFORE anything uses one, and before the `cd`, which is resolved by parameter expansion precisely so it
# needs no binary of its own: with a stripped PATH the obvious `dirname` form dies here with the wrong message.
for tool in git awk sort; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf '\033[1;31m[x]\033[0m %s is not on PATH, so this guard cannot look at anything\n' "$tool" >&2
    printf '\033[1;33m[!]\033[0m Refusing to exit 0: a guard that could not look must never read as "clean".\n' >&2
    verdict=1
    exit 2
  fi
done

case "${BASH_SOURCE[0]}" in
*/*) here="${BASH_SOURCE[0]%/*}" ;;
*) here='.' ;;
esac
if ! cd "$here/.."; then
  printf '\033[1;31m[x]\033[0m cannot reach the repo root from %s\n' "$here" >&2
  printf '\033[1;33m[!]\033[0m Refusing to exit 0: a guard that could not look must never read as "clean".\n' >&2
  verdict=1
  exit 2
fi

# Only the languages that HAVE `/* … */`. Markdown carries `*/` in prose all day and none of it is a comment;
# JSON has no comments at all. `--others --exclude-standard` is not a detail — a file is at its most dangerous
# before its first commit, and all three instances of this defect were caught (late) in files that had never been
# committed. git's failure is caught here rather than in a process substitution, whose exit status is DISCARDED:
# the loop would simply read nothing, which from where the reader sits is indistinguishable from a clean tree.
listing=''
if ! listing="$(git ls-files --cached --others --exclude-standard -- \
  '*.ts' '*.tsx' '*.js' '*.mjs' '*.cjs' '*.css' 2>&1)"; then
  printf '\033[1;31m[x]\033[0m git ls-files failed, so no file was examined:\n%s\n' "$listing" >&2
  printf '\033[1;33m[!]\033[0m Refusing to exit 0: a guard that could not look must never read as "clean".\n' >&2
  verdict=1
  exit 2
fi

# `./` in front of every path for two reasons: awk reads a bare `name=value` argument as a variable assignment
# rather than a file, and a path starting with `-` would be read as an option. The prefix is stripped again in the
# report so the paths printed are the ones a reader can paste.
files=()
while IFS= read -r f; do
  [ -n "$f" ] || continue
  [ -f "$f" ] || continue # tracked but deleted in the working tree
  files+=("./$f")
done <<EOF
$(printf '%s\n' "$listing" | sort -u)
EOF

# An empty list is not a pass. If the pathspec ever stops matching — a move, a rename, a wrong glob — awk would be
# handed no file, read STDIN instead, and hang or report a spotless zero.
if [ "${#files[@]}" -eq 0 ]; then
  printf '\033[1;31m[x]\033[0m matched 0 source files with block comments — nothing was examined\n' >&2
  printf '\033[1;33m[!]\033[0m Refusing to exit 0: a guard that could not look must never read as "clean".\n' >&2
  verdict=1
  exit 2
fi

# The characters that may follow a `*/` in a glob but never follow a real terminator in this tree. Built with
# ANSI-C quoting so the backtick (\x60), the apostrophe (\x27) and the quote need no escaping games in either
# shell or awk, and compared with awk's `index()`, which is a literal substring search — no character class, so
# the `-` and `/` in it carry no regex meaning.
glue=$'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789*._-/\x60\x27"'

report=''
if ! report="$(awk -v glue="$glue" '
function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t\r]+$/, "", s); return s }

FNR == 1 { inBlock = 0; inStr = ""; openLine = 0; nfiles++ }

{
  line = $0
  wasInBlock = inBlock
  wasInStr = inStr
  n = length(line)
  i = 1

  while (i <= n) {
    c = substr(line, i, 1)
    d = substr(line, i + 1, 1)

    if (inBlock) {
      if (c == "*" && d == "/") {
        # Rule A. `before` is the character the `*` is glued to, `after` the one the `/` is glued to; the ends of
        # the line are deliberately NOT treated as glue, since ` */` at end of line is the terminator itself.
        before = (i > 1) ? substr(line, i - 1, 1) : ""
        after = (i + 2 <= n) ? substr(line, i + 2, 1) : ""
        if (before == "/" || (after != "" && index(glue, after) > 0)) {
          printf "A\t%s\t%d\t%d\t%s\n", FILENAME, FNR, openLine, trim(line)
          nfound++
        }
        inBlock = 0
        nblocks++
        i += 2
        continue
      }
      i++
      continue
    }

    if (inStr != "") {
      if (c == "\\") { i += 2; continue }
      if (c == inStr) { inStr = "" }
      i++
      continue
    }

    if (c == "/" && d == "/") break                                   # line comment: the rest of the line is prose
    if (c == "/" && d == "*") { inBlock = 1; openLine = FNR; i += 2; continue }
    if (c == "\x27" || c == "\"" || c == "`") { inStr = c; i++; continue }
    i++
  }

  # Rule B, judged from the state the line STARTED in: a lone `*/` on a line that no block comment was open on.
  # There is no reading of that as code, so it is reported as a certainty, not a suspicion.
  if (!wasInBlock && wasInStr == "" && trim(line) == "*/") {
    printf "B\t%s\t%d\t%d\t%s\n", FILENAME, FNR, 0, trim(line)
    nfound++
  }

  # Only a backtick survives a newline; an unterminated quote is a syntax error, not a multi-line string, and
  # carrying it forward would desynchronise every line after it.
  if (inStr != "" && inStr != "`") inStr = ""
}

END { printf "=\t%d\t%d\t%d\n", nfiles, nblocks, nfound }
' "${files[@]}" 2>&1)"; then
  printf '\033[1;31m[x]\033[0m awk could not read the sources, so the result is not a verdict:\n%s\n' "$report" >&2
  printf '\033[1;33m[!]\033[0m Refusing to exit 0: a guard that could not look must never read as "clean".\n' >&2
  verdict=1
  exit 2
fi

summary="$(printf '%s\n' "$report" | awk -F'\t' '$1 == "=" { print $2, $3, $4 }')"
if [ -z "$summary" ]; then
  printf '\033[1;31m[x]\033[0m the scan produced no summary line — it did not run to completion\n' >&2
  printf '\033[1;33m[!]\033[0m Refusing to exit 0: a guard that could not look must never read as "clean".\n' >&2
  verdict=1
  exit 2
fi
# shellcheck disable=SC2086
set -- $summary
n_files="$1"
n_blocks="$2"
n_found="$3"

if [ "$n_found" -gt 0 ]; then
  shown=0
  while IFS="$(printf '\t')" read -r rule file line open text; do
    case "$rule" in
    A | B) ;;
    *) continue ;;
    esac
    file="${file#./}"
    shown=$((shown + 1))
    if [ "$shown" -gt 10 ]; then
      printf '      … and %s more\n' "$((n_found - 10))" >&2
      break
    fi
    if [ "$rule" = 'A' ]; then
      printf '\033[1;31m[x]\033[0m %s:%s — `*/` inside the block comment opened on line %s ends it here\n' \
        "$file" "$line" "$open" >&2
    else
      printf '\033[1;31m[x]\033[0m %s:%s — a lone `*/` with no block comment open: one was closed early above\n' \
        "$file" "$line" >&2
    fi
    printf '      %s\n' "$text" >&2
  done <<EOF
$report
EOF
  printf '\033[1;33m[!]\033[0m A glob in a doc comment carries the comment terminator inside it, so the comment ends\n' >&2
  printf '    mid-sentence and the prose after it is parsed as code. tsc then reports TS1443/TS1434/TS1160 wherever\n' >&2
  printf '    the wreckage first fails to parse — usually far below — and esbuild cannot transform the module at all,\n' >&2
  printf '    so the file will not even LOAD under vitest.\n' >&2
  printf '\033[1;33m[!]\033[0m Write the path without the glob: `locales/<lang>/coverage.ts`, `locales/{en,es}/…`, or\n' >&2
  printf '    name the two files. Anything but the two characters that close the comment.\n' >&2
  verdict=1
  exit 1
fi

# The success line states what was LOOKED AT, not merely that nothing was found. "Found nothing" and "looked at
# nothing" are the same sentence until the counts are in it — and the block-comment count is the one that says the
# scanner actually walked comments rather than skimming past every file.
verdict=1
printf '\033[1;36m==>\033[0m no comment-terminating glob: %s source file(s) scanned, %s block comment(s) walked\n' \
  "$n_files" "$n_blocks"
