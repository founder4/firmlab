#!/usr/bin/env bash
#
# Refuse a hand-written `api` mock in the web suite.
#
# Every web test file used to build its own mock by spreading the real client — `{ ...actual.api, foo: vi.fn() }` —
# naming the methods it happened to know about. Every method it did NOT name kept pointing at the REAL client, so a
# call the component made and the file forgot issued a live `fetch` from inside jsdom. Five such calls were found and
# fixed in 8cb4251, four of them through one shared child component, and they were invisible: an unmocked call that
# RESOLVES says nothing at all, and the suite was green throughout. `apps/web/src/test-api-mock.ts` now enumerates the
# surface from the real client at runtime, so an omission names itself instead of reaching the network — but nothing
# stopped the next test file from hand-writing the spread again, because the old shape still compiles and still passes.
#
# Two rules, deliberately different in scope:
#
#   A. No web source may spread the real client (`...actual.api`, `Object.assign({}, actual.api, …)`). This one runs
#      over every `.ts`/`.tsx` under `apps/web/src`, not only test files, because a shared test helper is exactly where
#      the pattern would hide next.
#   B. A test file that `vi.mock`s the client must delegate to `buildApiMock`. Rule A can be sidestepped by writing the
#      object literal out by hand; this one cannot, and it is what keeps the enumerate-at-runtime property.
#
# What this does NOT claim. It checks the SHAPE of the mock, not that a test asserts anything useful about the call —
# a component that swallows its own errors will swallow an unmocked-call throw too, and a default stubbed with the
# wrong fixture is as wrong as it ever was. The one guarantee is narrow and worth having by itself: no web test file
# silently keeps a live client under its mock.
#
# Its own success path is the part that matters. `grep` exits 1 when it matches nothing, which under `set -e` is how
# this project's last four guards died on a CLEAN tree — so "no match" is separated from "grep could not read the
# file" (>= 2) explicitly rather than swallowed with `|| true`, the tools it shells out to are checked for existence
# first, and an empty file list is reported as a failure to look, never as a pass. A guard that could not look must
# never read as "clean".
#
#   scripts/check-web-api-mock.sh      check web sources, tracked or newly added
set -euo pipefail

# The backstop for an abort this script did not handle — every deliberate outcome below prints its own verdict and
# sets this first. Written as an EXIT trap rather than the obvious ERR one because `set -E` propagates ERR into
# command substitutions, where `if ! x="$(git …)"` is a HANDLED failure: the first version printed "this is a bug in
# the guard" over a branch that was working exactly as designed, which is how a backstop teaches its reader to ignore
# it. Command substitutions reset the EXIT trap, so this fires once, in the main shell, and only when it should.
#
# `exit "$rc"` at the end is not tidiness. bash hands the shell the exit status of the LAST COMMAND RUN IN THE TRAP,
# so the first version of this backstop printed "a bug in the guard, NOT a clean tree" and then returned 0 — `printf`
# had succeeded — and `pnpm biome` would have walked straight past an aborted guard into `biome check .`. The status
# is captured on the first line and re-raised on the last, and an abort that somehow carried 0 is forced to 2.
verdict=0
on_exit() {
  local rc=$?
  if [ "$verdict" -eq 0 ]; then
    printf '\033[1;31m[x]\033[0m check-web-api-mock.sh exited before reaching a verdict — a bug in the guard, NOT a clean tree\n' >&2
    [ "$rc" -eq 0 ] && rc=2
  fi
  exit "$rc"
}
trap on_exit EXIT

# Every binary this script relies on, checked BEFORE anything uses one. `pkill` was missing from the container for the
# entire life of the module that shelled out to it, and the ENOENT was logged as "nothing to do" — so absence is
# checked here, and it is fatal. This block comes before the `cd` for the same reason: the first draft resolved its
# own directory with `dirname`, an external binary, and on a broken PATH died there with a confusing message instead
# of the clear one two lines further down. The root is resolved with parameter expansion now, and needs no binary.
for tool in git grep sort; do
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

# The one file that must name the real client: it builds the mock FROM it, and its doc comment quotes the very shape
# refused below. Anything else added here needs its justification written down beside it.
is_allowed() {
  case "$1" in
  apps/web/src/test-api-mock.ts) return 0 ;;
  esac
  return 1
}

# A spread of the real client, under any variable name — `...actual.api`, `...real.api`, `Object.assign({}, o.api, …)`.
RULE_A='\.\.\.[A-Za-z_$][A-Za-z0-9_$]*\.api|Object\.assign\([^)]*\.api'
# A `vi.mock` of the client module itself, relative-imported as web code always imports it.
MOCKS_CLIENT="vi\.mock\([[:space:]]*['\"](\.\./|\./)+api(\.js)?['\"]"
# The delegation that keeps the mocked surface enumerated from the real one.
DELEGATES="buildApiMock"

SCAN_OUT=''
# Returns 0 with SCAN_OUT set when the pattern matches, 1 when it does not — the SUCCESS path, and the one that killed
# deploy.sh's port check — and >= 2 when grep itself could not read the file, which is an answer of its own and must
# not be filed under "no match". Written as an `if` condition on purpose: a bare `SCAN_OUT="$(grep …)"` is a failing
# command under `set -e` the moment the tree is clean, and `|| true` would hide the >= 2 case along with it.
scan() {
  local pattern="$1"
  local file="$2"
  SCAN_OUT=''
  if SCAN_OUT="$(grep -nE "$pattern" -- "$file")"; then
    return 0
  else
    return $?
  fi
}

# Name the offending lines. An exit code alone sends the reader back to the same grep this script just ran.
report_lines() {
  local shown=0
  local line no text
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    shown=$((shown + 1))
    if [ "$shown" -gt 5 ]; then
      printf '      … and more\n' >&2
      break
    fi
    no="${line%%:*}"
    text="${line#*:}"
    printf '      line %s: %s\n' "$no" "$text" >&2
  done <<EOF
$SCAN_OUT
EOF
}

# `--others --exclude-standard` is not a detail: a file is at its most dangerous BEFORE its first commit, and a new
# test file is written, run and believed long before it is added. git's failure is caught here rather than in a
# process substitution, where its exit status is discarded and the loop simply reads nothing — indistinguishable,
# from where the reader sits, from a clean tree. `sort -u` runs separately so that only git's status is read as git's.
listing=''
if ! listing="$(git ls-files --cached --others --exclude-standard -- \
  'apps/web/src/*.ts' 'apps/web/src/*.tsx' 2>&1)"; then
  printf '\033[1;31m[x]\033[0m git ls-files failed, so no file was examined:\n%s\n' "$listing" >&2
  printf '\033[1;33m[!]\033[0m Refusing to exit 0: a guard that could not look must never read as "clean".\n' >&2
  verdict=1
  exit 2
fi
sources="$(printf '%s\n' "$listing" | sort -u)"

offenders=0
unreadable=0
n_sources=0
n_tests=0
n_mockers=0

while IFS= read -r f; do
  [ -n "$f" ] || continue
  [ -f "$f" ] || continue # tracked but deleted in the working tree
  is_allowed "$f" && continue
  n_sources=$((n_sources + 1))

  # Rule A — the spread, anywhere in web sources.
  if scan "$RULE_A" "$f"; then
    printf '\033[1;31m[x]\033[0m %s hand-writes the api mock by spreading the real client\n' "$f" >&2
    report_lines
    offenders=$((offenders + 1))
  elif [ "$?" -ge 2 ]; then
    printf '\033[1;31m[x]\033[0m %s could not be read by grep — not examined\n' "$f" >&2
    unreadable=$((unreadable + 1))
  fi

  # Rule B — a test file that mocks the client must delegate.
  case "$f" in
  *.test.ts | *.test.tsx) ;;
  *) continue ;;
  esac
  n_tests=$((n_tests + 1))

  if scan "$MOCKS_CLIENT" "$f"; then
    n_mockers=$((n_mockers + 1))
    mock_lines="$SCAN_OUT"
    if scan "$DELEGATES" "$f"; then
      : # delegates to buildApiMock — the whole surface is enumerated from the real client
    elif [ "$?" -ge 2 ]; then
      printf '\033[1;31m[x]\033[0m %s could not be read by grep — not examined\n' "$f" >&2
      unreadable=$((unreadable + 1))
    else
      printf '\033[1;31m[x]\033[0m %s mocks the api client without buildApiMock\n' "$f" >&2
      SCAN_OUT="$mock_lines"
      report_lines
      offenders=$((offenders + 1))
    fi
  elif [ "$?" -ge 2 ]; then
    printf '\033[1;31m[x]\033[0m %s could not be read by grep — not examined\n' "$f" >&2
    unreadable=$((unreadable + 1))
  fi
done <<EOF
$sources
EOF

# A file grep could not read is not a file that passed. It gets its own exit code, and it is checked first so that
# "I could not look at 3 files" is never buried under a verdict about the ones I could.
if [ "$unreadable" -gt 0 ]; then
  printf '\033[1;31m[x]\033[0m %s file(s) could not be examined (grep failed on them)\n' "$unreadable" >&2
  printf '\033[1;33m[!]\033[0m Refusing to exit 0: a guard that could not look must never read as "clean".\n' >&2
  verdict=1
  exit 2
fi

if [ "$offenders" -gt 0 ]; then
  printf '\033[1;33m[!]\033[0m Build the mock from the real client instead:\n' >&2
  printf "        vi.mock('../api', async (importOriginal) => {\n" >&2
  printf "          const actual = await importOriginal<typeof import('../api')>();\n" >&2
  printf "          const { buildApiMock } = await import('../test-api-mock');\n" >&2
  printf '          return { ...actual, api: buildApiMock(actual.api) };\n' >&2
  printf '        });\n' >&2
  printf '\033[1;33m[!]\033[0m A spread names the methods the file knows about and leaves every other one pointing at the\n' >&2
  printf '    REAL client, so a call the component makes and the test forgot issues a live fetch from jsdom. Five of\n' >&2
  printf '    those were found and fixed in 8cb4251, and the suite was green the whole time.\n' >&2
  verdict=1
  exit 1
fi

# An empty list is not a pass. If the pathspec ever stops matching — a move, a rename, a wrong glob — the loop above
# runs zero times and every counter stays at zero, which is exactly what a clean tree looks like from here.
if [ "$n_sources" -eq 0 ] || [ "$n_tests" -eq 0 ]; then
  printf '\033[1;31m[x]\033[0m matched %s web source(s) and %s test file(s) under apps/web/src — nothing was examined\n' \
    "$n_sources" "$n_tests" >&2
  printf '\033[1;33m[!]\033[0m Refusing to exit 0: a guard that could not look must never read as "clean".\n' >&2
  verdict=1
  exit 2
fi

# The success line states what was looked at, not just that nothing was found — the two are only the same sentence
# when the counts are in it.
verdict=1
printf '\033[1;36m==>\033[0m no hand-written api mock: %s web sources scanned, %s test files, %s of them mock the client via buildApiMock\n' \
  "$n_sources" "$n_tests" "$n_mockers"
