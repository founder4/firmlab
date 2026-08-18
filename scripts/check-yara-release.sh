#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="${YARA_CORPUS_LOCK:-$ROOT/ops/yara/corpus.lock.json}"
API="${YARA_RELEASE_API:-https://api.github.com/repos/YARAHQ/yara-forge/releases/latest}"
JSON_FILE="${YARA_RELEASE_JSON_FILE:-}"
NO_FAIL=0

if [ "${1:-}" = "--no-fail" ]; then NO_FAIL=1; fi

for tool in jq node; do
  command -v "$tool" >/dev/null 2>&1 || { printf 'falta la dependencia: %s\n' "$tool" >&2; exit 127; }
done

if [ -n "$JSON_FILE" ]; then
  release="$(cat "$JSON_FILE")"
else
  command -v curl >/dev/null 2>&1 || { printf 'falta la dependencia: curl\n' >&2; exit 127; }
  headers=(-H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28')
  if [ -n "${GITHUB_TOKEN:-}" ]; then headers+=(-H "Authorization: Bearer ${GITHUB_TOKEN}"); fi
  release="$(curl --fail --silent --show-error --location "${headers[@]}" "$API")"
fi

current="$(node -e 'const x=require(process.argv[1]); process.stdout.write(String(x.external.release))' "$LOCK")"
current_rules="$(node -e 'const x=require(process.argv[1]); process.stdout.write(String(x.external.rulesDeclared))' "$LOCK")"
latest="$(printf '%s' "$release" | jq -er '.tag_name')"
published="$(printf '%s' "$release" | jq -er '.published_at')"
asset="$(printf '%s' "$release" | jq -er '.assets[] | select(.name == "yara-forge-rules-core.zip")')"
url="$(printf '%s' "$asset" | jq -er '.browser_download_url')"
digest="$(printf '%s' "$asset" | jq -er '.digest | sub("^sha256:"; "")')"
bytes="$(printf '%s' "$asset" | jq -er '.size')"
latest_rules="$(printf '%s' "$release" | jq -r '.body | capture("(?m)^\\|[[:space:]]*core[[:space:]]*\\|[[:space:]]*(?<rules>[0-9]+)").rules // empty')"
[ -n "$latest_rules" ] || { printf 'la release %s no declara el total Core en su tabla\n' "$latest" >&2; exit 1; }

update=false
if [[ "$latest" > "$current" ]]; then update=true; fi

jq -n \
  --arg currentRelease "$current" \
  --arg latestRelease "$latest" \
  --arg publishedAt "$published" \
  --arg archiveUrl "$url" \
  --arg archiveSha256 "$digest" \
  --argjson currentRules "$current_rules" \
  --argjson latestRules "$latest_rules" \
  --argjson archiveBytes "$bytes" \
  --argjson updateAvailable "$update" \
  '{schemaVersion:1,currentRelease:$currentRelease,latestRelease:$latestRelease,publishedAt:$publishedAt,updateAvailable:$updateAvailable,currentRules:$currentRules,latestRules:$latestRules,ruleDelta:($latestRules-$currentRules),archiveUrl:$archiveUrl,archiveSha256:$archiveSha256,archiveBytes:$archiveBytes,action:(if $updateAvailable then "evaluate-only: run scripts/evaluate-yara-candidate.sh; this check never changes the lock or deployment" else "none" end)}'

if [ "$update" = true ] && [ "$NO_FAIL" -eq 0 ]; then exit 3; fi
