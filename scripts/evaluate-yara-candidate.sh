#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="$ROOT/ops/yara/corpus.lock.json"
TAG="${1:-latest}"
REPORT="${2:-$ROOT/yara-candidate-report.md}"
CONTAINER="${FIRMLAB_CONTAINER:-firmlab}"
API_BASE="${FIRMLAB_API_BASE:-http://127.0.0.1:8899/api}"

for tool in curl jq node unzip docker comm; do
  command -v "$tool" >/dev/null 2>&1 || { printf 'falta la dependencia: %s\n' "$tool" >&2; exit 127; }
done

if [ "$TAG" = latest ]; then
  release_api='https://api.github.com/repos/YARAHQ/yara-forge/releases/latest'
else
  release_api="https://api.github.com/repos/YARAHQ/yara-forge/releases/tags/$TAG"
fi
headers=(-H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28')
if [ -n "${GITHUB_TOKEN:-}" ]; then headers+=(-H "Authorization: Bearer ${GITHUB_TOKEN}"); fi
release="$(curl --fail --silent --show-error --location "${headers[@]}" "$release_api")"
tag="$(printf '%s' "$release" | jq -er '.tag_name')"
asset="$(printf '%s' "$release" | jq -er '.assets[] | select(.name == "yara-forge-rules-core.zip")')"
url="$(printf '%s' "$asset" | jq -er '.browser_download_url')"
expected_sha="$(printf '%s' "$asset" | jq -er '.digest | sub("^sha256:"; "")')"
current_tag="$(node -e 'const x=require(process.argv[1]); process.stdout.write(String(x.external.release))' "$LOCK")"
current_rules="${FIRMLAB_YARA_CURRENT:-${HOME}/homelab/firmlab/yara-rules/external/yara-forge-core.yar}"
if [ ! -f "$current_rules" ]; then
  printf 'no existe el corpus actual esperado: %s\n' "$current_rules" >&2
  exit 1
fi

tmp="$(mktemp -d /tmp/firmlab-yara-candidate.XXXXXX)"
cleanup() {
  find "$tmp" -type f -delete 2>/dev/null || true
  find "$tmp" -depth -type d -exec rmdir {} \; 2>/dev/null || true
}
trap cleanup EXIT

archive="$tmp/core.zip"
candidate="$tmp/yara-forge-core-$tag.yar"
curl --fail --location --proto '=https' --tlsv1.2 "$url" --output "$archive"
actual_sha="$(shasum -a 256 "$archive" | awk '{print $1}')"
[ "$actual_sha" = "$expected_sha" ] || {
  printf 'SHA-256 de candidata inesperado: %s != %s\n' "$actual_sha" "$expected_sha" >&2
  exit 1
}
unzip -p "$archive" packages/core/yara-rules-core.yar > "$candidate"

rule_names() {
  sed -nE 's/^[[:space:]]*((private|global)[[:space:]]+)*rule[[:space:]]+([A-Za-z_][A-Za-z0-9_]*).*/\3/p' "$1" | sort -u
}
rule_names "$current_rules" > "$tmp/current.rules"
rule_names "$candidate" > "$tmp/candidate.rules"
comm -13 "$tmp/current.rules" "$tmp/candidate.rules" > "$tmp/added.rules"
comm -23 "$tmp/current.rules" "$tmp/candidate.rules" > "$tmp/removed.rules"
current_count="$(wc -l < "$tmp/current.rules" | tr -d ' ')"
candidate_count="$(wc -l < "$tmp/candidate.rules" | tr -d ' ')"
added_count="$(wc -l < "$tmp/added.rules" | tr -d ' ')"
removed_count="$(wc -l < "$tmp/removed.rules" | tr -d ' ')"

container_rule="/tmp/firmlab-yara-core-candidate-$tag.yar"
docker cp "$candidate" "$CONTAINER:$container_rule" >/dev/null
docker exec "$CONTAINER" yara -w -e "$container_rule" /dev/null >/dev/null

# Positive controls must continue to fire before a candidate is even compared with production rootfs.
docker cp "$ROOT/scripts/test-yara-external.sh" "$CONTAINER:/tmp/test-yara-external.sh" >/dev/null
docker exec "$CONTAINER" sh -lc "YARA_BIN=yara /tmp/test-yara-external.sh '$container_rule'" > "$tmp/positive.log"

: > "$tmp/roots"
for id in $(curl --fail --silent "$API_BASE/images" | jq -r '.images[].id'); do
  root="$(curl --fail --silent "$API_BASE/images/$id/yarascan" | jq -r '.result.scan.root // empty')"
  [ -z "$root" ] || printf '%s\n' "$root" >> "$tmp/roots"
done
sort -u "$tmp/roots" -o "$tmp/roots"

: > "$tmp/current.matches"
: > "$tmp/candidate.matches"
while IFS= read -r root; do
  [ -n "$root" ] || continue
  docker exec "$CONTAINER" yara -w -e -r /opt/firmlab-yara/external/yara-forge-core.yar "$root" \
    | sed "s#^#$root\t#" >> "$tmp/current.matches"
  docker exec "$CONTAINER" yara -w -e -r "$container_rule" "$root" \
    | sed "s#^#$root\t#" >> "$tmp/candidate.matches"
done < "$tmp/roots"
sort -u "$tmp/current.matches" -o "$tmp/current.matches"
sort -u "$tmp/candidate.matches" -o "$tmp/candidate.matches"
comm -13 "$tmp/current.matches" "$tmp/candidate.matches" > "$tmp/new.matches"
comm -23 "$tmp/current.matches" "$tmp/candidate.matches" > "$tmp/lost.matches"

root_count="$(wc -l < "$tmp/roots" | tr -d ' ')"
current_match_count="$(wc -l < "$tmp/current.matches" | tr -d ' ')"
candidate_match_count="$(wc -l < "$tmp/candidate.matches" | tr -d ' ')"
new_match_count="$(wc -l < "$tmp/new.matches" | tr -d ' ')"
lost_match_count="$(wc -l < "$tmp/lost.matches" | tr -d ' ')"

{
  printf '# Evaluación YARA Forge Core %s\n\n' "$tag"
  printf -- '- Corpus desplegado: `%s` (%s reglas)\n' "$current_tag" "$current_count"
  printf -- '- Candidata: `%s` (%s reglas)\n' "$tag" "$candidate_count"
  printf -- '- Archivo verificado: `sha256:%s`\n' "$actual_sha"
  printf -- '- Reglas añadidas/eliminadas: %s / %s\n' "$added_count" "$removed_count"
  printf -- '- Rootfs A/B: %s\n' "$root_count"
  printf -- '- Matches actual/candidata: %s / %s\n' "$current_match_count" "$candidate_match_count"
  printf -- '- Matches nuevos/perdidos: %s / %s\n\n' "$new_match_count" "$lost_match_count"
  printf '## Positivos inertes\n\n```text\n'
  cat "$tmp/positive.log"
  printf '```\n\n## Primeras reglas añadidas\n\n```text\n'
  sed -n '1,50p' "$tmp/added.rules"
  printf '```\n\n## Primeras reglas eliminadas\n\n```text\n'
  sed -n '1,50p' "$tmp/removed.rules"
  printf '```\n\n## Matches nuevos\n\n```text\n'
  sed -n '1,100p' "$tmp/new.matches"
  printf '```\n\n## Matches perdidos\n\n```text\n'
  sed -n '1,100p' "$tmp/lost.matches"
  printf '```\n\n**Este informe no modifica `corpus.lock.json`, el compose ni el corpus desplegado.**\n'
} > "$REPORT"

docker exec "$CONTAINER" find /tmp -maxdepth 1 -name "firmlab-yara-core-candidate-$tag.yar" -delete
printf 'evaluación escrita en %s; no se desplegó nada\n' "$REPORT"
