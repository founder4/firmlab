#!/usr/bin/env bash
# A/B evaluation of one YARA Forge Core candidate against the release pinned in ops/yara/corpus.lock.json.
#
# It only ever produces a report: it never edits the lock, the compose or the deployed corpus. Two outcomes exist
# and must never look alike. Exit 0 with «Resultado: completo» is a comparison that ran against the lock-verified
# baseline over at least one real rootfs. Exit 3 with «Resultado: INCOMPLETO (<motivo>)» is a comparison that did
# not run — API unreachable, no rootfs, a baseline that is not the lock — and its zeros are not zeros. The report
# is overwritten at start, so a previous run's complete report can never be read as this run's.
set -Eeuo pipefail
export LC_ALL=C # sort, comm and join must agree on one collation

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="$ROOT/ops/yara/corpus.lock.json"
TAG="${1:-latest}"
# Written outside the repo by default: the report is a dated evaluation of ONE candidate, not a source file, and
# the previous default dropped it in the repo root where it sat untracked until someone noticed. A report worth
# keeping is archived deliberately under docs/ (see docs/YARA-CANDIDATE-20260830.md).
REPORT="${2:-${TMPDIR:-/tmp}/yara-candidate-report.md}"
CONTAINER="${FIRMLAB_CONTAINER:-firmlab}"
API_BASE="${FIRMLAB_API_BASE:-http://127.0.0.1:8899/api}"

for tool in curl jq unzip docker awk comm join; do
  command -v "$tool" >/dev/null 2>&1 || { printf 'falta la dependencia: %s\n' "$tool" >&2; exit 127; }
done

write_incomplete() {
  printf '# Evaluación YARA Forge Core %s — INCOMPLETA\n\n- Resultado: **INCOMPLETO** (`%s`)\n- Motivo: %s\n\n%s\n' \
    "$TAG" "$1" "$2" 'No se comparó nada: los recuentos ausentes no son cero diferencias ni cero matches.' > "$REPORT"
}
incomplete() {
  write_incomplete "$1" "$2"
  printf 'resultado: INCOMPLETO (%s): %s; informe en %s\n' "$1" "$2" "$REPORT" >&2
  exit 3
}
write_incomplete interrupted 'la evaluación no llegó a terminar; sólo un final completo sobrescribe este informe.'

tmp="$(mktemp -d "${TMPDIR:-/tmp}/firmlab-yara-candidate.XXXXXX")"
in_container=0
cleanup() {
  [ "$in_container" = 0 ] || docker exec "$CONTAINER" rm -f "$container_rule" "$container_base" >/dev/null 2>&1 || true
  find "$tmp" -type f -delete 2>/dev/null || true
  find "$tmp" -depth -type d -exec rmdir {} \; 2>/dev/null || true
}
trap cleanup EXIT

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | awk '{print $1}'
}
bytes() { wc -c < "$1" | tr -d ' '; }
lock() { jq -er "$1" "$LOCK"; }

# name<TAB>logic_hash per rule; «-» when a rule carries no logic_hash, so its logic is reported as not compared.
rule_table() {
  awk '
    function flush() { if (name != "") print name "\t" (hash == "" ? "-" : hash) }
    match($0, /^[[:space:]]*((private|global)[[:space:]]+)*rule[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/) {
      flush(); k = split(substr($0, RSTART, RLENGTH), f, /[[:space:]]+/); name = f[k]; hash = ""; next
    }
    name != "" && hash == "" && match($0, /logic_hash[[:space:]]*=[[:space:]]*"[^"]*"/) {
      hash = substr($0, RSTART, RLENGTH); sub(/^[^"]*"/, "", hash); sub(/"$/, "", hash)
    }
    END { flush() }
  ' "$1" | sort
}

# Baseline: the lock's own archive, verified byte for byte — never whatever sits in ~/homelab or /opt.
current_tag="$(lock .external.release)"
base_url="$(lock .external.archiveUrl)"
base_archive="$tmp/baseline.zip"
baseline="$tmp/yara-forge-core-$current_tag.yar"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 "$base_url" --output "$base_archive" ||
  incomplete baseline_download_failed "no se pudo descargar la baseline del lock: $base_url"
[ "$(sha256 "$base_archive")" = "$(lock .external.archiveSha256)" ] &&
  [ "$(bytes "$base_archive")" = "$(lock .external.archiveBytes)" ] ||
  incomplete baseline_lock_mismatch "el zip descargado no es el $current_tag del lock (sha256/bytes)"
unzip -p "$base_archive" "$(lock .external.archiveMember)" > "$baseline" ||
  incomplete baseline_lock_mismatch "el zip del lock no contiene $(lock .external.archiveMember)"
rule_table "$baseline" > "$tmp/current.tsv"
[ "$(sha256 "$baseline")" = "$(lock .external.ruleFileSha256)" ] &&
  [ "$(bytes "$baseline")" = "$(lock .external.ruleFileBytes)" ] &&
  [ "$(wc -l < "$tmp/current.tsv" | tr -d ' ')" = "$(lock .external.rulesDeclared)" ] ||
  incomplete baseline_lock_mismatch "el .yar de $current_tag no coincide con el lock (sha256/bytes/reglas)"

if [ "$TAG" = latest ]; then
  release_api='https://api.github.com/repos/YARAHQ/yara-forge/releases/latest'
else
  release_api="https://api.github.com/repos/YARAHQ/yara-forge/releases/tags/$TAG"
fi
headers=(-H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28')
if [ -n "${GITHUB_TOKEN:-}" ]; then headers+=(-H "Authorization: Bearer ${GITHUB_TOKEN}"); fi
release="$(curl --fail --silent --show-error --location "${headers[@]}" "$release_api")" ||
  incomplete github_api_unreachable "GET $release_api"
tag="$(printf '%s' "$release" | jq -er '.tag_name')"
asset="$(printf '%s' "$release" | jq -er '.assets[] | select(.name == "yara-forge-rules-core.zip")')" ||
  incomplete candidate_asset_missing "la release $tag no publica yara-forge-rules-core.zip"
url="$(printf '%s' "$asset" | jq -er '.browser_download_url')"
expected_sha="$(printf '%s' "$asset" | jq -er '.digest | sub("^sha256:"; "")')"

archive="$tmp/core.zip"
candidate="$tmp/yara-forge-core-$tag.yar"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 "$url" --output "$archive" ||
  incomplete candidate_download_failed "GET $url"
actual_sha="$(sha256 "$archive")"
[ "$actual_sha" = "$expected_sha" ] ||
  incomplete candidate_digest_mismatch "SHA-256 de la candidata $actual_sha != publicado $expected_sha"
unzip -p "$archive" packages/core/yara-rules-core.yar > "$candidate"
rule_table "$candidate" > "$tmp/candidate.tsv"

cut -f1 "$tmp/current.tsv" > "$tmp/current.rules"
cut -f1 "$tmp/candidate.tsv" > "$tmp/candidate.rules"
comm -13 "$tmp/current.rules" "$tmp/candidate.rules" > "$tmp/added.rules"
comm -23 "$tmp/current.rules" "$tmp/candidate.rules" > "$tmp/removed.rules"
join -t "$(printf '\t')" "$tmp/current.tsv" "$tmp/candidate.tsv" > "$tmp/common.tsv"
awk -F '\t' '$2 != "-" && $3 != "-" && $2 != $3 {print $1}' "$tmp/common.tsv" > "$tmp/changed.rules"
awk -F '\t' '$2 == "-" || $3 == "-" {print $1}' "$tmp/common.tsv" > "$tmp/unhashed.rules"
count() { wc -l < "$1" | tr -d ' '; }

container_rule="/tmp/firmlab-yara-core-candidate-$tag.yar"
container_base="/tmp/firmlab-yara-core-baseline-$current_tag.yar"
in_container=1
docker cp "$candidate" "$CONTAINER:$container_rule" >/dev/null
docker cp "$baseline" "$CONTAINER:$container_base" >/dev/null
docker exec "$CONTAINER" yara -w -e "$container_rule" /dev/null >/dev/null ||
  incomplete candidate_compile_failed "la candidata $tag no compila con el yara de $CONTAINER"

# Positive controls must continue to fire before a candidate is even compared with production rootfs.
docker cp "$ROOT/scripts/test-yara-external.sh" "$CONTAINER:/tmp/test-yara-external.sh" >/dev/null
docker exec "$CONTAINER" sh -lc "YARA_BIN=yara /tmp/test-yara-external.sh '$container_rule'" > "$tmp/positive.log" ||
  incomplete positive_controls_failed "la candidata $tag no dispara los positivos inertes de test-yara-external.sh"

# A failed request is not an empty corpus: `for x in $(curl …)` hid exactly that from `set -e`.
curl --fail --silent --show-error "$API_BASE/images" | jq -r '.images[].id' > "$tmp/images" ||
  incomplete api_unreachable "GET $API_BASE/images"
: > "$tmp/roots"
while IFS= read -r id; do
  root="$(curl --fail --silent --show-error "$API_BASE/images/$id/yarascan" | jq -r '.result.scan.root // empty')" ||
    incomplete api_unreachable "GET $API_BASE/images/$id/yarascan"
  [ -z "$root" ] || printf '%s\n' "$root" >> "$tmp/roots"
done < "$tmp/images"
sort -u "$tmp/roots" -o "$tmp/roots"
image_count="$(count "$tmp/images")"
root_count="$(count "$tmp/roots")"
[ "$root_count" -gt 0 ] ||
  incomplete no_rootfs "$image_count imágenes en $API_BASE y ninguna con un yarascan completado que nombre su rootfs"

scan() {
  docker exec "$CONTAINER" yara -w -e -r "$1" "$2" < /dev/null > "$tmp/scan.out" ||
    incomplete scan_failed "yara -r $1 sobre $2"
  ROOTFS="$2" awk '{print ENVIRON["ROOTFS"] "\t" $0}' "$tmp/scan.out" >> "$3"
}
: > "$tmp/current.matches"
: > "$tmp/candidate.matches"
while IFS= read -r root; do
  scan "$container_base" "$root" "$tmp/current.matches"
  scan "$container_rule" "$root" "$tmp/candidate.matches"
done < "$tmp/roots"
sort -u "$tmp/current.matches" -o "$tmp/current.matches"
sort -u "$tmp/candidate.matches" -o "$tmp/candidate.matches"
comm -13 "$tmp/current.matches" "$tmp/candidate.matches" > "$tmp/new.matches"
comm -23 "$tmp/current.matches" "$tmp/candidate.matches" > "$tmp/lost.matches"

{
  printf '# Evaluación YARA Forge Core %s\n\n' "$tag"
  printf -- '- Resultado: completo\n'
  printf -- '- Baseline: `%s` del lock (%s reglas; zip y `.yar` verificados contra `corpus.lock.json`)\n' \
    "$current_tag" "$(count "$tmp/current.rules")"
  printf -- '- Candidata: `%s` (%s reglas)\n' "$tag" "$(count "$tmp/candidate.rules")"
  printf -- '- Archivo verificado: `sha256:%s`\n' "$actual_sha"
  printf -- '- Reglas añadidas/eliminadas/lógica cambiada: %s / %s / %s\n' \
    "$(count "$tmp/added.rules")" "$(count "$tmp/removed.rules")" "$(count "$tmp/changed.rules")"
  printf -- '- Reglas comunes sin `logic_hash` (lógica no comparada): %s\n' "$(count "$tmp/unhashed.rules")"
  printf -- '- Imágenes / rootfs A/B: %s / %s (una imagen sin yarascan completado no está cubierta)\n' \
    "$image_count" "$root_count"
  printf -- '- Matches actual/candidata: %s / %s\n' "$(count "$tmp/current.matches")" "$(count "$tmp/candidate.matches")"
  printf -- '- Matches nuevos/perdidos: %s / %s\n\n' "$(count "$tmp/new.matches")" "$(count "$tmp/lost.matches")"
  printf '## Positivos inertes\n\n```text\n'
  cat "$tmp/positive.log"
  printf '```\n\n## Primeras reglas añadidas\n\n```text\n'
  sed -n '1,50p' "$tmp/added.rules"
  printf '```\n\n## Primeras reglas eliminadas\n\n```text\n'
  sed -n '1,50p' "$tmp/removed.rules"
  printf '```\n\n## Primeras reglas con lógica cambiada\n\n```text\n'
  sed -n '1,50p' "$tmp/changed.rules"
  printf '```\n\n## Matches nuevos\n\n```text\n'
  sed -n '1,100p' "$tmp/new.matches"
  printf '```\n\n## Matches perdidos\n\n```text\n'
  sed -n '1,100p' "$tmp/lost.matches"
  printf '```\n\n**Este informe no modifica `corpus.lock.json`, el compose ni el corpus desplegado.**\n'
} > "$REPORT"

printf 'evaluación completa escrita en %s; no se desplegó nada\n' "$REPORT"
