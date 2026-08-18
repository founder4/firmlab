#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="$ROOT/ops/yara/corpus.lock.json"
LOCAL_RULES="$ROOT/ops/yara/operator-firmware-policy.yar"
DEST="${1:-}"

if [ -z "$DEST" ]; then
  printf 'uso: scripts/sync-yara-corpus.sh /ruta/absoluta/yara-rules\n' >&2
  exit 2
fi
case "$DEST" in
  /*) ;;
  *) printf 'el destino debe ser absoluto: %s\n' "$DEST" >&2; exit 2 ;;
esac

for tool in curl node unzip; do
  command -v "$tool" >/dev/null 2>&1 || { printf 'falta la dependencia: %s\n' "$tool" >&2; exit 127; }
done

json() {
  node -e 'const x=require(process.argv[1]); let v=x; for(const k of process.argv[2].split(".")) v=v[k]; process.stdout.write(String(v))' "$LOCK" "$1"
}

URL="$(json external.archiveUrl)"
ARCHIVE_SHA="$(json external.archiveSha256)"
ARCHIVE_BYTES="$(json external.archiveBytes)"
MEMBER="$(json external.archiveMember)"
RULE_SHA="$(json external.ruleFileSha256)"
RULE_BYTES="$(json external.ruleFileBytes)"
RULE_COUNT="$(json external.rulesDeclared)"
TOTAL_COUNT="$(json totals.rulesDeclared)"
LOCAL_SHA="$(json local.sha256)"

parent="$(dirname "$DEST")"
base="$(basename "$DEST")"
mkdir -p "$parent"
stage="$(mktemp -d "$parent/.${base}.staging.XXXXXX")"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/external" "$stage/local"

archive="$stage/yara-forge-core.zip"
curl --fail --location --proto '=https' --tlsv1.2 "$URL" --output "$archive"

actual_archive_bytes="$(wc -c < "$archive" | tr -d ' ')"
[ "$actual_archive_bytes" = "$ARCHIVE_BYTES" ] || {
  printf 'tamaño inesperado del archivo: esperado %s, obtenido %s\n' "$ARCHIVE_BYTES" "$actual_archive_bytes" >&2
  exit 1
}

if command -v sha256sum >/dev/null 2>&1; then
  actual_archive_sha="$(sha256sum "$archive" | awk '{print $1}')"
else
  actual_archive_sha="$(shasum -a 256 "$archive" | awk '{print $1}')"
fi
[ "$actual_archive_sha" = "$ARCHIVE_SHA" ] || {
  printf 'SHA-256 inesperado del archivo: esperado %s, obtenido %s\n' "$ARCHIVE_SHA" "$actual_archive_sha" >&2
  exit 1
}

external="$stage/external/yara-forge-core.yar"
unzip -p "$archive" "$MEMBER" > "$external"
rm "$archive"

if command -v sha256sum >/dev/null 2>&1; then
  actual_rule_sha="$(sha256sum "$external" | awk '{print $1}')"
else
  actual_rule_sha="$(shasum -a 256 "$external" | awk '{print $1}')"
fi
actual_rule_bytes="$(wc -c < "$external" | tr -d ' ')"
actual_rule_count="$(grep -Ec '^(private |global )?rule[[:space:]]+' "$external")"
[ "$actual_rule_sha" = "$RULE_SHA" ] && [ "$actual_rule_bytes" = "$RULE_BYTES" ] && [ "$actual_rule_count" = "$RULE_COUNT" ] || {
  printf 'el miembro extraído no coincide con el lock (sha=%s bytes=%s rules=%s)\n' \
    "$actual_rule_sha" "$actual_rule_bytes" "$actual_rule_count" >&2
  exit 1
}

cp "$LOCAL_RULES" "$stage/local/operator-firmware-policy.yar"
cp "$LOCK" "$stage/corpus.lock.json"
cp "$ROOT/ops/yara/README.md" "$stage/README.md"

if command -v sha256sum >/dev/null 2>&1; then
  actual_local_sha="$(sha256sum "$stage/local/operator-firmware-policy.yar" | awk '{print $1}')"
else
  actual_local_sha="$(shasum -a 256 "$stage/local/operator-firmware-policy.yar" | awk '{print $1}')"
fi
[ "$actual_local_sha" = "$LOCAL_SHA" ] || {
  printf 'las reglas locales no coinciden con el lock: esperado %s, obtenido %s\n' "$LOCAL_SHA" "$actual_local_sha" >&2
  exit 1
}

if command -v yara >/dev/null 2>&1; then
  probe="$stage/empty.probe"
  : > "$probe"
  yara -w -e "$external" "$probe" >/dev/null
  yara -w -e "$stage/local/operator-firmware-policy.yar" "$probe" >/dev/null
  rm "$probe"
else
  printf 'aviso: yara no está en este host; hashes y recuentos validados, compilación pendiente en el contenedor\n' >&2
fi

backup=""
if [ -e "$DEST" ]; then
  backup="${DEST}.previous.$(date -u +%Y%m%dT%H%M%SZ)"
  mv "$DEST" "$backup"
fi
mv "$stage" "$DEST"
trap - EXIT

printf 'corpus instalado: %s reglas (%s externas + %s locales) en %s\n' \
  "$TOTAL_COUNT" "$RULE_COUNT" "$((TOTAL_COUNT - RULE_COUNT))" "$DEST"
[ -z "$backup" ] || printf 'copia anterior conservada: %s\n' "$backup"
