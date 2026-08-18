#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES="${1:-$ROOT/ops/yara/operator-firmware-policy.yar}"
CASES="$ROOT/ops/yara/tests"
YARA_BIN="${YARA_BIN:-yara}"

command -v "$YARA_BIN" >/dev/null 2>&1 || {
  printf 'yara no está instalado; define YARA_BIN o ejecuta el test dentro de la imagen FirmLab\n' >&2
  exit 127
}

positive="$($YARA_BIN -w -e -r "$RULES" "$CASES/positive")"
negative="$($YARA_BIN -w -e -r "$RULES" "$CASES/negative")"

while IFS=$'\t' read -r rule relative; do
  [ -n "$rule" ] || continue
  if ! printf '%s\n' "$positive" | awk -v wanted_rule="$rule" -v wanted_path="$relative" '
    ($1 == wanted_rule || $1 == "default:" wanted_rule) && index($0, wanted_path) > 0 { found = 1 }
    END { exit(found ? 0 : 1) }
  '; then
    printf 'falta el match esperado: %s -> %s\n' "$rule" "$relative" >&2
    printf '%s\n' "$positive" >&2
    exit 1
  fi
done < "$CASES/expected.tsv"

if [ -n "$negative" ]; then
  printf 'un fixture negativo produjo matches inesperados:\n%s\n' "$negative" >&2
  exit 1
fi

expected="$(wc -l < "$CASES/expected.tsv" | tr -d ' ')"
actual="$(printf '%s\n' "$positive" | sed '/^$/d' | wc -l | tr -d ' ')"
[ "$actual" -eq "$expected" ] || {
  printf 'se esperaban %s matches positivos exactos y se obtuvieron %s:\n%s\n' "$expected" "$actual" "$positive" >&2
  exit 1
}

printf 'YARA policy: %s positivos exactos y 3 negativos limpios\n' "$actual"
