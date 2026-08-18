#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES="${1:-}"
YARA_BIN="${YARA_BIN:-yara}"

if [ -z "$RULES" ]; then
  printf 'uso: scripts/test-yara-external.sh /ruta/yara-forge-core.yar\n' >&2
  exit 2
fi
command -v "$YARA_BIN" >/dev/null 2>&1 || {
  printf 'yara no está instalado; define YARA_BIN o ejecuta el test dentro de la imagen FirmLab\n' >&2
  exit 127
}

tmp="$(mktemp -d /tmp/firmlab-yara-external.XXXXXX)"
cleanup() {
  find "$tmp" -type f -delete 2>/dev/null || true
  rmdir "$tmp" 2>/dev/null || true
}
trap cleanup EXIT

# The standard EICAR test string is assembled from two pieces so antivirus products do not quarantine this source
# tree. The resulting temporary file is inert test data, not an executable.
printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-' 'ANTIVIRUS-TEST-FILE!$H+H*' > "$tmp/eicar.inert"

# A tiny text fixture for a public generic-webshell rule. It is never served or executed.
printf '%s\n' "<?php system(\$_POST['a']); ?>" > "$tmp/webshell.inert.php"

# An ELF-shaped but invalid, non-executable byte string carrying four published Mirai indicators. The leading
# magic exercises the rule's type guard without creating a runnable ELF program.
printf '\177ELF\n%s\n%s\n%s\n%s\n' 'SERVZUXO' '-loldongs' '/dev/null' '/bin/busybox' > "$tmp/mirai-shape.inert"

assert_match() {
  local rule="$1" file="$2" output
  output="$($YARA_BIN -w -e "$RULES" "$file")"
  if ! printf '%s\n' "$output" | awk -v wanted="$rule" '$1 == wanted || $1 == "default:" wanted { found=1 } END { exit(found ? 0 : 1) }'; then
    printf 'la regla externa esperada no disparó: %s -> %s\n%s\n' "$rule" "$file" "$output" >&2
    exit 1
  fi
  printf '%s\t%s\n' "$rule" "$(basename "$file")"
}

assert_match TRELLIX_ARC_Malw_Eicar "$tmp/eicar.inert"
assert_match SEKOIA_Generic_Php_Webshell "$tmp/webshell.inert.php"
assert_match SIGNATURE_BASE_MAL_Mirai_Nov19_1 "$tmp/mirai-shape.inert"
printf 'YARA external: 3 positivos inertes confirmados\n'
