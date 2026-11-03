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

# YARA Forge 20261101 dropped TRELLIX_ARC_Malw_Eicar (plain EICAR) by selection, not logic. This targets
# ELCEEF_EICAR_Encrypted_ZIP, whose logic is identical in 20261011 and 20261103: a bare 30-byte ZIP local header
# (encrypted flag bit 0, CRC-32 0x6851cf3c at +14, uncompressed size 68 at +22) that DESCRIBES an encrypted EICAR
# entry but carries no data, so not even the EICAR string is ever written.
printf '\120\113\003\004\000\000\001\000\000\000\000\000\000\000\074\317\121\150\000\000\000\000\104\000\000\000\000\000\000\000' \
  > "$tmp/eicar-encrypted-zip-header.inert"

# A tiny text fixture for a public generic-webshell rule. It is never served or executed.
printf '%s\n' "<?php system(\$_POST['a']); ?>" > "$tmp/webshell.inert.php"

# An ELF-shaped but invalid, non-executable byte string carrying four function names from the published Mirai source
# (attack.c / resolv.c). The leading magic exercises the rule's type guard without creating a runnable ELF program.
# It targets SIGNATURE_BASE_MAL_ARM_LNX_Mirai_Mar13_2022 because YARA Forge 20260927 dropped the previous control,
# SIGNATURE_BASE_MAL_Mirai_Nov19_1; this rule's logic is identical in 20260816 and 20260927, so the control does not
# depend on which of the two is deployed.
printf '\177ELF\n%s\n%s\n%s\n%s\n' 'anti_gdb_entry' 'resolve_cnc_addr' 'attack_gre_eth' 'attack_udp_generic' \
  > "$tmp/mirai-shape.inert"

assert_match() {
  local rule="$1" file="$2" output
  output="$($YARA_BIN -w -e "$RULES" "$file")"
  if ! printf '%s\n' "$output" | awk -v wanted="$rule" '$1 == wanted || $1 == "default:" wanted { found=1 } END { exit(found ? 0 : 1) }'; then
    printf 'la regla externa esperada no disparó: %s -> %s\n%s\n' "$rule" "$file" "$output" >&2
    exit 1
  fi
  printf '%s\t%s\n' "$rule" "$(basename "$file")"
}

assert_match ELCEEF_EICAR_Encrypted_ZIP "$tmp/eicar-encrypted-zip-header.inert"
assert_match SEKOIA_Generic_Php_Webshell "$tmp/webshell.inert.php"
assert_match SIGNATURE_BASE_MAL_ARM_LNX_Mirai_Mar13_2022 "$tmp/mirai-shape.inert"
printf 'YARA external: 3 positivos inertes confirmados\n'
