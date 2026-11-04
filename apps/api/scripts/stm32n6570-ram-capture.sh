#!/usr/bin/env bash
# Pauses an explicitly connected STM32N6570-DK, captures one operator-declared RAM range, then resumes it.
# No reset, flash write, network listener, target guess or output overwrite is permitted.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: stm32n6570-ram-capture.sh --target CFG --base 0xADDR --size BYTES --output FILE [options]

Options:
  --openocd PATH      ST OpenOCD executable (default: openocd)
  --interface CFG     Debug adapter config (default: interface/stlink.cfg)
  --dry-run           Validate and print the invocation without requiring hardware
EOF
}

openocd_bin=openocd
interface_cfg=interface/stlink.cfg
target_cfg=
ram_base=
ram_size=
output_path=
dry_run=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --openocd) openocd_bin="${2:-}"; shift 2 ;;
    --interface) interface_cfg="${2:-}"; shift 2 ;;
    --target) target_cfg="${2:-}"; shift 2 ;;
    --base) ram_base="${2:-}"; shift 2 ;;
    --size) ram_size="${2:-}"; shift 2 ;;
    --output) output_path="${2:-}"; shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ -z "$target_cfg" ] || [ -z "$ram_base" ] || [ -z "$ram_size" ] || [ -z "$output_path" ]; then
  echo 'Target config, base, size and output are all required; FirmLab will not guess an STM32N6 RAM range.' >&2
  exit 2
fi
if [ ! -f "$target_cfg" ]; then
  echo "Target config is not a readable file: $target_cfg" >&2
  exit 2
fi
if [[ ! "$ram_base" =~ ^0x[0-9a-fA-F]+$ ]]; then
  echo 'RAM base must be a hexadecimal address such as 0x34180000.' >&2
  exit 2
fi
if [[ ! "$ram_size" =~ ^(0x[0-9a-fA-F]+|[1-9][0-9]*)$ ]]; then
  echo 'RAM size must be a positive decimal or hexadecimal byte count.' >&2
  exit 2
fi
if [[ "$output_path" == *$'\n'* || "$output_path" == *$'\r'* || "$output_path" == *'{'* || "$output_path" == *'}'* || "$output_path" == *';'* ]]; then
  echo 'Output path contains characters that cannot be represented safely in an OpenOCD command.' >&2
  exit 2
fi
if [ -e "$output_path" ]; then
  echo "Refusing to overwrite existing output: $output_path" >&2
  exit 2
fi
output_parent=$(dirname "$output_path")
if [ ! -d "$output_parent" ]; then
  echo "Output directory does not exist: $output_parent" >&2
  exit 2
fi

listener_policy='gdb port disabled; tcl port disabled; telnet port disabled'
if [ "$dry_run" = 1 ]; then
  printf 'DRY RUN:'
  printf ' %q' "$openocd_bin" -c "$listener_policy" -f "$interface_cfg" -c 'transport select swd' -f "$target_cfg"
  printf ' -c %q\n' "init; halt; dump_image {<temporary>/ram.bin} $ram_base $ram_size; resume; shutdown"
  exit 0
fi

if ! command -v "$openocd_bin" >/dev/null 2>&1; then
  echo "OpenOCD executable not found: $openocd_bin" >&2
  exit 3
fi
if ! command -v lsusb >/dev/null 2>&1 || ! lsusb | grep -Eqi '0483:(3748|374b|374d|374e|3752|3753|3754)'; then
  echo 'No supported ST-LINK USB device is present; no capture was attempted.' >&2
  exit 4
fi

capture_tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/firmlab-stm32n6.XXXXXX")
cleanup() {
  if [ -n "${capture_tmp_dir:-}" ] && [ -d "$capture_tmp_dir" ]; then
    rm -f -- "$capture_tmp_dir/ram.bin"
    rmdir -- "$capture_tmp_dir"
  fi
}
trap cleanup EXIT
temporary_capture="$capture_tmp_dir/ram.bin"

"$openocd_bin" \
  -c "$listener_policy" \
  -f "$interface_cfg" \
  -c 'transport select swd' \
  -f "$target_cfg" \
  -c "init; halt; dump_image {$temporary_capture} $ram_base $ram_size; resume; shutdown"

expected_size=$((ram_size))
actual_size=$(stat -c '%s' "$temporary_capture")
if [ "$actual_size" -ne "$expected_size" ]; then
  echo "Capture size mismatch: expected $expected_size bytes, got $actual_size; output was not installed." >&2
  exit 5
fi
mv -- "$temporary_capture" "$output_path"
trap - EXIT
rmdir -- "$capture_tmp_dir"
printf 'Captured %s bytes from %s to %s\n' "$actual_size" "$ram_base" "$output_path"
sha256sum "$output_path"
