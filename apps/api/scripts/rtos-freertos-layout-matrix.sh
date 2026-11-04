#!/usr/bin/env bash
# Builds and exercises every 16/32/64-bit layout supported by the ARM_CM3/ARM_CM4F fixture. Artifacts are temporary;
# Renode is network-isolated and each invocation declares the exact FreeRTOS configuration flags.
set -euo pipefail
repo="$(cd "$(dirname "$0")/../../.." && pwd)"
fixture="$repo/apps/api/src/providers/__fixtures__/freertos-stm32f4"
matrix_dir="$(mktemp -d)"
trap 'rm -rf "$matrix_dir"' EXIT

OUTPUT_DIR="$matrix_dir" MATRIX=1 "$fixture/build.sh"

for tick_width in 16 32 64; do
  for mini in 0 1; do
    for integrity in 0 1; do
      name="freertos-stm32f4-tick${tick_width}-mini${mini}-integrity${integrity}"
      echo "== $name =="
      docker run --rm --network none \
        -v "$repo:/w" -v "$matrix_dir:/matrix:ro" -w /w \
        -e FREERTOS_ELF="/matrix/$name.elf" \
        -e TICK_WIDTH="$tick_width" \
        -e USE_MINI_LIST_ITEM="$mini" \
        -e USE_LIST_DATA_INTEGRITY_CHECK_BYTES="$integrity" \
        firmlab-firmware:latest node apps/api/scripts/rtos-freertos-e2e.mjs
    done
  done
done
