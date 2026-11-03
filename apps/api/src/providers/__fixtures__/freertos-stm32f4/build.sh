#!/usr/bin/env bash
# Rebuilds the default fixture or all four supported list-layout variants in a disposable Debian container.
# Network is used ONLY to fetch the pinned toolchain package and FreeRTOS-Kernel tag. Matrix outputs should point
# OUTPUT_DIR at a temporary directory; only the historical default build writes into the fixture directory.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
KERNEL_TAG="${KERNEL_TAG:-V11.1.0}"
OUTPUT_DIR="${OUTPUT_DIR:-$here}"
MATRIX="${MATRIX:-0}"
USE_MINI_LIST_ITEM="${USE_MINI_LIST_ITEM:-1}"
USE_LIST_DATA_INTEGRITY_CHECK_BYTES="${USE_LIST_DATA_INTEGRITY_CHECK_BYTES:-0}"
mkdir -p "$OUTPUT_DIR"
docker run --rm -v "$here:/fx:ro" -v "$OUTPUT_DIR:/out" -w /tmp \
  -e KERNEL_TAG="$KERNEL_TAG" -e MATRIX="$MATRIX" -e USE_MINI_LIST_ITEM="$USE_MINI_LIST_ITEM" \
  -e USE_LIST_DATA_INTEGRITY_CHECK_BYTES="$USE_LIST_DATA_INTEGRITY_CHECK_BYTES" \
  debian:bookworm bash -euo pipefail -c '
  apt-get update -qq && apt-get install -y -qq --no-install-recommends gcc-arm-none-eabi libnewlib-arm-none-eabi git ca-certificates >/dev/null
  git -c advice.detachedHead=false clone -q --depth 1 --branch "$KERNEL_TAG" https://github.com/FreeRTOS/FreeRTOS-Kernel.git k
  K=/tmp/k
  build_variant() {
    name="$1"
    mini="$2"
    integrity="$3"
    arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -O1 -g -ffreestanding -fno-common -nostdlib -Wall \
      -DconfigUSE_MINI_LIST_ITEM="$mini" -DconfigUSE_LIST_DATA_INTEGRITY_CHECK_BYTES="$integrity" \
      -I/fx -I"$K/include" -I"$K/portable/GCC/ARM_CM3" \
      /fx/startup.c /fx/main.c "$K/tasks.c" "$K/list.c" "$K/queue.c" "$K/portable/GCC/ARM_CM3/port.c" "$K/portable/MemMang/heap_4.c" \
      -T /fx/link.ld -Wl,--gc-sections -lgcc -o "/out/$name.elf"
    info="/out/$name.build-info.txt"
    {
      echo "kernel_tag=$KERNEL_TAG"
      echo "kernel_commit=$(git -C "$K" rev-parse HEAD)"
      echo "toolchain=$(arm-none-eabi-gcc --version | head -1)"
      echo "toolchain_package=$(dpkg-query -W -f=\${Version} gcc-arm-none-eabi)"
      echo "configUSE_MINI_LIST_ITEM=$mini"
      echo "configUSE_LIST_DATA_INTEGRITY_CHECK_BYTES=$integrity"
      echo "elf_sha256=$(sha256sum "/out/$name.elf" | cut -d" " -f1)"
    } > "$info"
    cat "$info"
  }
  if [ "$MATRIX" = 1 ]; then
    for mini in 0 1; do
      for integrity in 0 1; do
        build_variant "freertos-stm32f4-mini${mini}-integrity${integrity}" "$mini" "$integrity"
      done
    done
  else
    build_variant freertos-stm32f4 "$USE_MINI_LIST_ITEM" "$USE_LIST_DATA_INTEGRITY_CHECK_BYTES"
    mv /out/freertos-stm32f4.build-info.txt /out/build-info.txt
  fi
'
