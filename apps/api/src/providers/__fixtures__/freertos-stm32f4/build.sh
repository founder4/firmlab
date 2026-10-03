#!/usr/bin/env bash
# Rebuilds freertos-stm32f4.elf in a disposable Debian container. Network is used ONLY to fetch the pinned
# toolchain package and the pinned FreeRTOS-Kernel tag; PROVENANCE.md records what was fetched and the result hash.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
KERNEL_TAG="${KERNEL_TAG:-V11.1.0}"
docker run --rm -v "$here:/fx" -w /tmp debian:bookworm bash -euo pipefail -c "
  apt-get update -qq && apt-get install -y -qq --no-install-recommends gcc-arm-none-eabi libnewlib-arm-none-eabi git ca-certificates >/dev/null
  git -c advice.detachedHead=false clone -q --depth 1 --branch $KERNEL_TAG https://github.com/FreeRTOS/FreeRTOS-Kernel.git k
  K=/tmp/k
  arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -O1 -g -ffreestanding -fno-common -nostdlib -Wall \
    -I/fx -I\$K/include -I\$K/portable/GCC/ARM_CM3 \
    /fx/startup.c /fx/main.c \$K/tasks.c \$K/list.c \$K/queue.c \$K/portable/GCC/ARM_CM3/port.c \$K/portable/MemMang/heap_4.c \
    -T /fx/link.ld -Wl,--gc-sections -lgcc -o /fx/freertos-stm32f4.elf
  {
    echo \"kernel_tag=$KERNEL_TAG\"
    echo \"kernel_commit=\$(git -C \$K rev-parse HEAD)\"
    echo \"toolchain=\$(arm-none-eabi-gcc --version | head -1)\"
    echo \"toolchain_package=\$(dpkg-query -W -f='\${Version}' gcc-arm-none-eabi)\"
    echo \"elf_sha256=\$(sha256sum /fx/freertos-stm32f4.elf | cut -d' ' -f1)\"
  } > /fx/build-info.txt
  cat /fx/build-info.txt
"
