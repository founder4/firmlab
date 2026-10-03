# FreeRTOS task-walk fixture — provenance

`freertos-stm32f4.elf` is a synthetic firmware built for FirmLab, not a vendor or corpus image. Its task set is
known by construction (`main.c`), so the RTOS lane (ELF symbols → Renode RAM capture → task-list walk) can be
checked against an expected answer: `apps/api/scripts/rtos-freertos-e2e.mjs`.

| Item | Value |
|---|---|
| Kernel | FreeRTOS-Kernel tag `V11.1.0`, commit `dbf70559b27d39c1fdb68dfb9a32140b6a6777a0` (MIT), fetched by `build.sh` from `github.com/FreeRTOS/FreeRTOS-Kernel` |
| Kernel files linked | `tasks.c`, `list.c`, `queue.c`, `portable/GCC/ARM_CM3/port.c`, `portable/MemMang/heap_4.c` — not vendored |
| Toolchain | Debian bookworm `gcc-arm-none-eabi` `15:12.2.rel1-1` (arm-none-eabi-gcc 12.2.1 20221205), disposable container |
| Flags | `-mcpu=cortex-m3 -mthumb -O1 -g -ffreestanding -nostdlib`, linked at flash `0x08000000`, RAM `0x20000000` |
| Result | `freertos-stm32f4.elf`, sha256 `912231e23bd7672369ed85a6eebd7443a60161fe032f5b532bba80adcc45ff84`, 65 140 bytes (symbols kept) |
| Built | 2026-10-03, by the FirmLab coordinator; `build-info.txt` is the build's own record |

Network was used only to fetch the toolchain package and the pinned kernel tag. Rebuilding with a different
toolchain will change the hash; the e2e check, not the hash, is what establishes the fixture still means what it says.

Expected state after the scheduler has run (any capture window of 1 s or more on Renode's `stm32f4.repl`):
`pxReadyTasksLists[1]` = SpinA, SpinB (one of them `pxCurrentTCB`); `[0]` = IDLE; a delayed list = Sleeper (prio 2);
`xSuspendedTaskList` = Parked (prio 3). `INCLUDE_vTaskDelete` is 0, so `xTasksWaitingTermination` is not compiled in
and the walk honestly reports `partial` coverage for that lane.

Validated 2026-10-03 in `firmlab-firmware` (`--network none`) at 1, 3 and 7 s: all checks pass; Renode refused the
platform's remote SVD (`STM32F40x.svd.gz`) and ran without it. A deliberately wrong `sizeof(List_t)` (24) is refused
by the snapshot contract. This is emulation of a synthetic build: it says nothing about a physical device, another
FreeRTOS version/configuration, or any corpus image.
