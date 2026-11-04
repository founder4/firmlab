# FreeRTOS task-walk fixture — provenance

`freertos-stm32f4.elf` is a synthetic firmware built for FirmLab, not a vendor or corpus image. Its task set is
known by construction (`main.c`), so the RTOS lane (ELF symbols → Renode RAM capture → task-list walk) can be
checked against an expected answer: `apps/api/scripts/rtos-freertos-e2e.mjs`.

| Item | Value |
|---|---|
| Kernel | FreeRTOS-Kernel tag `V11.1.0`, commit `dbf70559b27d39c1fdb68dfb9a32140b6a6777a0` (MIT), fetched by `build.sh` from `github.com/FreeRTOS/FreeRTOS-Kernel` |
| Kernel files linked | `tasks.c`, `list.c`, `queue.c`, `event_groups.c`, `portable/GCC/ARM_CM3/port.c` (16/32-bit) or `ARM_CM4F/port.c` (64-bit), `portable/MemMang/heap_4.c` — not vendored |
| Toolchain | Debian bookworm `gcc-arm-none-eabi` `15:12.2.rel1-1` (arm-none-eabi-gcc 12.2.1 20221205), disposable container |
| Flags | `-mcpu=cortex-m3 -mthumb -O1 -g -ffreestanding -nostdlib`, linked at flash `0x08000000`, RAM `0x20000000` |
| Result | `freertos-stm32f4.elf`, sha256 `1dab3a289d49db6a84e1b52456396022d1607961e8fa717d88b830cc59a9d915`, 106 484 bytes (symbols kept) |
| Built | 2026-11-04, by the FirmLab coordinator; `build-info.txt` is the build's own record |

Network was used only to fetch the toolchain package and the pinned kernel tag. Rebuilding with a different
toolchain will change the hash; the e2e check, not the hash, is what establishes the fixture still means what it says.

Expected state after the scheduler has run (any capture window of 1 s or more on Renode's `stm32f4.repl`):
`pxReadyTasksLists[1]` = SpinA, SpinB (one of them `pxCurrentTCB`); `[0]` = IDLE; a delayed list = Sleeper (prio 2);
`xSuspendedTaskList` = Parked (prio 3), QueueRx (prio 4), QueueTx (prio 2) and EventWait (prio 3). QueueRx's distinct `xEventListItem`
is on an empty static queue's ordered `xTasksWaitingToReceive` with key 1; QueueTx's is on a separate full static
queue's ordered `xTasksWaitingToSend` with key 3. EventWait's item is on an unordered Event Group
`xTasksWaitingForBits` list and encodes bits 0+2, wait-all and clear-on-exit in the TickType_t-relative control byte.
`INCLUDE_vTaskDelete` is 0, so `xTasksWaitingTermination` is not
compiled in and the walk honestly reports `partial` coverage for that lane.

Validated 2026-11-04 in `firmlab-firmware` (`--network none`) across the full 12-layout matrix: all checks pass,
including both queue wait directions, the Event Group wait semantics, their independently exported `List_t`
addresses and their TCB event nodes.
Renode refused the platform's remote SVD (`STM32F40x.svd.gz`) and ran without it. A deliberately wrong
`sizeof(List_t)` (24) is refused by the snapshot contract. This is emulation of a synthetic build: it says nothing
about a physical device, another FreeRTOS version/configuration, or any corpus image.

`build.sh` also supports `MATRIX=1 OUTPUT_DIR=<temporary-directory>`. The matrix compiles all twelve combinations of
16/32/64-bit `TickType_t`, `configUSE_MINI_LIST_ITEM` and `configUSE_LIST_DATA_INTEGRITY_CHECK_BYTES` without replacing
the tracked fixture;
`apps/api/scripts/rtos-freertos-layout-matrix.sh` feeds each ELF to the product with the matching explicit layout and
runs the full symbol → offline Renode capture → task-list walk check. Generated matrix ELF files are never committed.
The 64-bit variants use the official ARM_CM4F port. Application and kernel objects remain soft-float while only
`port.c` is softfp, because compiling initialization code with softfp executes FPU instructions before the port
enables the FPU and produces a Renode `NOCP` fault. V11.1.0 `heap_4.c` emits a visible `portMAX_DELAY`→`size_t`
conversion warning in Tick64; its heap-stats function is not called by this fixture.
