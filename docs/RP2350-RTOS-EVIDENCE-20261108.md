# RP2350 RTOS evidence retention and instance boundaries — 2026-11-08

Task `task_c1d93269a7e6`, dispatch `ctx_3d5f9d4ac5eb`, Run `run_4723fc97d2d6`.
The editing worktree started clean at `6f35be5af6bb9daa31a84c3cdb3410a7dc8cf8e2`, on
`founder4/campaign-rtos-evidence-20261108`, separate from the original main checkout.
The independent review's defects 2 and 5 were verified against that source, rather than assumed correct.

## Verified defects and changes

- `runRtosAnalysis` computed PICOBIN images, RISC-V disassembly and the runtime plan before branching, then
  omitted all three fields from the Cortex-M return. Both returns now attach the same optional evidence and
  disassembly status text. A universal image retains both Arm and RISC-V declarations even when offset zero
  has plausible Cortex-M vectors. Vector detection, marker coverage, findings and proof rules are unchanged.
- `selectPicobinDisassemblyTarget` treated `undefined !== null` as load-map evidence. Selection now prefers a
  nonempty load map, then a non-nullish rolling delta (including zero), then the previous candidate/fallback
  ordering. This selects evidence; the downstream mapping validator still decides whether it is usable.
- UART and timer ranges merged adjacent hardware instances. The required model names remain `uart` and
  `timer`, but each instance has a separate range, and a complete access must fit one range.
- Empty/whitespace-only boot-ROM or platform-description declarations leave the runtime plan blocked.
  Nonblank strings remain declarations, not proof that a file exists or that any runtime has executed.

All `RtosResult` PICOBIN fields remain optional forever. A typed legacy result without those fields and a typed
`PicobinInfo` without `loadMap` are covered. No finding severity, proof state or marker coverage was upgraded.

## Primary address-map evidence

Checked Raspberry Pi's [Pico SDK 2.2.0 RP2350 address map](https://github.com/raspberrypi/pico-sdk/blob/2.2.0/src/rp2350/hardware_regs/include/hardware/regs/addressmap.h),
specifically lines 54–64. Its UART0/UART1/SPI0 and TIMER0/TIMER1/HSTX_CTRL bases establish these adjacent slots:

| Instance | Start | End exclusive | Required model |
| --- | --- | --- | --- |
| UART0 | `0x40070000` | `0x40078000` | `uart` |
| UART1 | `0x40078000` | `0x40080000` | `uart` |
| TIMER0 | `0x400b0000` | `0x400b8000` | `timer` |
| TIMER1 | `0x400b8000` | `0x400c0000` | `timer` |

The policy checks slot containment. It does not validate individual register offsets or require natural
alignment, and a model name alone does not prove fidelity of that model.

## Validation

Executed locally in the editing worktree:

```sh
pnpm install --frozen-lockfile --offline
pnpm --filter @firmlab/api check
pnpm --filter @firmlab/api build
pnpm --filter @firmlab/api run test rtos.test.ts picobin
pnpm biome
```

Core was built before API consumption. API typecheck/build passed, all 90 focused tests across five files passed,
and repository Biome plus source audits passed with zero errors/warnings. Before production fixes, the added
regressions failed on the Cortex-M omission, legacy/empty-map selection, instance ranges and whitespace paths
(10 failures). Host tests allow either a successful real decoder or explicit unavailability, without mocking
the provider; the following container check requires real decoder success.

### Actual built provider, offline synthetic inputs

Used the existing immutable image ID
`sha256:758b44ca5e1487da3f34bd96ec1d84558354cc837f69da0fafb54e6c21f82b42`, with local
`apps/api/dist` and `packages/core/dist` mounted read-only over `/app/apps/api/dist` and
`/app/packages/core/dist`. The disposable container ran with `--rm --network none`, no published ports, no data
mount and `--entrypoint node --input-type=module`. It reported Node `v22.23.4` and radare2
`6.2.4 +1 abi:152 @ linux-arm_64`.

Synthetic fixture construction for reproduction (96 bytes, no corpus payload):

```js
const bytes = Buffer.alloc(0x60);
// Repeat once without these vectors, then once with them:
bytes.writeUInt32LE(0x20082000, 0);
bytes.writeUInt32LE(0x10000055, 4);
for (const [offset, value] of [
  [0x10, 0xffffded3], [0x14, 0x10010142], [0x18, 0x1ff],
  [0x1c, 0x20], [0x20, 0xab123579],
  [0x30, 0xffffded3], [0x34, 0x11010142], [0x38, 0x344],
  [0x3c, 0x10000054], [0x40, 0x20082000], [0x44, 0x4ff],
  [0x48, 0xffffffe0], [0x4c, 0xab123579], [0x54, 0x8067],
]) bytes.writeUInt32LE(value, offset);
```

The script wrote each fixture into a container temporary directory and directly called built
`/app/apps/api/dist/providers/rtos.js`'s `runRtosAnalysis`. Both variants passed assertions for:

- Correct `isCortexM`, Arm/RISC-V `picobinImages`, `picobinDisassembly.available: true`, entry `0x10000054`,
  a decoded `ret`, and a blocked runtime plan with `blocked_by_platform`.
- Exactly two structural `rtos-picobin` findings (`static_confirmed`) and one entry CFG finding
  (`static_confirmed`). The Cortex-M variant additionally retained the static vector-table finding and existing
  `needs_runtime_reproduction` bare-metal lead. No runtime-confirmed findings were present.
- Complete marker scanning of exactly 96 bytes. This is marker scan coverage, not complete disassembly or
  runtime coverage.
- Old absent `loadMap` losing selection to a later real map or explicit rolling delta zero.
- Both path declarations individually tested with undefined, empty and whitespace strings, each producing
  exactly one missing-path blocker when all other prerequisites were declared.
- Clearing PICOBIN blocks while preserving the optional vectors exercised both plain-image return paths;
  all three optional PICOBIN fields were absent.

The same built runtime-policy module accepted 72 accesses (four instances × read/write × widths 1/2/4 ×
start/interior/end-exact) and stopped 32 accesses (four instances × read/write × every 2/4-byte crossing offset).
Every stopped crossing retained `blocked_by_platform` and had no synthesized value. Temporary files and the
container were removed after the successful run.

## Limits and integration

No firmware acquisition/execution, deployment, push, shared image-tag mutation, live database/corpus/lanes
write or host/network change was performed. Disassembly success proves only these bounded synthetic bytes.
Runtime prerequisites remain unsupplied, and nothing here proves RP2350 hardware behavior or model fidelity.
Decoder, graph/mapping and core MCU review findings are outside this task's ownership and are not closed by this
evidence. The coordinator owns backlog updates, integration and the final repository-wide validation pass.
