#!/usr/bin/env node
/**
 * End-to-end check of the FreeRTOS lane against a fixture whose task set is KNOWN: ELF symbols → Renode RAM capture
 * → task-list walk, then a comparison with what `__fixtures__/freertos-stm32f4/main.c` creates.
 *
 * Run it where Renode is installed (the firmlab-tools/firmlab-firmware images), against a built `apps/api/dist`:
 *
 *   docker run --rm --network none -v "$PWD:/w" -w /w firmlab-firmware node apps/api/scripts/rtos-freertos-e2e.mjs
 *
 * What it proves and what it does not. A pass shows that, for THIS fixture on Renode's stm32f4 platform, the
 * product's three providers chain without hand-entered addresses and that every task the walker reports is one the
 * firmware created, on the list its state implies. It is emulation of a synthetic build — not a device, not another
 * FreeRTOS version or configuration, and not evidence about any corpus image.
 *
 * The expected side reads each TCB's `uxPriority` and `pcTaskName` from the captured bytes at offsets that hold for
 * FreeRTOS V11.1.0 built with this fixture's FreeRTOSConfig.h on a 32-bit target (no MPU wrappers): that layout is
 * this script's knowledge of the fixture, used only to corroborate. The product itself never decodes TCB names.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const api = path.resolve(here, '..');
const { runRtosElfSymbols } = await import(path.join(api, 'dist/providers/rtos-elf-symbols.js'));
const { runRenodeRamCapture } = await import(path.join(api, 'dist/providers/renode-ram.js'));
const { runRtosTaskSnapshot, validateRtosTaskSnapshot } = await import(path.join(api, 'dist/providers/rtos-tasks.js'));

const ELF = path.join(api, 'src/providers/__fixtures__/freertos-stm32f4/freertos-stm32f4.elf');
const PLATFORM = process.env.RENODE_PLATFORM ?? '/opt/renode/platforms/cpus/stm32f4.repl';
const SECONDS = Number(process.env.CAPTURE_SECONDS ?? 3);
// Declared for this build (FreeRTOSConfig.h, 32-bit List_t with mini list items, no integrity-check bytes).
const MAX_PRIORITIES = 5;
const LIST_SIZE = 20;
const TCB_PRIORITY_OFFSET = 44;
const TCB_NAME_OFFSET = 52;
const EXPECTED = {
  ready: { SpinA: 1, SpinB: 1, IDLE: 0 },
  delayed: { Sleeper: 2 },
  suspended: { Parked: 3 },
};

const failures = [];
const check = (ok, what) => {
  console.log(`${ok ? 'PASS' : 'FAIL'} ${what}`);
  if (!ok) failures.push(what);
};

const sym = runRtosElfSymbols(ELF);
console.log(`elf-symbols: ${sym.verdict} — ${sym.summary}`);
check(sym.prefill !== null, 'ELF symbols produced a snapshot pre-fill');
const prefill = sym.prefill ?? {};
check(
  prefill.readyListArray?.symbolSize === MAX_PRIORITIES * LIST_SIZE,
  'pxReadyTasksLists st_size = 5 × sizeof(List_t)',
);

const cap = await runRenodeRamCapture(ELF, { platform: PLATFORM, seconds: SECONDS });
console.log(`ram-capture: captured=${cap.captured} — ${cap.reason}`);
if (cap.remoteResourcesRefused?.length)
  console.log(`  remote resources refused: ${cap.remoteResourcesRefused.join(', ')}`);
check(cap.captured && cap.region !== null && cap.bytesBase64, 'Renode captured the SRAM region');
if (!cap.captured || !cap.region || !cap.bytesBase64) {
  console.log(JSON.stringify({ ...cap, bytesBase64: undefined, bytes: undefined }, null, 1));
  process.exit(1);
}

const body = {
  memory: { base: cap.region.base, endian: 'little', pointerWidth: 4, bytesBase64: cap.bytesBase64 },
  symbols: {
    pxCurrentTCB: prefill.pxCurrentTCB,
    readyListArray: {
      base: prefill.readyListArray?.base ?? null,
      maxPriorities: MAX_PRIORITIES,
      listSize: LIST_SIZE,
      symbolSize: prefill.readyListArray?.symbolSize ?? null,
    },
    delayedLists: prefill.delayedLists,
    suspendedList: prefill.suspendedList,
    pendingReadyList: prefill.pendingReadyList,
    terminatedList: prefill.terminatedList,
  },
};
const v = validateRtosTaskSnapshot(body);
check(v.ok, `snapshot contract validated${v.ok ? '' : `: ${v.errors.join('; ')}`}`);
if (!v.ok) process.exit(1);
const r = runRtosTaskSnapshot(v.snapshot);
console.log(`walk: coverage=${r.coverage} proofState=${r.proofState} — ${r.summary}`);

const ram = Buffer.from(cap.bytesBase64, 'base64');
const at = (addr) => addr - cap.region.base;
const tcb = (addr) => {
  const o = at(addr);
  const name = ram.subarray(o + TCB_NAME_OFFSET, o + TCB_NAME_OFFSET + 16);
  const end = name.indexOf(0);
  return {
    name: name.subarray(0, end < 0 ? 16 : end).toString('latin1'),
    priority: ram.readUInt32LE(o + TCB_PRIORITY_OFFSET),
  };
};
const named = (tasks) =>
  Object.fromEntries((tasks ?? []).map((t) => [tcb(t.tcbAddress).name, tcb(t.tcbAddress).priority]));

const ready = {};
for (const lane of r.readyLists) {
  for (const [name, prio] of Object.entries(named(lane.tasks))) {
    ready[name] = prio;
    check(
      prio === lane.priority,
      `ready task ${name} sits on the list of its own priority (${prio} vs lane ${lane.priority})`,
    );
  }
}
const delayed = Object.assign({}, ...(r.delayedLists ?? []).map((l) => named(l.tasks)));
const suspended = named(r.suspendedList?.tasks);
console.log(
  JSON.stringify({ ready, delayed, suspended, current: r.currentTask.tcbAddress && tcb(r.currentTask.tcbAddress) }),
);

check(
  JSON.stringify(ready) === JSON.stringify(sortKeys(EXPECTED.ready, ready)),
  `ready lists hold exactly ${JSON.stringify(EXPECTED.ready)}`,
);
check(
  JSON.stringify(delayed) === JSON.stringify(EXPECTED.delayed),
  `delayed lists hold exactly ${JSON.stringify(EXPECTED.delayed)}`,
);
check(
  JSON.stringify(suspended) === JSON.stringify(EXPECTED.suspended),
  `suspended list holds exactly ${JSON.stringify(EXPECTED.suspended)}`,
);
const cur = r.currentTask.tcbAddress ? tcb(r.currentTask.tcbAddress).name : null;
check(cur === 'SpinA' || cur === 'SpinB', `pxCurrentTCB is one of the priority-1 spinners (got ${cur})`);
check((r.tcbsOnSeveralLists ?? []).length === 0, 'no TCB appears on two state lists');
check(r.proofState === 'needs_runtime_reproduction', 'proof state stays needs_runtime_reproduction');

function sortKeys(expected, actual) {
  // Compare as sets: order of tasks within a list is scheduling history, not a property of the fixture.
  const keys = Object.keys(actual).sort();
  return Object.keys(expected).sort().join() === keys.join()
    ? Object.fromEntries(keys.map((k) => [k, expected[k]]))
    : expected;
}

console.log(failures.length === 0 ? 'RESULT: PASS' : `RESULT: FAIL (${failures.length})`);
fs.writeFileSync(process.env.E2E_OUT ?? '/dev/null', JSON.stringify({ failures, coverage: r.coverage }, null, 1));
process.exit(failures.length === 0 ? 0 : 1);
