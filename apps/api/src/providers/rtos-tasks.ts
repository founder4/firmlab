/**
 * FreeRTOS task snapshot — the API surface over core's `parseFreeRtosReadyList` / `parseFreeRtosCurrentTask`.
 *
 * The operator hands in a RAM snapshot and the symbol addresses they resolved elsewhere; this module never acquires
 * memory, never resolves a symbol, and never guesses a layout. Every snapshot must DECLARE its base address, byte
 * order and pointer width — there is no default — because the parser's answer is only as true as those three
 * facts, and a silently-defaulted little-endian 32-bit read of a big-endian dump yields plausible-looking garbage.
 * The declaration is validated in full before any byte reaches the parser; a malformed contract is a 400, not a
 * degraded result.
 *
 * What the result can and cannot say. A `complete` walk proves only that the SUPPLIED lists, in the SUPPLIED bytes,
 * chain back to their sentinels — not that the snapshot is a real, consistent image of a running device, and not
 * that these are all the tasks (delayed, suspended and blocked tasks live on other lists). So the proof state is
 * pinned at `needs_runtime_reproduction`: the snapshot is operator-supplied input, not bytes of the image. An
 * empty task list is never reported as "no tasks" unless every lane walked to completion, and even then the
 * summary names what was not walked. Every lane reports nodes and bytes attempted vs. completed, plus the bounds
 * that applied, so a partial answer states where it stopped.
 */
import { type FreeRtosLayout, parseFreeRtosCurrentTask, parseFreeRtosReadyList } from '@firmlab/core';
import type { FreeRtosCoverage, FreeRtosCurrentTaskResult, FreeRtosTaskListResult, ProofState } from '@firmlab/core';

/** Decoded snapshot cap. Fastify's default 1 MiB body limit bounds the base64 anyway; this states it in bytes. */
export const MAX_SNAPSHOT_BYTES = 512 * 1024;
/** Mirrors core's per-list traversal cap (`MAX_LIST_ITEMS`), reported so a `cycle_capped` lane names its bound. */
export const MAX_LIST_ITEMS = 256;
/** `configMAX_PRIORITIES` is tens in practice; more lists than this is not a ready-list array. */
export const MAX_READY_LISTS = 64;
/** sizeof(TickType_t) — core's `TICK_WIDTH`. */
const TICK_WIDTH = 4;

/** The persisted request contract. Addresses are plain numbers (target address space, not buffer offsets). */
export interface RtosTaskSnapshotInput {
  memory: {
    /** Address of the first snapshot byte. */
    base: number;
    endian: 'little' | 'big';
    pointerWidth: 4 | 8;
    /** The raw RAM bytes, base64. */
    bytesBase64: string;
  };
  symbols: {
    /** Resolved address of `pxCurrentTCB`; omitted or null → that lane is `missing_symbol`. */
    pxCurrentTCB?: number | null;
    /** Resolved addresses of `pxReadyTasksLists[priority]` entries; omitted or empty → `missing_symbol`. */
    readyLists?: { priority: number; address: number | null }[];
  };
}

export interface ValidatedSnapshot {
  buf: Uint8Array;
  base: number;
  layout: FreeRtosLayout;
  pxCurrentTCB: number | null;
  readyLists: { priority: number; address: number | null }[];
}

export type SnapshotValidation = { ok: true; snapshot: ValidatedSnapshot } | { ok: false; errors: string[] };

export interface RtosReadyListLane extends FreeRtosTaskListResult {
  /** Null when no ready list was supplied at all (the lane exists to say so). */
  priority: number | null;
  listAddress: number | null;
  /** Bytes of records (sentinel + list items) the walk tried to read. */
  bytesAttempted?: number;
  /** Of those, bytes that lay wholly inside the snapshot and were read. */
  bytesCompleted?: number;
}

export interface RtosCurrentTaskLane extends FreeRtosCurrentTaskResult {
  pxCurrentTcbAddress: number | null;
  bytesAttempted?: number;
  bytesCompleted?: number;
}

/**
 * Persisted on the job row. Every field added after this first shape must be optional forever (CLAUDE.md): a
 * stored result was written by an older build.
 */
export interface RtosTaskSnapshotResult {
  proofState: ProofState;
  /** `complete` only when every lane is; `none` when no lane is. */
  coverage: 'complete' | 'partial' | 'none';
  summary: string;
  snapshot: { base: number; endian: 'little' | 'big'; pointerWidth: 4 | 8; bytesSupplied: number };
  limits: { maxSnapshotBytes: number; maxListItems: number; maxReadyLists: number };
  currentTask: RtosCurrentTaskLane;
  readyLists: RtosReadyListLane[];
  totals: { nodesAttempted: number; nodesCompleted: number; bytesAttempted: number; bytesCompleted: number };
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/** Validate the whole contract before anything is parsed. Returns every problem, not just the first. */
export function validateRtosTaskSnapshot(body: unknown): SnapshotValidation {
  const errors: string[] = [];
  if (!isRecord(body)) return { ok: false, errors: ['body must be an object with memory and symbols'] };
  const memory = body.memory;
  const symbols = body.symbols ?? {};
  if (!isRecord(memory)) return { ok: false, errors: ['memory must declare base, endian, pointerWidth, bytesBase64'] };
  if (!isRecord(symbols)) return { ok: false, errors: ['symbols must be an object'] };

  const { base, endian, pointerWidth, bytesBase64 } = memory;
  if (endian !== 'little' && endian !== 'big') errors.push("memory.endian must be declared as 'little' or 'big'");
  if (pointerWidth !== 4 && pointerWidth !== 8) errors.push('memory.pointerWidth must be declared as 4 or 8');
  const addrLimit = pointerWidth === 4 ? 2 ** 32 : Number.MAX_SAFE_INTEGER;
  const isAddr = (v: unknown): v is number =>
    Number.isSafeInteger(v) && (v as number) >= 0 && (v as number) < addrLimit;
  if (!isAddr(base)) errors.push('memory.base must be declared as a non-negative integer address');

  let buf: Uint8Array = new Uint8Array(0);
  if (typeof bytesBase64 !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(bytesBase64) || bytesBase64.length % 4 !== 0) {
    errors.push('memory.bytesBase64 must be canonical base64');
  } else {
    buf = new Uint8Array(Buffer.from(bytesBase64, 'base64'));
    if (buf.length === 0) errors.push('memory.bytesBase64 decodes to zero bytes — an empty snapshot answers nothing');
    if (buf.length > MAX_SNAPSHOT_BYTES)
      errors.push(`snapshot is ${buf.length} bytes; the cap is ${MAX_SNAPSHOT_BYTES}`);
  }
  if (isAddr(base) && base + buf.length > addrLimit)
    errors.push('memory.base + snapshot length overflows the address space');

  const cur = symbols.pxCurrentTCB;
  if (cur !== undefined && cur !== null && !isAddr(cur)) errors.push('symbols.pxCurrentTCB must be an address or null');

  const readyLists: { priority: number; address: number | null }[] = [];
  const lists = symbols.readyLists;
  if (lists !== undefined) {
    if (!Array.isArray(lists)) errors.push('symbols.readyLists must be an array');
    else if (lists.length > MAX_READY_LISTS)
      errors.push(`symbols.readyLists holds ${lists.length}; the cap is ${MAX_READY_LISTS}`);
    else {
      const seen = new Set<number>();
      lists.forEach((l, i) => {
        if (!isRecord(l) || !Number.isSafeInteger(l.priority) || (l.priority as number) < 0) {
          errors.push(`symbols.readyLists[${i}].priority must be a non-negative integer`);
          return;
        }
        const priority = l.priority as number;
        if (seen.has(priority)) errors.push(`symbols.readyLists[${i}] repeats priority ${priority}`);
        seen.add(priority);
        if (l.address !== null && !isAddr(l.address)) {
          errors.push(`symbols.readyLists[${i}].address must be an address or null`);
          return;
        }
        readyLists.push({ priority, address: l.address as number | null });
      });
    }
  }

  if (errors.length > 0) return { ok: false, errors };
  return {
    ok: true,
    snapshot: {
      buf,
      base: base as number,
      layout: { endian: endian as 'little' | 'big', pointerWidth: pointerWidth as 4 | 8 },
      pxCurrentTCB: (cur as number | null | undefined) ?? null,
      readyLists,
    },
  };
}

/** Did the walk fail on the sentinel itself (nothing visited)? Derived from core's result, not re-parsed. */
const sentinelFailed = (r: FreeRtosTaskListResult) =>
  r.attempted === 0 && (r.coverage === 'out_of_range' || r.coverage === 'truncated');

function listBytes(r: FreeRtosTaskListResult, ptr: number): { bytesAttempted: number; bytesCompleted: number } {
  if (r.coverage === 'missing_symbol') return { bytesAttempted: 0, bytesCompleted: 0 };
  const sentinel = TICK_WIDTH + ptr;
  if (sentinelFailed(r)) return { bytesAttempted: sentinel, bytesCompleted: 0 };
  const record = TICK_WIDTH + 4 * ptr;
  // The last visited node failed its bounds check on these two codes; every other visited node was read whole.
  const failedLast = r.coverage === 'out_of_range' || r.coverage === 'truncated' ? 1 : 0;
  return {
    bytesAttempted: sentinel + r.attempted * record,
    bytesCompleted: sentinel + (r.attempted - failedLast) * record,
  };
}

/** Run both parsers over a validated snapshot and compose the persisted, coverage-honest result. */
export function runRtosTaskSnapshot(s: ValidatedSnapshot): RtosTaskSnapshotResult {
  const ptr = s.layout.pointerWidth;
  const cur = parseFreeRtosCurrentTask(s.buf, s.base, s.pxCurrentTCB, s.layout);
  const currentTask: RtosCurrentTaskLane = {
    ...cur,
    pxCurrentTcbAddress: s.pxCurrentTCB,
    bytesAttempted: s.pxCurrentTCB === null ? 0 : ptr,
    bytesCompleted: cur.coverage === 'complete' ? ptr : 0,
  };

  const readyLists: RtosReadyListLane[] =
    s.readyLists.length === 0
      ? [
          {
            priority: null,
            listAddress: null,
            ...parseFreeRtosReadyList(s.buf, s.base, null, s.layout),
            bytesAttempted: 0,
            bytesCompleted: 0,
          },
        ]
      : s.readyLists.map((l) => {
          const r = parseFreeRtosReadyList(s.buf, s.base, l.address, s.layout);
          return { priority: l.priority, listAddress: l.address, ...r, ...listBytes(r, ptr) };
        });

  const coverages: FreeRtosCoverage[] = [currentTask.coverage, ...readyLists.map((l) => l.coverage)];
  const done = coverages.filter((c) => c === 'complete').length;
  const coverage = done === coverages.length ? 'complete' : done === 0 ? 'none' : 'partial';
  const tasks = readyLists.reduce((n, l) => n + l.completed, 0);
  const incomplete = [
    ...(currentTask.coverage === 'complete' ? [] : [`pxCurrentTCB: ${currentTask.coverage}`]),
    ...readyLists
      .filter((l) => l.coverage !== 'complete')
      .map((l) => `ready list ${l.priority ?? '(none supplied)'}: ${l.coverage}`),
  ];
  const scope =
    'Only the supplied lists in the supplied bytes were walked; delayed, suspended and blocked tasks live on lists ' +
    'not read here, and the snapshot itself is operator-supplied, not proven against a running device.';
  const summary =
    coverage === 'complete'
      ? `${tasks} ready task record(s) across ${readyLists.length} list(s), every lane walked to its sentinel. ${scope}`
      : `${tasks} ready task record(s) found, but ${incomplete.join('; ')} — this is not a complete task set, and an ` +
        `empty result here is not "no tasks". ${scope}`;

  const all = [currentTask, ...readyLists];
  return {
    proofState: 'needs_runtime_reproduction',
    coverage,
    summary,
    snapshot: { base: s.base, endian: s.layout.endian, pointerWidth: ptr, bytesSupplied: s.buf.length },
    limits: { maxSnapshotBytes: MAX_SNAPSHOT_BYTES, maxListItems: MAX_LIST_ITEMS, maxReadyLists: MAX_READY_LISTS },
    currentTask,
    readyLists,
    totals: {
      nodesAttempted: readyLists.reduce((n, l) => n + l.attempted, 0),
      nodesCompleted: tasks,
      bytesAttempted: all.reduce((n, l) => n + (l.bytesAttempted ?? 0), 0),
      bytesCompleted: all.reduce((n, l) => n + (l.bytesCompleted ?? 0), 0),
    },
  };
}
