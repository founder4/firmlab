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
 * that these are all the tasks (only the lists the operator named were read). So the proof state is
 * pinned at `needs_runtime_reproduction`: the snapshot is operator-supplied input, not bytes of the image. An
 * empty task list is never reported as "no tasks" unless every lane walked to completion, and even then the
 * summary names what was not walked. Every lane reports nodes and bytes attempted vs. completed, plus the bounds
 * that applied, so a partial answer states where it stopped.
 *
 * Beyond the ready lists, the operator may name the other `tasks.c` state lists — the two delayed lists, the
 * suspended list, the pending-ready list and the waiting-termination list. They are the same `List_t`, walked by
 * core's `parseFreeRtosNamedList` under the same coverage rules, and each becomes its own typed lane. A list the
 * request does not mention is not walked and adds no lane (so a ready-only request keeps the coverage it always
 * had), but the summary names every kind that was not read; a list mentioned with a null address is a
 * `missing_symbol` lane, because the operator asked and could not resolve it. A TCB found on two state lists at once
 * is something a consistent snapshot cannot produce, and the result says so rather than counting it twice quietly.
 */
import {
  type FreeRtosLayout,
  parseFreeRtosCurrentTask,
  parseFreeRtosNamedList,
  parseFreeRtosReadyList,
} from '@firmlab/core';
import type {
  FreeRtosCoverage,
  FreeRtosCurrentTaskResult,
  FreeRtosListKind,
  FreeRtosNamedList,
  FreeRtosNamedListResult,
  FreeRtosTaskListResult,
  ProofState,
} from '@firmlab/core';

/** Decoded snapshot cap, checked after decoding: the API's 8 MiB `bodyLimit` (index.ts) admits far more base64. */
export const MAX_SNAPSHOT_BYTES = 512 * 1024;
/** Mirrors core's per-list traversal cap (`MAX_LIST_ITEMS`), reported so a `cycle_capped` lane names its bound. */
export const MAX_LIST_ITEMS = 256;
/** `configMAX_PRIORITIES` is tens in practice; more lists than this is not a ready-list array. */
export const MAX_READY_LISTS = 64;
/** `xDelayedTaskList1` and `xDelayedTaskList2`: `tasks.c` declares exactly two. */
export const MAX_DELAYED_LISTS = 2;
/** A list label is an audit-trail string, not free text: a C identifier with an optional index, kept short. */
const LIST_NAME = /^[A-Za-z_][A-Za-z0-9_]*(\[\d+\])?$/;
const MAX_LIST_NAME = 64;
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
    /**
     * `xDelayedTaskList1`/`2`, up to two. A name containing "overflow" (e.g. `pxOverflowDelayedTaskList`) makes the
     * lane `delayed_overflow`: the two lists swap roles at every tick wrap, so only the operator, reading the two
     * pointers in the snapshot, can say which is which. Unnamed lists default to `xDelayedTaskList<n>`.
     */
    delayedLists?: { name?: string; address: number | null }[];
    /** `xSuspendedTaskList`. Omitted → not walked; null → a `missing_symbol` lane. */
    suspendedList?: number | null;
    /** `xPendingReadyList`. Omitted → not walked; null → a `missing_symbol` lane. */
    pendingReadyList?: number | null;
    /** `xTasksWaitingTermination`. Omitted → not walked; null → a `missing_symbol` lane. */
    terminatedList?: number | null;
  };
}

export interface ValidatedSnapshot {
  buf: Uint8Array;
  base: number;
  layout: FreeRtosLayout;
  pxCurrentTCB: number | null;
  readyLists: { priority: number; address: number | null }[];
  /** Each absent field means "not asked", which is different from a null address ("asked, not resolved"). */
  delayedLists?: FreeRtosNamedList[];
  suspendedList?: number | null;
  pendingReadyList?: number | null;
  terminatedList?: number | null;
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

/** A non-ready state list (delayed, suspended, pending-ready, waiting-termination) as walked, plus its byte budget. */
export interface RtosNamedListLane extends FreeRtosNamedListResult {
  /** Bytes of records (sentinel + list items) the walk tried to read; the header count annotation is not counted. */
  bytesAttempted?: number;
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
  limits: { maxSnapshotBytes: number; maxListItems: number; maxReadyLists: number; maxDelayedLists?: number };
  currentTask: RtosCurrentTaskLane;
  readyLists: RtosReadyListLane[];
  /** Totals cover EVERY lane walked — ready and named alike. */
  totals: { nodesAttempted: number; nodesCompleted: number; bytesAttempted: number; bytesCompleted: number };
  /** Present only when the request named delayed lists. */
  delayedLists?: RtosNamedListLane[];
  suspendedList?: RtosNamedListLane;
  pendingReadyList?: RtosNamedListLane;
  terminatedList?: RtosNamedListLane;
  /** Non-ready list kinds the request did not name, so did not walk. */
  unwalkedKinds?: FreeRtosListKind[];
  /**
   * TCBs found on more than one state list (ready, delayed, suspended, terminated). A task's `xStateListItem` is
   * on one list at a time, so this is a torn or inconsistent snapshot. The pending-ready list is excluded: it holds
   * `xEventListItem`, and a task on it legitimately still sits on its delayed or suspended list.
   */
  tcbsOnSeveralLists?: number[];
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
  if (!isAddr(base))
    errors.push(
      pointerWidth === 8
        ? 'memory.base must be a non-negative integer address below 2^53 (the JSON number precision this API reads)'
        : 'memory.base must be declared as a non-negative integer address',
    );

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

  // A list walked twice counts its tasks twice; the ready lanes have always allowed it, the new lanes do not.
  const seenAddresses = new Set<number>(readyLists.flatMap((l) => (l.address === null ? [] : [l.address])));
  const claim = (field: string, address: number | null) => {
    if (address === null) return;
    if (seenAddresses.has(address))
      errors.push(`${field} repeats list address 0x${address.toString(16)}; each list is walked once`);
    seenAddresses.add(address);
  };

  let delayedLists: FreeRtosNamedList[] | undefined;
  const delayed = symbols.delayedLists;
  if (delayed !== undefined) {
    if (!Array.isArray(delayed)) errors.push('symbols.delayedLists must be an array');
    else if (delayed.length > MAX_DELAYED_LISTS)
      errors.push(`symbols.delayedLists holds ${delayed.length}; tasks.c declares ${MAX_DELAYED_LISTS}`);
    else {
      delayedLists = [];
      const names = new Set<string>();
      delayed.forEach((l, i) => {
        if (!isRecord(l)) {
          errors.push(`symbols.delayedLists[${i}] must be an object with an address`);
          return;
        }
        let name = `xDelayedTaskList${i + 1}`;
        if (l.name !== undefined) {
          if (typeof l.name !== 'string' || l.name.length > MAX_LIST_NAME || !LIST_NAME.test(l.name)) {
            errors.push(
              `symbols.delayedLists[${i}].name must be a C identifier of at most ${MAX_LIST_NAME} characters`,
            );
            return;
          }
          name = l.name;
        }
        if (names.has(name)) errors.push(`symbols.delayedLists[${i}] repeats name ${name}`);
        names.add(name);
        if (l.address !== null && !isAddr(l.address)) {
          errors.push(`symbols.delayedLists[${i}].address must be an address or null`);
          return;
        }
        const address = l.address as number | null;
        claim(`symbols.delayedLists[${i}]`, address);
        delayedLists?.push({ kind: /overflow/i.test(name) ? 'delayed_overflow' : 'delayed', name, address });
      });
    }
  }

  const single = (field: 'suspendedList' | 'pendingReadyList' | 'terminatedList'): number | null | undefined => {
    const v = symbols[field];
    if (v === undefined || v === null) return v;
    if (!isAddr(v)) {
      errors.push(`symbols.${field} must be an address or null`);
      return undefined;
    }
    claim(`symbols.${field}`, v);
    return v;
  };
  const suspendedList = single('suspendedList');
  const pendingReadyList = single('pendingReadyList');
  const terminatedList = single('terminatedList');

  if (errors.length > 0) return { ok: false, errors };
  return {
    ok: true,
    snapshot: {
      buf,
      base: base as number,
      layout: { endian: endian as 'little' | 'big', pointerWidth: pointerWidth as 4 | 8 },
      pxCurrentTCB: (cur as number | null | undefined) ?? null,
      readyLists,
      ...(delayedLists !== undefined ? { delayedLists } : {}),
      ...(suspendedList !== undefined ? { suspendedList } : {}),
      ...(pendingReadyList !== undefined ? { pendingReadyList } : {}),
      ...(terminatedList !== undefined ? { terminatedList } : {}),
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

const TORN = 'which a consistent snapshot cannot produce — the snapshot may be torn.';
const SCOPE_TAIL =
  'ready lists at priorities not supplied were not read, and the snapshot itself is operator-supplied, not proven ' +
  'against a running device.';

type StateKind = Exclude<FreeRtosListKind, 'ready'>;
/** Plural-free labels for the summary, one per non-ready kind. */
const KIND_LABEL: Record<StateKind, string> = {
  delayed: 'delayed',
  delayed_overflow: 'overflow-delayed',
  suspended: 'suspended',
  pending: 'pending-ready',
  terminated: 'waiting-termination',
};

/** Run the parsers over a validated snapshot and compose the persisted, coverage-honest result. */
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

  const walk = (list: FreeRtosNamedList): RtosNamedListLane => {
    const r = parseFreeRtosNamedList(s.buf, s.base, list, s.layout);
    return { ...r, ...listBytes(r, ptr) };
  };
  const delayedLists = s.delayedLists?.map(walk);
  const suspendedList =
    s.suspendedList === undefined ? undefined : walk({ kind: 'suspended', address: s.suspendedList });
  const pendingReadyList =
    s.pendingReadyList === undefined ? undefined : walk({ kind: 'pending', address: s.pendingReadyList });
  const terminatedList =
    s.terminatedList === undefined ? undefined : walk({ kind: 'terminated', address: s.terminatedList });
  const named = [...(delayedLists ?? []), suspendedList, pendingReadyList, terminatedList].filter(
    (l): l is RtosNamedListLane => l !== undefined,
  );
  const lists: FreeRtosTaskListResult[] = [...readyLists, ...named];

  const coverages: FreeRtosCoverage[] = [currentTask.coverage, ...lists.map((l) => l.coverage)];
  const done = coverages.filter((c) => c === 'complete').length;
  const tasks = lists.reduce((n, l) => n + l.completed, 0);
  const readyTasks = readyLists.reduce((n, l) => n + l.completed, 0);
  // A lane that stopped early can still have corroborated tasks before it stopped; that is partial, not none.
  const coverage = done === coverages.length ? 'complete' : done === 0 && tasks === 0 ? 'none' : 'partial';
  const nodesAttempted = lists.reduce((n, l) => n + l.attempted, 0);
  const discarded =
    nodesAttempted > tasks
      ? ` ${nodesAttempted - tasks} walked node(s) did not yield a corroborated task record and are not counted.`
      : '';

  // Per-kind counts, in tasks.c order, for every non-ready kind the request named.
  const walkedKinds = new Set(named.map((l) => l.kind));
  const perKind = (['delayed', 'delayed_overflow', 'suspended', 'pending', 'terminated'] as const)
    .filter((k) => walkedKinds.has(k))
    .map((k) => `${named.filter((l) => l.kind === k).reduce((n, l) => n + l.completed, 0)} ${KIND_LABEL[k]}`);
  const counted = `${readyTasks} ready task record(s)${perKind.length > 0 ? ` (plus ${perKind.join(', ')})` : ''}`;

  // A delayed list of either role covers the delayed tasks only when both were named; one alone leaves the other.
  const unwalkedKinds: StateKind[] = [
    ...((delayedLists?.length ?? 0) < MAX_DELAYED_LISTS ? (['delayed'] as const) : []),
    ...(suspendedList ? [] : (['suspended'] as const)),
    ...(pendingReadyList ? [] : (['pending'] as const)),
    ...(terminatedList ? [] : (['terminated'] as const)),
  ];

  const onList = new Map<number, number>();
  for (const l of [...readyLists, ...named.filter((n) => n.kind !== 'pending')])
    for (const t of new Set(l.tasks.map((x) => x.tcbAddress))) onList.set(t, (onList.get(t) ?? 0) + 1);
  const tcbsOnSeveralLists = [...onList].filter(([, n]) => n > 1).map(([t]) => t);
  const torn =
    tcbsOnSeveralLists.length > 0
      ? ` ${tcbsOnSeveralLists.length} TCB(s) appear on more than one state list, ${TORN}`
      : '';
  const inconsistent = named.filter((l) => l.containerMismatches > 0 || l.orderViolations > 0).length;
  const anomalies =
    inconsistent > 0 ? ` ${inconsistent} list(s) carry structural inconsistencies, recorded in their evidence.` : '';

  const incomplete = [
    ...(currentTask.coverage === 'complete' ? [] : [`pxCurrentTCB: ${currentTask.coverage}`]),
    ...readyLists
      .filter((l) => l.coverage !== 'complete')
      .map((l) => `ready list ${l.priority ?? '(none supplied)'}: ${l.coverage}`),
    ...named.filter((l) => l.coverage !== 'complete').map((l) => `${l.name}: ${l.coverage}`),
  ];
  const notRead =
    unwalkedKinds.length > 0
      ? `${unwalkedKinds
          .map((k) => (k === 'delayed' && delayedLists?.length ? 'delayed (second list)' : KIND_LABEL[k]))
          .join(', ')} tasks live on lists not read here, `
      : '';
  const scope = `Only the supplied lists in the supplied bytes were walked; ${notRead}${SCOPE_TAIL}`;
  const summary =
    coverage === 'complete'
      ? `${counted} across ${lists.length} list(s), every lane walked to its sentinel.${discarded}${torn}${anomalies} ${scope}`
      : `${counted} found, but ${incomplete.join('; ')} — this is not a complete task set, and an ` +
        `empty result here is not "no tasks".${discarded}${torn}${anomalies} ${scope}`;

  const all = [currentTask, ...readyLists, ...named];
  return {
    proofState: 'needs_runtime_reproduction',
    coverage,
    summary,
    snapshot: { base: s.base, endian: s.layout.endian, pointerWidth: ptr, bytesSupplied: s.buf.length },
    limits: {
      maxSnapshotBytes: MAX_SNAPSHOT_BYTES,
      maxListItems: MAX_LIST_ITEMS,
      maxReadyLists: MAX_READY_LISTS,
      maxDelayedLists: MAX_DELAYED_LISTS,
    },
    currentTask,
    readyLists,
    totals: {
      nodesAttempted,
      nodesCompleted: tasks,
      bytesAttempted: all.reduce((n, l) => n + (l.bytesAttempted ?? 0), 0),
      bytesCompleted: all.reduce((n, l) => n + (l.bytesCompleted ?? 0), 0),
    },
    ...(delayedLists ? { delayedLists } : {}),
    ...(suspendedList ? { suspendedList } : {}),
    ...(pendingReadyList ? { pendingReadyList } : {}),
    ...(terminatedList ? { terminatedList } : {}),
    unwalkedKinds,
    ...(tcbsOnSeveralLists.length > 0 ? { tcbsOnSeveralLists } : {}),
  };
}
