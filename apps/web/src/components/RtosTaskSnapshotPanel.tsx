/**
 * RtosTaskSnapshotPanel — the FreeRTOS RAM-snapshot walk (`/rtos/tasks`) on a screen.
 *
 * The API refuses an undeclared layout on purpose — a silently-defaulted little-endian 32-bit read of a big-endian
 * dump yields plausible-looking garbage — so this form has NO default for byte order or pointer width: the analyst
 * picks both or the form will not submit. The API's caps are mirrored client-side so a bad field is named before
 * a round trip, but the API stays the authority: its 400 `details` list is rendered verbatim when it refuses.
 *
 * The result is always `needs_runtime_reproduction`. The snapshot is operator-supplied input, not bytes of the
 * image, and a `complete` lane only proves the supplied list chains back to its sentinel in the supplied bytes. The
 * provider's summary sentence (which already says what was NOT walked) is shown first, verbatim.
 *
 * Beyond the ready lists, the analyst may name the other `tasks.c` state lists (delayed, overflow-delayed,
 * suspended, pending-ready, waiting-termination). An empty field is left out of the request, and the API then
 * reports that kind as NOT WALKED — the result names it, so tasks in that state are never silently absent. Wake
 * ticks are shown only on delayed lanes, the one kind whose `xItemValue` the kernel sets to a wake tick.
 *
 * The addresses can be read from the image's OWN ELF symbol table (`/rtos/elf-symbols`), but only on an explicit
 * operator action, and only fields whose symbol resolved to exactly one absolute address are filled. A link-time
 * address is not runtime proof, and the RAM snapshot still comes from the analyst; every filled field stays editable.
 * A raw binary, a stripped ELF or a refused read is shown as the reason it is, never as "no FreeRTOS". The two
 * delayed lists are listed and never filled — which is current is a RAM fact. No per-priority ready list is filled
 * either, because that would need a `sizeof(List_t)` this panel refuses to infer from a symbol size; only the ready
 * array's address and raw `st_size` are, and the analyst still declares the priority count and the list size.
 *
 * The ready lists can instead be declared as the whole `pxReadyTasksLists` array: its address, plus
 * `configMAX_PRIORITIES` and `sizeof(List_t)` as the analyst's build declares them. The declared size is checked
 * against the one layout the walk reads, client-side for an early message and again by the API, which is the
 * authority; the array and individual rows are mutually exclusive, because each list is walked once.
 *
 * Folded behind a disclosure on images not classed rtos/baremetal: still usable, never clutter on a Linux image.
 */
import { type JSX, useEffect, useRef, useState } from 'react';
import {
  type RenodeRamCaptureResult,
  type RtosElfSymbolStatus,
  type RtosElfSymbolsResult,
  type RtosNamedListLane,
  type RtosTaskLane,
  type RtosTaskSnapshotInput,
  type RtosTaskSnapshotResult,
  api,
} from '../api';
import { type Messages, useMessages } from '../i18n';
import { ProofStateBadge } from './FindingsLedger';

/** Mirrors `MAX_SNAPSHOT_BYTES` / `MAX_READY_LISTS` in `apps/api/src/providers/rtos-tasks.ts`. */
export const MAX_SNAPSHOT_BYTES = 512 * 1024;
export const MAX_READY_LISTS = 64;
/** sizeof(List_t) in the one layout the walk reads — core's `listRecordSize` for each declarable pointer width. */
export const LIST_RECORD_BYTES = { '4': 20, '8': 40 } as const;

type M = Messages['rtosTasks'];

export interface SnapshotForm {
  bytes: Uint8Array | null;
  base: string;
  endian: '' | 'little' | 'big';
  pointerWidth: '' | '4' | '8';
  pxCurrentTCB: string;
  readyLists: { priority: string; address: string }[];
  /** The `pxReadyTasksLists` array; all four empty → not declared. `symbolSize` alone stays optional. */
  readyArray: { base: string; maxPriorities: string; listSize: string; symbolSize: string };
  /** The List_t `pxDelayedTaskList` points to at snapshot time. Empty → not walked. */
  delayedList: string;
  /** The List_t `pxOverflowDelayedTaskList` points to. Empty → not walked. */
  overflowDelayedList: string;
  suspendedList: string;
  pendingReadyList: string;
  terminatedList: string;
}

/** The single-address state-list fields, in `tasks.c` order. */
export const STATE_LIST_FIELDS = [
  'delayedList',
  'overflowDelayedList',
  'suspendedList',
  'pendingReadyList',
  'terminatedList',
] as const;
type StateListField = (typeof STATE_LIST_FIELDS)[number];

export const EMPTY_FORM: SnapshotForm = {
  bytes: null,
  base: '',
  endian: '',
  pointerWidth: '',
  pxCurrentTCB: '',
  readyLists: [],
  readyArray: { base: '', maxPriorities: '', listSize: '', symbolSize: '' },
  delayedList: '',
  overflowDelayedList: '',
  suspendedList: '',
  pendingReadyList: '',
  terminatedList: '',
};

/** Field key → message. `readyLists.<i>.priority` / `.address` name the row. */
export type FormErrors = Record<string, string>;

/** Decimal, or hex with a `0x` prefix. Anything else (including a bare hex string) is refused, never guessed. */
export function parseAddress(raw: string): number | null {
  const s = raw.trim().replace(/_/g, '');
  const n = /^0x[0-9a-f]+$/i.test(s) ? Number.parseInt(s.slice(2), 16) : /^\d+$/.test(s) ? Number(s) : Number.NaN;
  return Number.isSafeInteger(n) ? n : null;
}

/** Pure: validate the form against the API's contract and build the request, or name every bad field. */
export function buildSnapshotRequest(
  f: SnapshotForm,
  m: M,
): { ok: true; input: RtosTaskSnapshotInput } | { ok: false; errors: FormErrors } {
  const errors: FormErrors = {};
  const maxKiB = MAX_SNAPSHOT_BYTES / 1024;
  if (!f.bytes) errors.file = m.error.fileMissing;
  else if (f.bytes.length === 0) errors.file = m.error.fileEmpty;
  else if (f.bytes.length > MAX_SNAPSHOT_BYTES) errors.file = m.error.fileTooLarge(f.bytes.length, maxKiB);
  if (!f.endian) errors.endian = m.error.endian;
  if (!f.pointerWidth) errors.pointerWidth = m.error.pointerWidth;

  // Until the width is declared, bound by the narrower space; the API re-checks against the declared one.
  const bits = f.pointerWidth === '8' ? 53 : 32;
  const limit = bits === 53 ? Number.MAX_SAFE_INTEGER + 1 : 2 ** 32;
  const addr = (raw: string) => {
    const n = parseAddress(raw);
    return n !== null && n < limit ? n : null;
  };

  const base = addr(f.base);
  if (parseAddress(f.base) === null) errors.base = m.error.base;
  else if (base === null || base + (f.bytes?.length ?? 0) > limit) errors.base = m.error.baseRange(bits);

  let pxCurrentTCB: number | null = null;
  if (f.pxCurrentTCB.trim()) {
    pxCurrentTCB = addr(f.pxCurrentTCB);
    if (pxCurrentTCB === null) errors.pxCurrentTCB = m.error.address(bits);
  }

  if (f.readyLists.length > MAX_READY_LISTS) errors.readyLists = m.error.tooManyLists(MAX_READY_LISTS);
  const seen = new Set<number>();
  const readyLists: { priority: number; address: number }[] = [];
  f.readyLists.forEach((l, i) => {
    const p = l.priority.trim();
    const priority = /^\d+$/.test(p) ? Number(p) : Number.NaN;
    if (!Number.isSafeInteger(priority)) errors[`readyLists.${i}.priority`] = m.error.priority;
    else if (seen.has(priority)) errors[`readyLists.${i}.priority`] = m.error.priorityRepeated(priority);
    else seen.add(priority);
    const address = addr(l.address);
    if (address === null) errors[`readyLists.${i}.address`] = m.error.address(bits);
    if (Number.isSafeInteger(priority) && address !== null) readyLists.push({ priority, address });
  });

  // Every list is walked once: the API refuses an address named twice, because its tasks would be counted twice and
  // the result would then blame the snapshot for the request's repeat.
  const taken = new Set<number>();
  readyLists.forEach((l, i) => {
    if (taken.has(l.address)) errors[`readyLists.${i}.address`] = m.error.addressRepeated(hex(l.address));
    taken.add(l.address);
  });

  const ra = f.readyArray;
  const whole = (raw: string) => (/^\d+$/.test(raw.trim()) ? Number(raw.trim()) : Number.NaN);
  let readyListArray: NonNullable<RtosTaskSnapshotInput['symbols']['readyListArray']> | undefined;
  if ([ra.base, ra.maxPriorities, ra.listSize, ra.symbolSize].some((v) => v.trim())) {
    if (f.readyLists.length > 0) errors.readyArray = m.error.arrayAndLists;
    const arrayBase = ra.base.trim() ? addr(ra.base) : null;
    if (arrayBase === null) errors['readyArray.base'] = ra.base.trim() ? m.error.address(bits) : m.error.arrayBase;
    const n = whole(ra.maxPriorities);
    if (!Number.isSafeInteger(n) || n < 1 || n > MAX_READY_LISTS)
      errors['readyArray.maxPriorities'] = m.error.maxPriorities(MAX_READY_LISTS);
    const size = whole(ra.listSize);
    const expected = f.pointerWidth ? LIST_RECORD_BYTES[f.pointerWidth] : null;
    if (!Number.isSafeInteger(size) || size < 1) errors['readyArray.listSize'] = m.error.listSizeNumber;
    else if (expected !== null && size !== expected) errors['readyArray.listSize'] = m.error.listSize(expected);
    const symbolSize = ra.symbolSize.trim() ? whole(ra.symbolSize) : null;
    if (symbolSize !== null && !Number.isSafeInteger(symbolSize)) errors['readyArray.symbolSize'] = m.error.symbolSize;
    else if (symbolSize !== null && Number.isSafeInteger(n) && Number.isSafeInteger(size) && symbolSize !== n * size)
      errors['readyArray.symbolSize'] = m.error.symbolSizeMismatch(symbolSize, n, size);
    if (arrayBase !== null && Number.isSafeInteger(n) && Number.isSafeInteger(size)) {
      readyListArray = { base: arrayBase, maxPriorities: n, listSize: size, symbolSize };
      for (let p = 0; p < Math.min(n, MAX_READY_LISTS); p++) taken.add(arrayBase + p * size);
    }
  }
  const state: Partial<Record<StateListField, number>> = {};
  for (const key of STATE_LIST_FIELDS) {
    if (!f[key].trim()) continue;
    const address = addr(f[key]);
    if (address === null) errors[key] = m.error.address(bits);
    else if (taken.has(address)) errors[key] = m.error.addressRepeated(hex(address));
    else {
      taken.add(address);
      state[key] = address;
    }
  }
  const delayedLists = [
    ...(state.delayedList !== undefined ? [{ name: 'pxDelayedTaskList', address: state.delayedList }] : []),
    ...(state.overflowDelayedList !== undefined
      ? [{ name: 'pxOverflowDelayedTaskList', address: state.overflowDelayedList }]
      : []),
  ];

  if (Object.keys(errors).length > 0 || !f.bytes || base === null) return { ok: false, errors };
  return {
    ok: true,
    input: {
      memory: {
        base,
        endian: f.endian as 'little' | 'big',
        pointerWidth: Number(f.pointerWidth) as 4 | 8,
        bytesBase64: toBase64(f.bytes),
      },
      symbols: {
        pxCurrentTCB,
        ...(readyListArray ? { readyListArray } : { readyLists }),
        ...(delayedLists.length > 0 ? { delayedLists } : {}),
        ...(state.suspendedList !== undefined ? { suspendedList: state.suspendedList } : {}),
        ...(state.pendingReadyList !== undefined ? { pendingReadyList: state.pendingReadyList } : {}),
        ...(state.terminatedList !== undefined ? { terminatedList: state.terminatedList } : {}),
      },
    },
  };
}

function toBase64(bytes: Uint8Array): string {
  let bin = '';
  // Chunked: spreading 512 KiB into one fromCharCode call overflows the argument limit.
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

/** Form field ← the kernel symbol it is filled from. The delayed lists are deliberately absent (see the header). */
const ELF_PREFILL_FIELDS = [
  ['pxCurrentTCB', 'pxCurrentTCB', 'pxCurrentTCB'],
  ['suspendedList', 'suspendedList', 'xSuspendedTaskList'],
  ['pendingReadyList', 'pendingReadyList', 'xPendingReadyList'],
  ['terminatedList', 'terminatedList', 'xTasksWaitingTermination'],
] as const;

/**
 * Pure: the form with every field whose symbol RESOLVED filled in, and the symbol names filled. A field is filled
 * only when the API's pre-fill carries an address AND the symbol's own status is `resolved` — an ambiguous, absent
 * or unexamined name leaves the field exactly as the analyst left it.
 */
export function applyElfPrefill(
  form: SnapshotForm,
  elf: RtosElfSymbolsResult | null | undefined,
): { form: SnapshotForm; filled: string[] } {
  const prefill = elf?.prefill;
  if (!prefill) return { form, filled: [] };
  const next = { ...form };
  const filled: string[] = [];
  for (const [field, key, symbol] of ELF_PREFILL_FIELDS) {
    const address = prefill[key];
    const status = elf?.symbols?.find((s) => s.name === symbol)?.status;
    if (typeof address !== 'number' || status !== 'resolved') continue;
    next[field] = hex(address);
    filled.push(symbol);
  }
  // The array's address and st_size only — configMAX_PRIORITIES and sizeof(List_t) stay what the analyst typed.
  const array = prefill.readyListArray;
  const readyStatus = elf?.symbols?.find((s) => s.name === 'pxReadyTasksLists')?.status;
  if (typeof array?.base === 'number' && readyStatus === 'resolved') {
    next.readyArray = {
      ...form.readyArray,
      base: hex(array.base),
      ...(typeof array.symbolSize === 'number' ? { symbolSize: String(array.symbolSize) } : {}),
    };
    filled.push('pxReadyTasksLists');
  }
  return { form: next, filled };
}

/** The array's numbers in reading order: the two declared facts, then the optional cross-check. */
const ARRAY_NUMBERS = ['maxPriorities', 'listSize', 'symbolSize'] as const;

const hex = (n: number | null | undefined) => (typeof n === 'number' ? `0x${n.toString(16)}` : '—');
const COVERAGE_CLASS = { complete: 'badge-ok', partial: 'badge-warn', none: 'badge' } as const;

export function RtosTaskSnapshotPanel({
  imageId,
  firmwareClass,
}: { imageId: string; firmwareClass?: string | undefined }): JSX.Element {
  const m = useMessages().rtosTasks;
  const [form, setForm] = useState<SnapshotForm>(EMPTY_FORM);
  const [errors, setErrors] = useState<FormErrors>({});
  const [result, setResult] = useState<RtosTaskSnapshotResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [refused, setRefused] = useState<{ error: string; details: string[] } | null>(null);
  const [runError, setRunError] = useState<string | null>(null);
  const timer = useRef<number | null>(null);
  const rowKey = useRef(0);
  const [rowKeys, setRowKeys] = useState<number[]>([]);
  const [elf, setElf] = useState<RtosElfSymbolsResult | null>(null);
  const [elfBusy, setElfBusy] = useState(false);
  const [elfError, setElfError] = useState<string | null>(null);
  const [elfFilled, setElfFilled] = useState<string[] | null>(null);
  const elfTimer = useRef<number | null>(null);
  const [ramCapture, setRamCapture] = useState<RenodeRamCaptureResult | null>(null);
  const [ramBusy, setRamBusy] = useState(false);
  const [ramError, setRamError] = useState<string | null>(null);
  const [ramLoaded, setRamLoaded] = useState(false);
  const [ramSeconds, setRamSeconds] = useState(2);
  const ramTimer = useRef<number | null>(null);

  useEffect(() => {
    api
      .rtosTasksResult(imageId)
      .then(setResult)
      // Unreadable reads as "not run", never as a snapshot with no tasks.
      .catch(() => setResult(null))
      .finally(() => setLoading(false));
    // A stored read is SHOWN, never applied: filling the form is the analyst's explicit action.
    api
      .rtosElfSymbolsResult(imageId)
      .then(setElf)
      .catch(() => setElf(null));
    api
      .renodeRamCaptureResult(imageId)
      .then(setRamCapture)
      .catch(() => setRamCapture(null));
    return () => {
      if (timer.current) window.clearInterval(timer.current);
      if (elfTimer.current) window.clearInterval(elfTimer.current);
      if (ramTimer.current) window.clearInterval(ramTimer.current);
    };
  }, [imageId]);

  const loadRamIntoForm = (cap: RenodeRamCaptureResult | null) => {
    if (!cap?.captured || !cap.bytesBase64 || !cap.region) return;
    try {
      const bin = atob(cap.bytesBase64);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      setForm((f) => ({
        ...f,
        bytes,
        base: hex(cap.region?.base),
        endian: cap.layout?.endian ?? f.endian,
        pointerWidth: cap.layout?.pointerWidth ? (String(cap.layout.pointerWidth) as '4' | '8') : f.pointerWidth,
      }));
      setErrors((e) => {
        const { file: _drop, base: _b, endian: _end, pointerWidth: _pw, ...rest } = e;
        return rest;
      });
      setRamLoaded(true);
    } catch {
      setRamError(m.ramCapture.failed);
    }
  };

  const captureRam = async () => {
    setRamBusy(true);
    setRamError(null);
    setRamLoaded(false);
    try {
      const { jobId } = await api.runRenodeRamCapture(imageId, { seconds: ramSeconds });
      ramTimer.current = window.setInterval(async () => {
        try {
          const j = await api.job(jobId);
          if (j.status !== 'done' && j.status !== 'error' && j.status !== 'cancelled') return;
          if (ramTimer.current) window.clearInterval(ramTimer.current);
          setRamBusy(false);
          if (j.status === 'done') {
            const cap = j.result as RenodeRamCaptureResult;
            setRamCapture(cap);
            if (cap.captured) {
              loadRamIntoForm(cap);
            }
          } else if (j.status === 'error') {
            setRamError(j.error ?? m.ramCapture.failed);
          }
        } catch (err) {
          if (ramTimer.current) window.clearInterval(ramTimer.current);
          setRamBusy(false);
          setRamError(err instanceof Error ? err.message : m.ramCapture.failed);
        }
      }, 900);
    } catch (err) {
      setRamBusy(false);
      setRamError(err instanceof Error ? err.message : m.ramCapture.failed);
    }
  };

  const fillFromElf = (read: RtosElfSymbolsResult | null) => {
    const { filled } = applyElfPrefill(EMPTY_FORM, read);
    setForm((f) => applyElfPrefill(f, read).form);
    setErrors((e) => Object.fromEntries(Object.entries(e).filter(([k]) => !filled.some((n) => fieldFor(n) === k))));
    setElfFilled(filled);
  };

  const readElf = async () => {
    setElfBusy(true);
    setElfError(null);
    setElfFilled(null);
    try {
      const { jobId } = await api.runRtosElfSymbols(imageId);
      elfTimer.current = window.setInterval(async () => {
        try {
          const j = await api.job(jobId);
          if (j.status !== 'done' && j.status !== 'error' && j.status !== 'cancelled') return;
          if (elfTimer.current) window.clearInterval(elfTimer.current);
          setElfBusy(false);
          if (j.status === 'done') {
            const read = j.result as RtosElfSymbolsResult;
            setElf(read);
            fillFromElf(read);
          } else if (j.status === 'error') setElfError(j.error ?? m.elfSymbols.failed);
        } catch (err) {
          if (elfTimer.current) window.clearInterval(elfTimer.current);
          setElfBusy(false);
          setElfError(err instanceof Error ? err.message : m.elfSymbols.failed);
        }
      }, 900);
    } catch (err) {
      setElfBusy(false);
      setElfError(err instanceof Error ? err.message : m.elfSymbols.failed);
    }
  };

  const set = <K extends keyof SnapshotForm>(key: K, value: SnapshotForm[K]) =>
    setForm((f) => ({ ...f, [key]: value }));

  const onFile = async (file: File | undefined) => {
    setErrors(({ file: _drop, ...rest }) => rest);
    if (!file) return set('bytes', null);
    // Refuse before reading: there is no reason to pull a 2 GB dump into the tab to say it is too large.
    if (file.size > MAX_SNAPSHOT_BYTES) {
      set('bytes', null);
      setErrors((e) => ({ ...e, file: m.error.fileTooLarge(file.size, MAX_SNAPSHOT_BYTES / 1024) }));
      return;
    }
    try {
      set('bytes', new Uint8Array(await file.arrayBuffer()));
    } catch (e) {
      set('bytes', null);
      setErrors((prev) => ({ ...prev, file: m.error.fileRead(e instanceof Error ? e.message : String(e)) }));
    }
  };

  const setList = (i: number, key: 'priority' | 'address', value: string) =>
    set(
      'readyLists',
      form.readyLists.map((l, j) => (j === i ? { ...l, [key]: value } : l)),
    );

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const built = buildSnapshotRequest(form, m);
    if (!built.ok) return setErrors(built.errors);
    setErrors({});
    setRefused(null);
    setRunError(null);
    setBusy(true);
    try {
      const started = await api.runRtosTasks(imageId, built.input);
      if ('refused' in started) {
        setRefused(started.refused);
        setBusy(false);
        return;
      }
      timer.current = window.setInterval(async () => {
        try {
          const j = await api.job(started.jobId);
          if (j.status !== 'done' && j.status !== 'error' && j.status !== 'cancelled') return;
          if (timer.current) window.clearInterval(timer.current);
          setBusy(false);
          if (j.status === 'done') setResult(j.result as RtosTaskSnapshotResult);
          else if (j.status === 'error') setRunError(j.error ?? m.runFailed);
        } catch (err) {
          if (timer.current) window.clearInterval(timer.current);
          setBusy(false);
          setRunError(err instanceof Error ? err.message : m.runFailed);
        }
      }, 900);
    } catch (err) {
      setBusy(false);
      setRunError(err instanceof Error ? err.message : m.runFailed);
    }
  };

  const fieldProps = (key: string) => ({
    'aria-invalid': errors[key] ? true : undefined,
    'aria-describedby': errors[key] ? `rtos-tasks-err-${key}` : undefined,
  });
  const fieldError = (key: string) =>
    errors[key] ? (
      <div id={`rtos-tasks-err-${key}`} className="hint" role="alert" style={{ color: 'var(--danger)' }}>
        {errors[key]}
      </div>
    ) : null;
  const id = (name: string) => `rtos-tasks-${name}`;
  const hasErrors = Object.keys(errors).length > 0;

  const body = (
    <>
      <div className="panel-sub" style={{ maxWidth: '72ch' }}>
        {m.sub}
      </div>

      <ElfSymbols
        elf={elf}
        busy={elfBusy}
        error={elfError}
        filled={elfFilled}
        onRead={() => void readElf()}
        onFill={() => fillFromElf(elf)}
        m={m.elfSymbols}
      />

      <RenodeRamCaptureView
        capture={ramCapture}
        busy={ramBusy}
        error={ramError}
        loaded={ramLoaded}
        seconds={ramSeconds}
        onSecondsChange={setRamSeconds}
        onCapture={() => void captureRam()}
        onLoad={() => loadRamIntoForm(ramCapture)}
        m={m.ramCapture}
      />

      <form onSubmit={submit} noValidate style={{ display: 'grid', gap: 12, marginTop: 14, maxWidth: '72ch' }}>
        <div>
          <label className="eyebrow" htmlFor={id('file')}>
            {m.field.file}
          </label>
          <input
            id={id('file')}
            type="file"
            className="input"
            style={{ paddingTop: 6 }}
            onChange={(e) => void onFile(e.target.files?.[0])}
            {...fieldProps('file')}
          />
          <div className="hint">
            {form.bytes ? m.field.fileLoaded(form.bytes.length) : m.field.fileHint(MAX_SNAPSHOT_BYTES / 1024)}
          </div>
          {fieldError('file')}
        </div>

        <div style={{ display: 'grid', gap: 12, gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))' }}>
          <div>
            <label className="eyebrow" htmlFor={id('base')}>
              {m.field.base}
            </label>
            <input
              id={id('base')}
              className="input mono"
              value={form.base}
              placeholder="0x20000000"
              onChange={(e) => set('base', e.target.value)}
              {...fieldProps('base')}
            />
            {fieldError('base')}
          </div>
          <div>
            <label className="eyebrow" htmlFor={id('endian')}>
              {m.field.endian}
            </label>
            <select
              id={id('endian')}
              className="select"
              value={form.endian}
              onChange={(e) => set('endian', e.target.value as SnapshotForm['endian'])}
              {...fieldProps('endian')}
            >
              <option value="">{m.field.endianChoose}</option>
              <option value="little">{m.field.little}</option>
              <option value="big">{m.field.big}</option>
            </select>
            {fieldError('endian')}
          </div>
          <div>
            <label className="eyebrow" htmlFor={id('pointerWidth')}>
              {m.field.pointerWidth}
            </label>
            <select
              id={id('pointerWidth')}
              className="select"
              value={form.pointerWidth}
              onChange={(e) => set('pointerWidth', e.target.value as SnapshotForm['pointerWidth'])}
              {...fieldProps('pointerWidth')}
            >
              <option value="">{m.field.pointerChoose}</option>
              <option value="4">{m.field.bytes(4)}</option>
              <option value="8">{m.field.bytes(8)}</option>
            </select>
            {fieldError('pointerWidth')}
          </div>
        </div>
        <div className="hint">
          {m.field.addressHint} {m.field.layoutHint}
        </div>

        <div>
          <label className="eyebrow" htmlFor={id('pxCurrentTCB')}>
            {m.field.pxCurrentTCB}
          </label>
          <input
            id={id('pxCurrentTCB')}
            className="input mono"
            value={form.pxCurrentTCB}
            onChange={(e) => set('pxCurrentTCB', e.target.value)}
            {...fieldProps('pxCurrentTCB')}
          />
          {fieldError('pxCurrentTCB')}
        </div>

        <fieldset style={{ border: 0, padding: 0, margin: 0, display: 'grid', gap: 8 }}>
          <legend className="eyebrow">{m.field.readyLists}</legend>
          <div className="hint">{m.field.readyListsHint(MAX_READY_LISTS)}</div>
          {form.readyLists.map((l, i) => (
            <div
              key={rowKeys[i]}
              style={{ display: 'grid', gap: 8, gridTemplateColumns: '110px 1fr auto', alignItems: 'start' }}
            >
              <div>
                <label className="sr-only" htmlFor={id(`p${i}`)}>
                  {`${m.field.priority} ${i + 1}`}
                </label>
                <input
                  id={id(`p${i}`)}
                  className="input mono"
                  inputMode="numeric"
                  placeholder={m.field.priority}
                  value={l.priority}
                  onChange={(e) => setList(i, 'priority', e.target.value)}
                  {...fieldProps(`readyLists.${i}.priority`)}
                />
                {fieldError(`readyLists.${i}.priority`)}
              </div>
              <div>
                <label className="sr-only" htmlFor={id(`a${i}`)}>
                  {`${m.field.address} ${i + 1}`}
                </label>
                <input
                  id={id(`a${i}`)}
                  className="input mono"
                  placeholder={m.field.address}
                  value={l.address}
                  onChange={(e) => setList(i, 'address', e.target.value)}
                  {...fieldProps(`readyLists.${i}.address`)}
                />
                {fieldError(`readyLists.${i}.address`)}
              </div>
              <button
                type="button"
                className="btn btn-sm btn-ghost"
                aria-label={m.field.removeList(i + 1)}
                onClick={() => {
                  // Errors are keyed by row index; removing a row shifts every later one, so drop them all.
                  setErrors({});
                  set(
                    'readyLists',
                    form.readyLists.filter((_, j) => j !== i),
                  );
                  setRowKeys((k) => k.filter((_, j) => j !== i));
                }}
              >
                ✕
              </button>
            </div>
          ))}
          {fieldError('readyLists')}
          <div>
            <button
              type="button"
              className="btn btn-sm"
              disabled={form.readyLists.length >= MAX_READY_LISTS}
              onClick={() => {
                set('readyLists', [...form.readyLists, { priority: '', address: '' }]);
                setRowKeys((k) => [...k, rowKey.current++]);
              }}
            >
              {m.field.addList}
            </button>
          </div>
        </fieldset>

        <fieldset style={{ border: 0, padding: 0, margin: 0, display: 'grid', gap: 8 }}>
          <legend className="eyebrow">{m.field.readyArray}</legend>
          <div className="hint">{m.field.readyArrayHint}</div>
          <div>
            <label className="eyebrow" htmlFor={id('array-base')}>
              {m.field.arrayBase}
            </label>
            <input
              id={id('array-base')}
              className="input mono"
              placeholder="0x20000100"
              value={form.readyArray.base}
              onChange={(e) => set('readyArray', { ...form.readyArray, base: e.target.value })}
              {...fieldProps('readyArray.base')}
            />
            {fieldError('readyArray.base')}
          </div>
          <div style={{ display: 'grid', gap: 12, gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))' }}>
            {ARRAY_NUMBERS.map((key) => (
              <div key={key}>
                <label className="eyebrow" htmlFor={id(`array-${key}`)}>
                  {m.field[key]}
                </label>
                <input
                  id={id(`array-${key}`)}
                  className="input mono"
                  inputMode="numeric"
                  value={form.readyArray[key]}
                  onChange={(e) => set('readyArray', { ...form.readyArray, [key]: e.target.value })}
                  {...fieldProps(`readyArray.${key}`)}
                />
                {fieldError(`readyArray.${key}`)}
              </div>
            ))}
          </div>
          {fieldError('readyArray')}
        </fieldset>

        <fieldset style={{ border: 0, padding: 0, margin: 0, display: 'grid', gap: 8 }}>
          <legend className="eyebrow">{m.field.stateLists}</legend>
          <div className="hint">{m.field.stateListsHint}</div>
          <div style={{ display: 'grid', gap: 12, gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))' }}>
            {STATE_LIST_FIELDS.map((key) => (
              <div key={key}>
                <label className="eyebrow" htmlFor={id(key)}>
                  {m.field[key]}
                </label>
                <input
                  id={id(key)}
                  className="input mono"
                  placeholder={m.field.address}
                  value={form[key]}
                  onChange={(e) => set(key, e.target.value)}
                  {...fieldProps(key)}
                />
                {fieldError(key)}
              </div>
            ))}
          </div>
          <div className="hint">{m.field.delayedHint}</div>
        </fieldset>

        {hasErrors && (
          <div className="banner banner-warn" role="alert">
            {m.error.fixFields}
          </div>
        )}
        <div>
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {busy ? (
              <>
                <span className="spinner" /> {m.running}
              </>
            ) : result ? (
              m.rerun
            ) : (
              m.run
            )}
          </button>
        </div>
      </form>

      {refused && (
        <div className="banner banner-warn" style={{ marginTop: 12 }}>
          <span className="eyebrow">{m.refusedHeading}</span>
          <p style={{ margin: '4px 0 0', maxWidth: '72ch' }}>{refused.error}</p>
          {refused.details.length > 0 && (
            <ul style={{ margin: '6px 0 0', paddingLeft: 18 }}>
              {refused.details.map((d) => (
                <li key={d} className="mono">
                  {d}
                </li>
              ))}
            </ul>
          )}
          <p className="hint" style={{ margin: '6px 0 0', maxWidth: '72ch' }}>
            {m.refusedHint}
          </p>
        </div>
      )}
      {runError && (
        <div className="banner banner-warn" style={{ marginTop: 12 }}>
          <span className="eyebrow">{m.runFailedHeading}</span>
          <p style={{ margin: '4px 0 0', maxWidth: '72ch' }}>{runError}</p>
          <p className="hint" style={{ margin: '6px 0 0', maxWidth: '72ch' }}>
            {m.runFailedHint}
          </p>
        </div>
      )}

      {loading ? (
        <div className="skeleton" style={{ height: 80, marginTop: 14 }} />
      ) : result ? (
        <SnapshotResult result={result} m={m} />
      ) : (
        !busy && (
          <div className="hint" style={{ marginTop: 14, maxWidth: '72ch' }}>
            {m.notRun}
          </div>
        )
      )}
    </>
  );

  if (firmwareClass === 'rtos' || firmwareClass === 'baremetal') {
    return (
      <section className="panel">
        <div className="panel-title">{m.title}</div>
        {body}
      </section>
    );
  }
  return (
    <details className="panel">
      {/* `list-item` keeps the disclosure triangle, which `panel-title`'s block display removed: folded, the panel
          read as a heading with nothing under it. The hint sits in the summary so it is visible while folded. */}
      <summary className="panel-title" style={{ cursor: 'pointer', display: 'list-item' }}>
        {m.title}
        <span className="hint" style={{ display: 'block', maxWidth: '72ch', fontWeight: 400, marginTop: 4 }}>
          {m.collapsedHint}
        </span>
      </summary>
      {body}
    </details>
  );
}

function SnapshotResult({ result, m }: { result: RtosTaskSnapshotResult; m: M }): JSX.Element {
  const snap = result.snapshot;
  const limits = result.limits;
  const cur = result.currentTask;
  const lanes = result.readyLists ?? [];
  const array = result.readyListArray;
  const pair = (done?: number, tried?: number) => `${done ?? '—'} / ${tried ?? '—'}`;
  return (
    <section style={{ marginTop: 16 }} aria-label={m.result.heading}>
      <div className="eyebrow">{m.result.heading}</div>
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap', marginTop: 6 }}>
        <span className="eyebrow">{m.result.coverage}</span>
        {result.coverage ? (
          <span className={`badge ${COVERAGE_CLASS[result.coverage]}`}>{m.result.coverageValue[result.coverage]}</span>
        ) : (
          <span className="badge">{m.result.notRecorded}</span>
        )}
        {/* Pinned by the API: the snapshot is operator input, so this is a lead however complete the walk. */}
        <ProofStateBadge state={result.proofState ?? 'needs_runtime_reproduction'} />
      </div>
      {result.summary && <p style={{ margin: '8px 0 0', maxWidth: '72ch', fontWeight: 500 }}>{result.summary}</p>}
      <p className="hint" style={{ margin: '6px 0 0', maxWidth: '72ch' }}>
        {m.result.proofLead}
      </p>
      {snap && (
        <p className="hint mono" style={{ margin: '6px 0 0' }}>
          {m.result.snapshot(hex(snap.base), snap.endian ?? '?', snap.pointerWidth ?? 0, snap.bytesSupplied ?? 0)}
        </p>
      )}
      {array && typeof array.base === 'number' && (
        <p className="hint" style={{ margin: '6px 0 0', maxWidth: '72ch' }}>
          {m.result.readyArray(
            hex(array.base),
            array.maxPriorities ?? 0,
            array.listSize ?? 0,
            array.sizeCrossCheck === 'agrees',
          )}
        </p>
      )}

      <div className="table-wrap" style={{ marginTop: 12 }}>
        <table className="data" aria-label={m.result.lanes}>
          <thead>
            <tr>
              <th>{m.result.col.lane}</th>
              <th>{m.result.col.priority}</th>
              <th>{m.result.col.coverage}</th>
              <th>{m.result.col.nodes}</th>
              <th>{m.result.col.bytes}</th>
              <th>{m.result.col.tasks}</th>
            </tr>
          </thead>
          <tbody>
            {cur && (
              <tr>
                <td className="mono">
                  {m.result.currentLane} @ {hex(cur.pxCurrentTcbAddress)}
                </td>
                <td>—</td>
                <LaneCoverage coverage={cur.coverage} evidence={cur.evidence} m={m} />
                <td>—</td>
                <td className="mono">{pair(cur.bytesCompleted, cur.bytesAttempted)}</td>
                <td className="mono">{typeof cur.tcbAddress === 'number' ? hex(cur.tcbAddress) : m.result.noTasks}</td>
              </tr>
            )}
            {lanes.map((lane: RtosTaskLane, i) => (
              <tr key={`${lane.priority ?? 'none'}-${i}`}>
                <td className="mono">
                  {lane.listAddress == null ? m.result.noListSupplied : m.result.readyLane(hex(lane.listAddress))}
                </td>
                <td className="mono">{lane.priority ?? '—'}</td>
                <LaneCoverage coverage={lane.coverage} evidence={lane.evidence} m={m} />
                <td className="mono">{pair(lane.completed, lane.attempted)}</td>
                <td className="mono">{pair(lane.bytesCompleted, lane.bytesAttempted)}</td>
                <td className="mono">
                  {lane.tasks && lane.tasks.length > 0
                    ? lane.tasks.map((t) => hex(t.tcbAddress)).join(' ')
                    : m.result.noTasks}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <StateLists result={result} m={m} />

      {limits && (
        <p className="hint" style={{ margin: '8px 0 0', maxWidth: '72ch' }}>
          {m.result.limits((limits.maxSnapshotBytes ?? 0) / 1024, limits.maxListItems ?? 0, limits.maxReadyLists ?? 0)}
        </p>
      )}
    </section>
  );
}

/**
 * The non-ready lanes. Rendered only for lanes the result carries: a stored result from before these lanes existed
 * has none, and the "not walked" line then comes from `unwalkedKinds` when present — never inferred from absence.
 */
function StateLists({ result, m }: { result: RtosTaskSnapshotResult; m: M }): JSX.Element | null {
  const lanes: RtosNamedListLane[] = [
    ...(result.delayedLists ?? []),
    ...(result.suspendedList ? [result.suspendedList] : []),
    ...(result.pendingReadyList ? [result.pendingReadyList] : []),
    ...(result.terminatedList ? [result.terminatedList] : []),
  ];
  const unwalked = result.unwalkedKinds ?? [];
  const several = result.tcbsOnSeveralLists ?? [];
  if (lanes.length === 0 && unwalked.length === 0 && several.length === 0) return null;
  const pair = (done?: number, tried?: number) => `${done ?? '—'} / ${tried ?? '—'}`;
  const oneDelayed = (result.delayedLists?.length ?? 0) === 1;
  return (
    <>
      {several.length > 0 && (
        <div className="banner banner-warn" role="alert" style={{ marginTop: 12, maxWidth: '72ch' }}>
          {m.result.severalLists(several.length, several.map((t) => hex(t)).join(' '))}
        </div>
      )}
      {lanes.length > 0 && (
        <div className="table-wrap" style={{ marginTop: 12 }}>
          <table className="data" aria-label={m.result.stateLanes}>
            <thead>
              <tr>
                <th>{m.result.col.lane}</th>
                <th>{m.result.col.state}</th>
                <th>{m.result.col.coverage}</th>
                <th>{m.result.col.nodes}</th>
                <th>{m.result.col.bytes}</th>
                <th>{m.result.col.tasks}</th>
              </tr>
            </thead>
            <tbody>
              {lanes.map((lane, i) => (
                <tr key={`${lane.kind ?? 'list'}-${lane.listAddress ?? 'none'}-${i}`}>
                  <td className="mono">{m.result.stateLane(lane.name ?? '?', hex(lane.listAddress))}</td>
                  <td>{lane.kind ? m.result.kind[lane.kind] : m.result.notRecorded}</td>
                  <LaneCoverage coverage={lane.coverage} evidence={lane.evidence} m={m} />
                  <td className="mono">{pair(lane.completed, lane.attempted)}</td>
                  <td className="mono">{pair(lane.bytesCompleted, lane.bytesAttempted)}</td>
                  <td className="mono">
                    {lane.tasks && lane.tasks.length > 0 ? (
                      lane.itemValueMeaning === 'wake_tick' ? (
                        <ul style={{ margin: 0, paddingLeft: 0, listStyle: 'none' }}>
                          {lane.tasks.map((t, j) => (
                            <li key={`${t.listItemAddress ?? j}`}>
                              {m.result.wakeTick(hex(t.tcbAddress), t.itemValue ?? '—')}
                            </li>
                          ))}
                        </ul>
                      ) : (
                        lane.tasks.map((t) => hex(t.tcbAddress)).join(' ')
                      )
                    ) : (
                      m.result.noTasks
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {unwalked.length > 0 && (
        <p className="hint" style={{ margin: '8px 0 0', maxWidth: '72ch' }}>
          {m.result.notWalked(
            unwalked.map((k) => (k === 'delayed' && oneDelayed ? m.result.secondDelayed : m.result.kind[k])).join(', '),
          )}
        </p>
      )}
    </>
  );
}

function LaneCoverage({
  coverage,
  evidence,
  m,
}: { coverage?: string | undefined; evidence?: string[] | undefined; m: M }): JSX.Element {
  return (
    <td>
      <span className={`badge mono ${coverage === 'complete' ? 'badge-ok' : 'badge-warn'}`}>
        {coverage ?? m.result.notRecorded}
      </span>
      {/* Why the walk ended where it did — the provider's own audit trail. */}
      {evidence && evidence.length > 0 && (
        <div className="hint" style={{ fontSize: 11, marginTop: 3 }}>
          {evidence.join(' · ')}
        </div>
      )}
    </td>
  );
}

/** The form field an ELF-filled symbol lands in, so its stale validation error can be cleared. */
function fieldFor(symbol: string): string | undefined {
  return ELF_PREFILL_FIELDS.find(([, , name]) => name === symbol)?.[0];
}

const ELF_STATUS_CLASS: Record<RtosElfSymbolStatus, string> = {
  resolved: 'badge-ok',
  ambiguous: 'badge-warn',
  absent: '',
  'not-examined': 'badge-warn',
  'undefined-only': '',
  unavailable: '',
};

/**
 * The ELF symbol read: an explicit action, the verdict as a stated reason, and every kernel name with its status.
 * A non-`symbols-read` verdict is a warning about where the addresses must come from, never a negative about the
 * kernel; the per-symbol table is shown only when a static symbol table was actually read.
 */
function ElfSymbols({
  elf,
  busy,
  error,
  filled,
  onRead,
  onFill,
  m,
}: {
  elf: RtosElfSymbolsResult | null;
  busy: boolean;
  error: string | null;
  filled: string[] | null;
  onRead: () => void;
  onFill: () => void;
  m: M['elfSymbols'];
}): JSX.Element {
  const verdict = elf?.verdict;
  const read = verdict === 'symbols-read';
  const id = elf?.identity;
  const symbols = elf?.symbols ?? [];
  return (
    <section aria-label={m.heading} style={{ marginTop: 14, maxWidth: '72ch', display: 'grid', gap: 8 }}>
      <div className="eyebrow">{m.heading}</div>
      <div className="hint">{m.intro}</div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <button type="button" className="btn btn-sm" disabled={busy} onClick={onRead}>
          {busy ? (
            <>
              <span className="spinner" /> {m.reading}
            </>
          ) : elf ? (
            m.reread
          ) : (
            m.read
          )}
        </button>
        {elf?.prefill && !busy && (
          <button type="button" className="btn btn-sm btn-ghost" onClick={onFill}>
            {m.fill}
          </button>
        )}
      </div>
      {error && (
        <div className="banner banner-warn">
          <span className="eyebrow">{m.failed}</span>
          <p style={{ margin: '4px 0 0' }}>{error}</p>
        </div>
      )}
      {filled && <output className="hint">{filled.length > 0 ? m.filled(filled.join(', ')) : m.filledNone}</output>}
      {!elf ? (
        !busy && <div className="hint">{m.notRun}</div>
      ) : (
        <>
          {verdict && (
            <div className={read ? 'hint' : 'banner banner-warn'} style={read ? { fontWeight: 500 } : undefined}>
              {m.verdict[verdict]}
            </div>
          )}
          {elf.summary && <p style={{ margin: 0 }}>{elf.summary}</p>}
          {elf.refusal?.detail && (
            <p className="hint mono" style={{ margin: 0 }}>
              {elf.refusal.code ? `${elf.refusal.code}: ` : ''}
              {elf.refusal.detail}
            </p>
          )}
          {id && (
            <p className="hint" style={{ margin: 0 }}>
              {m.identity(
                id.elfClass ?? '?',
                id.endian ?? '?',
                id.pointerWidth ?? 0,
                id.machineName ?? (id.machine === undefined ? '?' : String(id.machine)),
              )}
            </p>
          )}
          {read && symbols.length > 0 && (
            <div className="table-wrap">
              <table className="data" aria-label={m.symbolsTable}>
                <thead>
                  <tr>
                    <th>{m.col.name}</th>
                    <th>{m.col.status}</th>
                    <th>{m.col.address}</th>
                    <th>{m.col.size}</th>
                    <th>{m.col.binding}</th>
                  </tr>
                </thead>
                <tbody>
                  {symbols.map((s, i) => {
                    const candidates = s.candidates ?? [];
                    return (
                      <tr key={s.name ?? i}>
                        <td className="mono">
                          {s.name ?? '?'}
                          {s.variant === 'smp' && (
                            <span className="badge" style={{ marginLeft: 6 }}>
                              {m.smp}
                            </span>
                          )}
                        </td>
                        <td>
                          <span className={`badge ${s.status ? ELF_STATUS_CLASS[s.status] : ''}`}>
                            {s.status ? m.status[s.status] : '—'}
                          </span>
                          {s.note && (
                            <div className="hint" style={{ fontSize: 11, marginTop: 3 }}>
                              {s.note}
                            </div>
                          )}
                        </td>
                        <td className="mono">
                          {candidates.length > 0
                            ? candidates
                                .map((c) => (typeof c.address === 'number' ? hex(c.address) : (c.valueHex ?? '—')))
                                .join(' · ')
                            : '—'}
                        </td>
                        <td className="mono">{candidates.map((c) => c.sizeHex ?? '—').join(' · ') || '—'}</td>
                        <td>{candidates.map((c) => c.binding ?? '—').join(' · ') || '—'}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
          {read && <div className="hint">{m.delayedNotFilled}</div>}
          <div className="hint">{m.readyManual}</div>
          {(elf.notCarried?.length ?? 0) > 0 && (
            <div>
              <div className="eyebrow">{m.notCarried}</div>
              <ul className="hint" style={{ margin: '4px 0 0', paddingLeft: 18 }}>
                {elf.notCarried?.map((n, i) => (
                  <li key={n.name ?? i}>
                    <span className="mono">{n.name ?? '?'}</span>: {n.reason ?? '—'}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </section>
  );
}

/** A stated refusal replaces the generic unavailable warning; older results may carry neither field. */
export function hasRamCaptureRefusal(capture: RenodeRamCaptureResult | null): boolean {
  return capture?.captured === false && Boolean(capture.reason);
}

function RenodeRamCaptureView({
  capture,
  busy,
  error,
  loaded,
  seconds,
  onSecondsChange,
  onCapture,
  onLoad,
  m,
}: {
  capture: RenodeRamCaptureResult | null;
  busy: boolean;
  error: string | null;
  loaded: boolean;
  seconds: number;
  onSecondsChange: (sec: number) => void;
  onCapture: () => void;
  onLoad: () => void;
  m: M['ramCapture'];
}): JSX.Element {
  const cap = capture;
  const captured = Boolean(cap?.captured && cap?.bytesBase64 && cap?.region);
  const refused = hasRamCaptureRefusal(cap);
  return (
    <section aria-label={m.heading} style={{ marginTop: 14, maxWidth: '72ch', display: 'grid', gap: 8 }}>
      <div className="eyebrow">{m.heading}</div>
      <div className="hint">{m.intro}</div>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <button type="button" className="btn btn-sm" disabled={busy} onClick={onCapture}>
          {busy ? (
            <>
              <span className="spinner" /> {m.capturing}
            </>
          ) : cap ? (
            m.recapture
          ) : (
            m.capture
          )}
        </button>
        <label className="hint" style={{ display: 'inline-flex', alignItems: 'center', gap: 6, margin: 0 }}>
          <span>{m.secondsLabel}:</span>
          <input
            type="number"
            className="input input-sm mono"
            style={{ width: 64 }}
            min={1}
            max={30}
            value={seconds}
            disabled={busy}
            onChange={(e) => {
              const val = Number.parseInt(e.target.value, 10);
              if (Number.isInteger(val) && val >= 1 && val <= 30) onSecondsChange(val);
            }}
          />
        </label>
        {captured && !busy && (
          <button type="button" className="btn btn-sm btn-ghost" onClick={onLoad}>
            {m.loadIntoForm}
          </button>
        )}
      </div>
      {error && (
        <div className="banner banner-warn">
          <span className="eyebrow">{m.failed}</span>
          <p style={{ margin: '4px 0 0' }}>{error}</p>
        </div>
      )}
      {loaded && <output className="hint">{m.loadedIntoForm}</output>}
      {!cap ? (
        !busy && <div className="hint">{m.notRun}</div>
      ) : (
        <>
          {cap.available === false && !refused && <div className="banner banner-warn">{m.notAvailable}</div>}
          {captured && cap.region && (
            <div className="banner banner-ok">
              <span className="eyebrow">{m.capturedHeading}</span>
              <p style={{ margin: '4px 0 0' }}>
                {m.capturedSummary(
                  cap.region.name ?? 'sram',
                  hex(cap.region.base),
                  cap.bytesCaptured ?? 0,
                  cap.secondsRun ?? cap.seconds ?? 2,
                )}
              </p>
              {cap.platform && (
                <p className="hint mono" style={{ margin: '4px 0 0' }}>
                  {m.platform(cap.platform)}
                </p>
              )}
            </div>
          )}
          {refused && (
            <div className="banner banner-warn">
              <span className="eyebrow">{m.refused}</span>
              <p style={{ margin: '4px 0 0' }}>{cap.reason}</p>
            </div>
          )}
          {cap.remoteResourcesRefused && cap.remoteResourcesRefused.length > 0 && (
            <p className="hint mono" style={{ margin: 0 }}>
              {m.remoteRefused(cap.remoteResourcesRefused.length)}
            </p>
          )}
        </>
      )}
    </section>
  );
}
