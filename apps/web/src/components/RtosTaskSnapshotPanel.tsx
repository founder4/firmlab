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
 * Folded behind a disclosure on images not classed rtos/baremetal: still usable, never clutter on a Linux image.
 */
import { type JSX, useEffect, useRef, useState } from 'react';
import {
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

type M = Messages['rtosTasks'];

export interface SnapshotForm {
  bytes: Uint8Array | null;
  base: string;
  endian: '' | 'little' | 'big';
  pointerWidth: '' | '4' | '8';
  pxCurrentTCB: string;
  readyLists: { priority: string; address: string }[];
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

  // Every state list is optional; a filled one must be an address no other lane already walks (the API refuses a
  // list walked twice, because its tasks would be counted twice).
  const taken = new Set(readyLists.map((l) => l.address));
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
        readyLists,
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

  useEffect(() => {
    api
      .rtosTasksResult(imageId)
      .then(setResult)
      // Unreadable reads as "not run", never as a snapshot with no tasks.
      .catch(() => setResult(null))
      .finally(() => setLoading(false));
    return () => {
      if (timer.current) window.clearInterval(timer.current);
    };
  }, [imageId]);

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
