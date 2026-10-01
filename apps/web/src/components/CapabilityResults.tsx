/**
 * The five capabilities that had a route and no reader, given one.
 *
 * Compact by design: one row per capability, each stating WHICH of the three states it is in and — when it ran — the
 * coverage numbers that bound what its result covers. That is deliberately not five bespoke panels. What the backlog
 * recorded as lost was not a rich rendering of each provider's payload; it was the fact that `rulesRun` against
 * `rulesInCorpus`, `rulesLost`, `capped` and `unmatchable` reached no screen at all, so a stage that never ran was
 * indistinguishable from one that ran and found nothing. A row that says which of the three it is, with the
 * denominator beside it, closes that. Ghidra additionally exposes its saved, bounded function reconstruction and
 * a discovered-binary picker without changing what the capability coverage claims.
 *
 * Every decision is in `capabilities.ts` and unit-tested without a DOM; this file renders and fetches.
 */
import { type FormEvent, type JSX, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { type BinaryEntry, type FwHuntResultView, type GhidraResult, type Job, api } from '../api';
import {
  type CapabilityId,
  type CapabilityResultBase,
  type CapabilityState,
  capabilityState,
  coverageIsPartial,
  coverageNumbers,
} from '../capabilities';
import { useMessages } from '../i18n';
import { GhidraFunctions } from './GhidraFunctions';

const CAPABILITIES: ReadonlyArray<{ id: CapabilityId; label: string; unlocks: string }> = [
  { id: 'yarascan', label: 'yarascan', unlocks: 'rule-based rootfs scan for known implants, with a corpus you supply' },
  {
    id: 'fwhunt',
    label: 'fwhunt',
    unlocks: 'UEFI implant rules (BlackLotus, LoJax, MoonBounce…) against carved modules',
  },
  { id: 'nvram', label: 'nvram', unlocks: 'the vendor key–value store carved out of flash' },
  { id: 'ghidra', label: 'ghidra', unlocks: 'decompiled pseudocode for one rootfs binary' },
  { id: 'funcdiff', label: 'funcdiff', unlocks: 'function-level diffing against a baseline image' },
  {
    id: 'dynprobe',
    label: 'dynprobe',
    unlocks: 'a crash reproduced under gdb, with the offset at which the input controls the return address',
  },
];

type Loaded = Record<string, CapabilityResultBase | null>;

function fwhuntBatchState(result: CapabilityResultBase | null): {
  current: number;
  total: number;
  scanned: number;
  carved: number;
  canContinue: boolean;
  incomplete: boolean;
  restart: boolean;
  legacy: boolean;
} | null {
  const pass = (result as FwHuntResultView | null)?.modulePass;
  if (!pass) return null;
  const current = pass?.batchIndex;
  const total = pass?.batchCount;
  const scanned = pass.modulesScanned?.length ?? 0;
  const carved = pass.modulesCarved ?? 0;
  if (typeof current !== 'number' || typeof total !== 'number' || total <= 0) {
    return {
      current: 0,
      total: 0,
      scanned,
      carved,
      canContinue: true,
      incomplete: false,
      restart: true,
      legacy: true,
    };
  }
  const record = pass?.batches?.find((batch) => batch.index === current);
  const incomplete = record?.complete === false;
  const completed = new Set(pass?.batchesCompleted ?? []);
  const allComplete = completed.size >= total;
  return {
    current,
    total,
    scanned,
    carved,
    canContinue: true,
    incomplete,
    restart: allComplete,
    legacy: false,
  };
}

async function waitForJob(jobId: string): Promise<Job> {
  for (;;) {
    const job = await api.job(jobId);
    if (job.status === 'done' || job.status === 'error') return job;
    await new Promise((resolve) => window.setTimeout(resolve, 1000));
  }
}

/** The number line for one row. An absent denominator says so instead of being printed as a zero. */
function Coverage({ id, result }: { id: CapabilityId; result: CapabilityResultBase | null }): JSX.Element | null {
  const t = useMessages();
  const c = coverageNumbers(id, result);
  if (c.applied === null && c.denominator === null) {
    return <span className="hint">{t.capabilities.coverage.unknownDenominator}</span>;
  }
  const partial = coverageIsPartial(c);
  return (
    <span style={{ display: 'inline-flex', gap: 10, flexWrap: 'wrap', alignItems: 'baseline' }}>
      <span className="mono" style={{ fontSize: 11.5 }}>
        {c.denominator !== null && c.applied !== null
          ? t.capabilities.coverage.applied({ applied: c.applied, denominator: c.denominator, unit: c.unit })
          : t.capabilities.coverage.appliedOnly({ applied: c.applied ?? 0, unit: c.unit })}
      </span>
      {c.lost !== null && c.lost > 0 && (
        <span className="hint">{t.capabilities.coverage.lost({ lost: c.lost, unit: c.unit })}</span>
      )}
      {partial && (
        <span className="mono" data-partial="true" style={{ fontSize: 11 }}>
          {t.capabilities.coverage.partial}
        </span>
      )}
      {c.denominator === null && <span className="hint">{t.capabilities.coverage.unknownDenominator}</span>}
    </span>
  );
}

/**
 * The latest function diff, found through the job list: its GET needs the baseline id, which only the job's params
 * remember. No done funcdiff job is `null` — "has not run" — never an empty result.
 */
async function latestFuncdiff(imageId: string): Promise<CapabilityResultBase | null> {
  const job = (await api.jobs(imageId)).find((j) => j.kind === 'funcdiff' && j.status === 'done');
  const against = (job?.params as { against?: unknown } | null)?.against;
  return typeof against === 'string' ? api.funcdiffResult(imageId, against) : null;
}

/**
 * Whether this deployment has Ghidra. `null` when the tool list could not be read — then the run stays enabled and
 * the provider answers `available: false` itself, because not knowing is not the same as knowing it is absent.
 */
async function ghidraInstalled(): Promise<boolean | null> {
  const tool = (await api.tools()).tools.find((x) => x.id === 'analyzeHeadless');
  return tool ? tool.available : null;
}

export function CapabilityResults({ imageId }: { imageId: string }): JSX.Element {
  const t = useMessages();
  const [loaded, setLoaded] = useState<Loaded>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [ghidraTool, setGhidraTool] = useState<boolean | null>(null);
  const [ghidraBinary, setGhidraBinary] = useState('');
  const [ghidraError, setGhidraError] = useState('');
  const [binaries, setBinaries] = useState<BinaryEntry[]>([]);
  const [binaryLoadFailed, setBinaryLoadFailed] = useState(false);

  useEffect(() => {
    let live = true;
    setBinaries([]);
    setGhidraBinary('');
    setBinaryLoadFailed(false);
    const load = async (): Promise<void> => {
      try {
        const entries = await api.binaries(imageId);
        if (live) setBinaries(entries);
      } catch {
        if (live) setBinaryLoadFailed(true);
      }
    };
    void load();
    return () => {
      live = false;
    };
  }, [imageId]);

  useEffect(() => {
    let live = true;
    ghidraInstalled()
      .then((v) => live && setGhidraTool(v))
      .catch(() => live && setGhidraTool(null));
    return () => {
      live = false;
    };
  }, []);

  useEffect(() => {
    let live = true;
    // Each result is fetched independently; failure never reads as a clean result. The Ghidra reader also
    // exposes its load error so an unreadable saved decompilation does not silently disappear.
    setLoaded({});
    setGhidraError('');
    const load = async (): Promise<void> => {
      const entries = await Promise.all([
        api
          .yarascanResult(imageId)
          .then((r) => ['yarascan', r] as const)
          .catch(() => ['yarascan', null] as const),
        api
          .fwhuntResult(imageId)
          .then((r) => ['fwhunt', r] as const)
          .catch(() => ['fwhunt', null] as const),
        api
          .nvramResult(imageId)
          .then((r) => ['nvram', r] as const)
          .catch(() => ['nvram', null] as const),
        api
          .ghidraResult(imageId)
          .then((r) => ['ghidra', r] as const)
          .catch((err: unknown) => {
            if (live) setGhidraError(err instanceof Error ? err.message : String(err));
            return ['ghidra', null] as const;
          }),
        api
          .dynprobeResult(imageId)
          .then((r) => ['dynprobe', r] as const)
          .catch(() => ['dynprobe', null] as const),
        latestFuncdiff(imageId)
          .then((r) => ['funcdiff', r] as const)
          .catch(() => ['funcdiff', null] as const),
      ]);
      if (live) setLoaded(Object.fromEntries(entries) as Loaded);
    };
    void load();
    return () => {
      live = false;
    };
  }, [imageId]);

  const run = async (id: CapabilityId): Promise<void> => {
    setBusy(id);
    try {
      if (id === 'yarascan') await api.runYarascan(imageId);
      else if (id === 'fwhunt') {
        const batch = fwhuntBatchState(loaded.fwhunt ?? null);
        const { jobId } = batch?.restart ? await api.runFwhunt(imageId, undefined, true) : await api.runFwhunt(imageId);
        const job = await waitForJob(jobId);
        if (job.status === 'done') {
          const result = await api.fwhuntResult(imageId);
          setLoaded((current) => ({ ...current, fwhunt: result }));
        }
      } else if (id === 'nvram') await api.runNvram(imageId);
    } finally {
      setBusy(null);
    }
  };

  const runGhidra = async (e: FormEvent): Promise<void> => {
    e.preventDefault();
    // The route resolves the path inside the rootfs and refuses an absolute one, so a pasted `/usr/sbin/httpd`
    // is made relative rather than sent to be rejected.
    const binary = ghidraBinary.trim().replace(/^\/+/, '');
    if (!binary) {
      setGhidraError(t.capabilities.ghidra.binaryRequired);
      return;
    }
    setGhidraError('');
    setBusy('ghidra');
    try {
      const { jobId } = await api.ghidra(imageId, binary);
      const job = await waitForJob(jobId);
      if (job.status === 'done') {
        const result = await api.ghidraResult(imageId);
        setLoaded((current) => ({ ...current, ghidra: result }));
      } else setGhidraError(job.error ?? t.imageDetail.job.failed);
    } catch (err) {
      setGhidraError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  return (
    <section data-testid="capability-results" className="panel">
      <h2 className="panel-title">{t.capabilities.heading}</h2>
      <p className="panel-sub" style={{ maxWidth: '72ch' }}>
        {t.capabilities.intro}
      </p>

      <div style={{ display: 'grid', gap: 14 }}>
        {CAPABILITIES.map((cap) => {
          const result = loaded[cap.id] ?? null;
          const state: CapabilityState = capabilityState(result);
          const fwhuntBatch = cap.id === 'fwhunt' ? fwhuntBatchState(result) : null;
          // funcdiff needs a baseline image, so its "nothing here" has a third cause worth naming rather than being
          // reported as a stage nobody ran.
          const notRunBody = cap.id === 'funcdiff' ? t.capabilities.needsBaseline : t.capabilities.states.notRun.body;
          return (
            <div
              key={cap.id}
              data-capability={cap.id}
              data-state={state.kind}
              className="panel-row"
              style={{ display: 'grid', gap: 6 }}
            >
              <div style={{ display: 'flex', gap: 10, alignItems: 'baseline', flexWrap: 'wrap' }}>
                <strong className="mono">{cap.label}</strong>
                <span className="mono" data-role="state" style={{ fontSize: 11 }}>
                  {t.capabilities.states[state.kind === 'not-run' ? 'notRun' : state.kind].label}
                </span>
                {state.kind === 'ran' && <span className="hint">{t.capabilities.findings(state.findingCount)}</span>}
                {state.kind === 'not-run' && (cap.id === 'yarascan' || cap.id === 'fwhunt' || cap.id === 'nvram') && (
                  <button
                    type="button"
                    className="btn btn-sm"
                    onClick={() => void run(cap.id)}
                    disabled={busy === cap.id}
                  >
                    {busy === cap.id ? t.capabilities.running : t.capabilities.run}
                  </button>
                )}
                {cap.id === 'fwhunt' && state.kind === 'ran' && fwhuntBatch?.canContinue && (
                  <button
                    type="button"
                    className="btn btn-sm"
                    onClick={() => void run(cap.id)}
                    disabled={busy === cap.id}
                  >
                    {busy === cap.id
                      ? t.capabilities.running
                      : fwhuntBatch.legacy
                        ? t.capabilities.startCampaign
                        : fwhuntBatch.restart
                          ? t.capabilities.restartCampaign
                          : fwhuntBatch.incomplete
                            ? t.capabilities.resumeBatch
                            : t.capabilities.nextBatch}
                  </button>
                )}
              </div>
              <span className="hint" style={{ maxWidth: '72ch' }}>
                {cap.unlocks}
              </span>
              <span className="hint" style={{ maxWidth: '72ch' }}>
                {state.kind === 'not-run' ? notRunBody : t.capabilities.states[state.kind].body}
              </span>
              {state.kind === 'ran' && <Coverage id={cap.id} result={result} />}
              {cap.id === 'fwhunt' && state.kind === 'ran' && fwhuntBatch && !fwhuntBatch.legacy && (
                <span className="hint" data-role="fwhunt-batch" style={{ maxWidth: '72ch' }}>
                  {t.capabilities.batchCoverage({
                    current: fwhuntBatch.current + 1,
                    total: fwhuntBatch.total,
                    scanned: fwhuntBatch.scanned,
                    carved: fwhuntBatch.carved,
                    incomplete: fwhuntBatch.incomplete,
                  })}
                </span>
              )}
              {state.kind === 'ran' && cap.id === 'dynprobe' && (
                <span className="hint" data-role="control-offset" style={{ maxWidth: '72ch' }}>
                  {typeof (result as { controlOffset?: number | null } | null)?.controlOffset === 'number'
                    ? t.capabilities.controlOffset((result as unknown as { controlOffset: number }).controlOffset)
                    : t.capabilities.controlOffsetNone}
                </span>
              )}
              {cap.id === 'ghidra' && (
                <form onSubmit={(e) => void runGhidra(e)} style={{ display: 'grid', gap: 6, maxWidth: '72ch' }}>
                  {state.kind === 'ran' && (
                    <span className="hint">
                      {t.capabilities.ghidra.lastBinary}{' '}
                      <span className="mono">{(result as { binary?: string } | null)?.binary ?? '—'}</span>
                    </span>
                  )}
                  <label>
                    {t.capabilities.ghidra.selectBinary}
                    <select
                      className="input mono"
                      value={binaries.some((b) => b.path === ghidraBinary) ? ghidraBinary : ''}
                      disabled={ghidraTool === false || busy === 'ghidra'}
                      onChange={(e) => setGhidraBinary(e.target.value)}
                    >
                      <option value="">—</option>
                      {binaries.map((b) => (
                        <option key={b.path} value={b.path}>
                          {b.path}
                          {b.arch ? ` (${b.arch})` : ''}
                        </option>
                      ))}
                    </select>
                  </label>
                  {binaryLoadFailed ? (
                    <span className="hint">{t.capabilities.ghidra.binaryLoadFailed}</span>
                  ) : (
                    binaries.length === 0 && <span className="hint">{t.capabilities.ghidra.noBinaries}</span>
                  )}
                  <label htmlFor="ghidra-binary" className="hint">
                    {t.capabilities.ghidra.binaryLabel}
                  </label>
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    <input
                      id="ghidra-binary"
                      className="input mono"
                      value={ghidraBinary}
                      onChange={(e) => setGhidraBinary(e.target.value)}
                      placeholder="usr/sbin/httpd"
                      aria-invalid={ghidraError === t.capabilities.ghidra.binaryRequired}
                      disabled={ghidraTool === false || busy === 'ghidra'}
                      style={{ flex: '1 1 240px', minWidth: 0 }}
                    />
                    <button type="submit" className="btn" disabled={ghidraTool === false || busy === 'ghidra'}>
                      {busy === 'ghidra' ? (
                        <>
                          <span className="spinner" /> {t.capabilities.running}
                        </>
                      ) : (
                        t.capabilities.ghidra.run
                      )}
                    </button>
                  </div>
                  {ghidraTool === false && (
                    <span className="hint" data-role="ghidra-missing">
                      {t.capabilities.ghidra.notInstalled}
                    </span>
                  )}
                  {ghidraError && (
                    <span className="hint" role="alert">
                      {ghidraError}
                    </span>
                  )}
                  {result && (
                    <GhidraFunctions
                      key={`${imageId}:${(result as GhidraResult).binary}`}
                      result={result as GhidraResult}
                    />
                  )}
                </form>
              )}
              {cap.id === 'funcdiff' && (
                <span className="hint" style={{ maxWidth: '72ch' }}>
                  {state.kind !== 'not-run' && (result as { older?: string } | null)?.older && (
                    <>
                      {t.capabilities.funcdiffBaseline}{' '}
                      <span className="mono">{(result as { older?: string }).older}</span>{' '}
                    </>
                  )}
                  <Link to={`/image/${imageId}/diff`}>{t.capabilities.funcdiffOpen}</Link>
                </span>
              )}
              {state.kind !== 'not-run' && state.reason && (
                <span className="hint" style={{ maxWidth: '72ch' }}>
                  <strong>{t.capabilities.reasonLabel}</strong> <span className="mono">{state.reason}</span>
                </span>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}
