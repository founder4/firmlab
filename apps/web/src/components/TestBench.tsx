/**
 * The test bench — every executable question in this workbench, organised by WHAT it was asked about.
 *
 * It replaces two sections that were organised by tool ("Binaries", "Emulation"), which is the wrong axis for the
 * question an operator actually has. Three probes against three binaries used to show one result: the routes each
 * answered with `listJobs().find(…)`, the most recent run of that kind, so the other two existed only in the
 * database. Nothing said three had happened, what they were aimed at, or what they returned.
 *
 * Three rules drive the layout.
 *
 * 1. **A run button states its cost and its prerequisites before it is pressed.** The dynamic probe needs sink
 *    ADDRESSES, which only a reachability run produces; pressing it without one used to return a 400 explaining
 *    that after the fact. Here the prerequisite is visible, and when a reachability run has already produced
 *    addresses the probe is offered per-sink with the address filled in — the chain becomes one click instead of
 *    a rejection.
 * 2. **Every run is kept and shown.** Runs are listed per target, newest first, with the question asked, the bound
 *    it ran under, and what came back.
 * 3. **Status and outcome are never collapsed.** `done` says the process finished; it says nothing about what was
 *    learned. A probe blocked because the sandbox lacks `/dev/nvram` finished successfully and answered nothing,
 *    and rendering that as an empty result is the conflation this whole workbench exists to prevent.
 *
 * The prose lives in the `testbench` namespace, and rule 3 is the reason it has to: `outcome.means` is the claim,
 * so a translation that lets `empty` read as "nothing is there" or `blocked` read as a clean result would undo the
 * surface. Target paths, sink names, addresses, architectures and the proof ceiling are identifiers and stay put.
 */
import { useCallback, useEffect, useMemo, useState } from 'react';
import { type BinaryEntry, type EmulationMenu, type RunSummary, type SymReachResult, api } from '../api';
import { type Messages, useMessages } from '../i18n';

/** Purely presentational: which dot and badge colour an outcome gets. Not prose, so not in the catalogue. */
const OUTCOME_CLASS: Record<RunSummary['outcome'], string> = {
  proven: 'run-proven',
  lead: 'run-lead',
  empty: 'run-empty',
  blocked: 'run-blocked',
  failed: 'run-failed',
  running: 'run-running',
};

function ago(ts: number, m: Messages['testbench']): string {
  const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
  if (s < 60) return m.ago.seconds(s);
  if (s < 3600) return m.ago.minutes(Math.round(s / 60));
  if (s < 86400) return m.ago.hours(Math.round(s / 3600));
  return m.ago.days(Math.round(s / 86400));
}

/** Kinds whose label IS a tool name. Never translated, so never in the catalogue. */
const TOOL_KIND: Record<string, string> = { renode: 'Renode' };

/** The kind is an identifier the API chose; an unknown one prints as sent rather than as a blank. */
const kindLabel = (kind: string, m: Messages['testbench']): string =>
  TOOL_KIND[kind] ?? (m.kind as Record<string, string>)[kind] ?? kind;

function RunRow({ run, onOpen }: { run: RunSummary; onOpen: (r: RunSummary) => void }): JSX.Element {
  const t = useMessages();
  const cls = OUTCOME_CLASS[run.outcome];
  return (
    <button
      type="button"
      className="run-row"
      onClick={() => onOpen(run)}
      title={t.testbench.outcome.means[run.outcome]}
    >
      <span className={`run-dot ${cls}`} aria-hidden="true" />
      <span className="run-kind">{kindLabel(run.kind, t.testbench)}</span>
      {run.question && <span className="run-question mono">{run.question}</span>}
      <span className="run-headline">{run.headline}</span>
      <span className="run-tail">
        {run.bound && <span className="run-bound">{run.bound}</span>}
        <span className={`badge ${cls}`}>{t.testbench.outcome.label[run.outcome]}</span>
        <time dateTime={new Date(run.startedAt).toISOString()}>{ago(run.startedAt, t.testbench)}</time>
      </span>
    </button>
  );
}

export function TestBench({ imageId }: { imageId: string }): JSX.Element {
  const t = useMessages();
  const [binaries, setBinaries] = useState<BinaryEntry[]>([]);
  const [menu, setMenu] = useState<EmulationMenu | null>(null);
  const [ledger, setLedger] = useState<RunSummary[]>([]);
  const [open, setOpen] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [log, setLog] = useState<{ target: string; text: string } | null>(null);
  const [detail, setDetail] = useState<{ run: RunSummary; result: unknown; log: string } | null>(null);
  /** The job just launched from here, followed through the ledger so its state outlives this component. */
  const [active, setActive] = useState<{ jobId: string; target: string } | null>(null);
  /** Sink addresses harvested from finished reachability runs, so the probe can be offered pre-filled. */
  const [addresses, setAddresses] = useState<Record<string, { sink: string; address: string }[]>>({});

  const refresh = useCallback(() => {
    api
      .runs(imageId, { scope: 'targeted' })
      .then((l) => setLedger(l.runs))
      .catch(() => setLedger([]));
  }, [imageId]);

  useEffect(() => {
    api
      .binaries(imageId)
      .then(setBinaries)
      .catch(() => setBinaries([]));
    api
      .emulation(imageId)
      .then(setMenu)
      .catch(() => setMenu(null));
    refresh();
  }, [imageId, refresh]);

  // Harvest addresses from every reachability run that proved something. This is what turns the dynamic probe's
  // hidden prerequisite into a visible, pre-filled action.
  useEffect(() => {
    const proven = ledger.filter((r) => r.kind === 'symreach' && r.outcome === 'proven' && r.target);
    for (const run of proven) {
      const key = run.target as string;
      if (addresses[key]) continue;
      api
        .runDetail(imageId, run.jobId)
        .then((d) => {
          const sinks = ((d.result as SymReachResult | null)?.sinks ?? []).filter(
            (s) => s.outcome === 'reached' && s.addresses.length > 0,
          );
          if (sinks.length === 0) return;
          setAddresses((prev) => ({
            ...prev,
            [key]: sinks.map((s) => ({ sink: s.sink, address: s.addresses[0] as string })),
          }));
        })
        .catch(() => undefined);
    }
  }, [ledger, imageId, addresses]);

  const runsByTarget = useMemo(() => {
    const m = new Map<string, RunSummary[]>();
    for (const r of ledger) {
      if (!r.target) continue;
      const list = m.get(r.target);
      if (list) list.push(r);
      else m.set(r.target, [r]);
    }
    return m;
  }, [ledger]);

  const rootfsReady = menu?.rootfsReady ?? false;
  const arch = menu?.capabilities?.arch ?? menu?.identity?.arch ?? null;
  const archKnown = Boolean(arch && arch !== 'unknown');

  const rows = useMemo(() => {
    const q = filter.trim().toLowerCase();
    // Binaries that have been run against sort first — that is where the operator left off.
    const scored = binaries.map((b) => ({ b, runs: runsByTarget.get(b.path) ?? [] }));
    return scored
      .filter(({ b }) => !q || b.path.toLowerCase().includes(q))
      .sort((x, y) => (y.runs.length ? 1 : 0) - (x.runs.length ? 1 : 0) || x.b.path.localeCompare(y.b.path));
  }, [binaries, runsByTarget, filter]);

  const totalRuns = ledger.length;
  const withRuns = rows.filter((r) => r.runs.length > 0).length;

  const launch = useCallback(
    async (target: string, what: 'decompile' | 'symreach' | 'dynprobe', extra?: { sink: string; address: string }) => {
      setBusy(`${target}:${what}`);
      setLog(null);
      try {
        const started =
          what === 'decompile'
            ? await api.decompile(imageId, target)
            : what === 'symreach'
              ? await api.symreach(imageId, { binary: target })
              : await api.dynprobe(imageId, {
                  binary: target,
                  sink: extra?.sink ?? '',
                  addresses: extra ? [extra.address] : [],
                });
        setActive({ jobId: (started as { jobId: string }).jobId, target });
        refresh();
      } catch (err) {
        setLog({ target, text: err instanceof Error ? err.message : String(err) });
        setActive(null);
      } finally {
        // The button stops being busy as soon as the job EXISTS. From here the row is driven by the ledger, so
        // the state survives navigating away — it lives in the database, not in this component.
        setBusy(null);
      }
    },
    [imageId, refresh],
  );

  /**
   * Follow running work through the ledger rather than through one job handle.
   *
   * The first version blocked in a `for` loop over `api.job(jobId)`, which meant a run only existed while this
   * component stayed mounted: navigating away lost the log tail, and a ten-minute fuzz lost it entirely. The job
   * itself always survived — it is a row in SQLite — so the fix is to read that row instead of holding it in the
   * browser. Polling stops on its own when nothing is running, so an idle bench makes no requests.
   */
  useEffect(() => {
    const running = ledger.some((r) => r.outcome === 'running');
    if (!running && !active) return;
    const timer = window.setInterval(() => {
      refresh();
      if (active) {
        api
          .runDetail(imageId, active.jobId)
          .then((d) => {
            setLog({ target: active.target, text: d.log ?? '' });
            if (d.summary.outcome !== 'running') setActive(null);
          })
          .catch(() => setActive(null));
      }
    }, 2000);
    return () => window.clearInterval(timer);
  }, [ledger, active, imageId, refresh]);

  if (!rootfsReady && binaries.length === 0) {
    return (
      <div className="panel">
        <div className="panel-title">{t.sections.testbench}</div>
        <div className="empty">
          <div className="empty-mark">0x—</div>
          <div className="empty-title">{t.testbench.noRootfsTitle}</div>
          <div className="empty-body">{t.testbench.noRootfsBody}</div>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="panel">
        <div className="panel-title">{t.sections.testbench}</div>
        <div className="panel-sub">{t.testbench.sub(binaries.length, totalRuns, withRuns)}</div>

        {/* What the bench can do right now, and what each gap costs. Stated once, up front, rather than as a
            rejection after a button is pressed. */}
        <div className="bench-ready">
          <span className={`bench-fact ${rootfsReady ? 'is-ok' : 'is-off'}`}>
            <b>{t.testbench.ready.filesystem}</b>{' '}
            {rootfsReady ? t.testbench.ready.filesystemOk : t.testbench.ready.filesystemOff}
          </span>
          <span className={`bench-fact ${archKnown ? 'is-ok' : 'is-off'}`}>
            <b>{t.testbench.ready.arch}</b> {archKnown ? (arch as string) : t.testbench.ready.archOff}
          </span>
          <span className="bench-fact">
            <b>{t.testbench.ready.ceiling}</b> {menu?.capabilities?.proofCeiling ?? 'static_confirmed'}{' '}
            {t.testbench.ready.ceilingNote}
          </span>
        </div>

        <label className="bench-filter">
          <span className="hint">{t.testbench.filterLabel}</span>
          <input
            className="input"
            value={filter}
            placeholder={t.testbench.filterPlaceholder}
            onChange={(e) => setFilter(e.target.value)}
          />
        </label>
      </div>

      {rows.length === 0 && (
        <div className="panel">
          <div className="empty">
            <div className="empty-mark">0x—</div>
            <div className="empty-title">{t.testbench.noMatchTitle(filter)}</div>
            <div className="empty-body">{t.testbench.noMatchBody(binaries.length)}</div>
          </div>
        </div>
      )}

      {rows.map(({ b, runs }) => {
        const isOpen = open === b.path;
        const known = addresses[b.path] ?? [];
        const best = runs.find((r) => r.outcome === 'proven') ?? runs[0];
        return (
          <div className={`panel bench-target${isOpen ? ' is-open' : ''}`} key={b.path}>
            <button
              type="button"
              className="bench-head"
              aria-expanded={isOpen}
              onClick={() => setOpen(isOpen ? null : b.path)}
            >
              <span className="bench-path mono">{b.path}</span>
              <span className="bench-meta">
                {b.arch ?? t.testbench.archUnknown}
                {b.networkFacing ? t.testbench.networkFacing : ''}
              </span>
              <span className="bench-state">
                {runs.length === 0 ? (
                  <span className="hint">{t.testbench.notExamined}</span>
                ) : (
                  <>
                    <span className={`badge ${OUTCOME_CLASS[(best as RunSummary).outcome]}`}>
                      {t.testbench.outcome.label[(best as RunSummary).outcome]}
                    </span>
                    <span className="hint">{t.testbench.runCount(runs.length)}</span>
                  </>
                )}
              </span>
            </button>

            {isOpen && (
              <div className="bench-body">
                {runs.length > 0 ? (
                  <div className="run-list">
                    {runs.map((r) => (
                      <RunRow
                        key={r.jobId}
                        run={r}
                        onOpen={(run) =>
                          api
                            .runDetail(imageId, run.jobId)
                            .then((d) => setDetail({ run, result: d.result, log: d.log }))
                            .catch(() => undefined)
                        }
                      />
                    ))}
                  </div>
                ) : (
                  <p className="bench-none">{t.testbench.nothingRun}</p>
                )}

                <div className="bench-actions">
                  <div className="bench-action">
                    <div className="bench-action-name">{t.testbench.actions.decompile.title}</div>
                    <p className="bench-action-gives">{t.testbench.actions.decompile.gives}</p>
                    <button
                      type="button"
                      className="btn btn-sm"
                      disabled={!rootfsReady || busy !== null}
                      onClick={() => launch(b.path, 'decompile')}
                    >
                      {busy === `${b.path}:decompile` ? t.testbench.running : t.testbench.actions.decompile.run}
                    </button>
                  </div>

                  <div className="bench-action">
                    <div className="bench-action-name">{t.testbench.actions.symreach.title}</div>
                    <p className="bench-action-gives">{t.testbench.actions.symreach.gives}</p>
                    <button
                      type="button"
                      className="btn btn-sm"
                      disabled={!rootfsReady || busy !== null}
                      onClick={() => launch(b.path, 'symreach')}
                    >
                      {busy === `${b.path}:symreach` ? t.testbench.running : t.testbench.actions.symreach.run}
                    </button>
                    <p className="bench-action-note">{t.testbench.actions.symreach.note}</p>
                  </div>

                  <div className="bench-action">
                    <div className="bench-action-name">{t.testbench.actions.dynprobe.title}</div>
                    <p className="bench-action-gives">{t.testbench.actions.dynprobe.gives}</p>
                    {known.length > 0 ? (
                      <div className="bench-probe-list">
                        {known.map((k) => (
                          <button
                            key={k.sink}
                            type="button"
                            className="btn btn-sm btn-primary"
                            disabled={!archKnown || busy !== null}
                            onClick={() => launch(b.path, 'dynprobe', k)}
                          >
                            {busy === `${b.path}:dynprobe`
                              ? t.testbench.running
                              : t.testbench.actions.dynprobe.probeAt(k.sink, k.address)}
                          </button>
                        ))}
                      </div>
                    ) : (
                      <>
                        <button type="button" className="btn btn-sm" disabled>
                          {t.testbench.actions.dynprobe.needsAddress}
                        </button>
                        <p className="bench-action-note">
                          {t.testbench.actions.dynprobe.needsAddressBefore} <b>{t.testbench.actions.symreach.title}</b>
                          {t.testbench.actions.dynprobe.needsAddressAfter}
                        </p>
                      </>
                    )}
                    {!archKnown && <p className="bench-action-note">{t.testbench.actions.dynprobe.noArch}</p>}
                  </div>
                </div>

                {log?.target === b.path && log.text && <pre className="joblog bench-log">{log.text}</pre>}
              </div>
            )}
          </div>
        );
      })}

      {detail && (
        <div className="panel">
          <div className="panel-head">
            <div>
              <div className="panel-title">
                {kindLabel(detail.run.kind, t.testbench)}
                {detail.run.target ? ` · ${detail.run.target}` : ''}
              </div>
              <div className="panel-sub">
                {detail.run.headline} — {t.testbench.outcome.means[detail.run.outcome]}
              </div>
            </div>
            <button type="button" className="btn btn-sm btn-ghost" onClick={() => setDetail(null)}>
              {t.common.close}
            </button>
          </div>
          {detail.log && <pre className="joblog">{detail.log}</pre>}
          <pre className="joblog">{JSON.stringify(detail.result, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}
