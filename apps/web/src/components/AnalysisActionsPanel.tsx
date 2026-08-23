/**
 * The boot/platform workbench.
 *
 * This used to be ten identical launch cards backed only by component-local state. A completed provider therefore
 * looked as if it had never run after every reload, while its actual answer lived much farther down in a collapsed
 * history. This surface now reads the persisted job ledger and the normalized run summaries: action, current state,
 * answer, bound and re-run all live on the same row.
 */
import { useCallback, useEffect, useMemo, useState } from 'react';
import { type AnalysisKind, type Job, type RunSummary, api } from '../api';
import { type Messages, useMessages } from '../i18n';
import { DeepAnalysisDetails } from './DeepAnalysisDetails';
import { RunHistory, ago } from './RunHistory';

type ProviderKind = keyof Messages['shell']['deep']['provider'] & AnalysisKind;
type GroupId = keyof Messages['shell']['deep']['group'];

const PROVIDER_GROUPS: { id: GroupId; kinds: ProviderKind[] }[] = [
  { id: 'boot', kinds: ['uboot', 'devicetree', 'kernel'] },
  { id: 'filesystem', kinds: ['fsaudit', 'certs', 'services'] },
  { id: 'update', kinds: ['updatepath', 'compmap'] },
  { id: 'device', kinds: ['rtos', 'fcc'] },
];

const ICONS: Record<ProviderKind, string> = {
  uboot: '🧰',
  devicetree: '🗺',
  kernel: '🐧',
  fsaudit: '🔎',
  certs: '📜',
  services: '🌐',
  updatepath: '🔐',
  compmap: '🕸',
  rtos: '🔬',
  fcc: '📡',
};

const PROVIDERS: ProviderKind[] = PROVIDER_GROUPS.flatMap((g) => g.kinds);

const OUTCOME_CLASS: Record<RunSummary['outcome'], string> = {
  proven: 'run-proven',
  lead: 'run-lead',
  empty: 'run-empty',
  blocked: 'run-blocked',
  failed: 'run-failed',
  running: 'run-running',
};

function latestByKind<T extends { kind: string }>(rows: T[], stamp: (row: T) => number): Map<string, T> {
  const latest = new Map<string, T>();
  for (const row of rows) {
    const previous = latest.get(row.kind);
    if (!previous || stamp(row) > stamp(previous)) latest.set(row.kind, row);
  }
  return latest;
}

function resultFacts(job: Job | undefined): { findings: number | null; reason: string | null } {
  if (!job?.result || typeof job.result !== 'object') return { findings: null, reason: null };
  const result = job.result as { findings?: unknown; reason?: unknown };
  return {
    findings: Array.isArray(result.findings) ? result.findings.length : null,
    reason: typeof result.reason === 'string' && result.reason.trim() ? result.reason : null,
  };
}

export function AnalysisActionsPanel({ imageId }: { imageId: string }): JSX.Element {
  const t = useMessages();
  const [jobs, setJobs] = useState<Job[]>([]);
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [starting, setStarting] = useState<Partial<Record<ProviderKind, boolean>>>({});
  const [startErrors, setStartErrors] = useState<Partial<Record<ProviderKind, string>>>({});

  const refresh = useCallback(async () => {
    try {
      const [nextJobs, ledger] = await Promise.all([
        api.jobs(imageId),
        api.runs(imageId, { kind: PROVIDERS.join(',') }),
      ]);
      setJobs(nextJobs);
      setRuns(ledger.runs);
      setLoadError(null);
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : String(error));
    } finally {
      setLoaded(true);
    }
  }, [imageId]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const currentJobs = useMemo(() => latestByKind(jobs, (job) => job.createdAt), [jobs]);
  const currentRuns = useMemo(() => latestByKind(runs, (run) => run.startedAt), [runs]);
  const historyKey = useMemo(() => jobs.reduce((latest, job) => Math.max(latest, job.updatedAt), 0), [jobs]);
  const hasActiveJob = PROVIDERS.some((kind) => {
    const status = currentJobs.get(kind)?.status;
    return starting[kind] || status === 'queued' || status === 'running';
  });

  useEffect(() => {
    if (!hasActiveJob) return;
    const timer = window.setInterval(() => void refresh(), 900);
    return () => window.clearInterval(timer);
  }, [hasActiveJob, refresh]);

  const run = useCallback(
    async (kind: ProviderKind) => {
      setStarting((current) => ({ ...current, [kind]: true }));
      setStartErrors((current) => ({ ...current, [kind]: undefined }));
      try {
        await api.runAnalysis(imageId, kind);
        await refresh();
      } catch (error) {
        setStartErrors((current) => ({
          ...current,
          [kind]: error instanceof Error ? error.message : String(error),
        }));
      } finally {
        setStarting((current) => ({ ...current, [kind]: false }));
      }
    },
    [imageId, refresh],
  );

  const counts = PROVIDERS.reduce(
    (count, kind) => {
      const job = currentJobs.get(kind);
      const summary = currentRuns.get(kind);
      if (starting[kind] || job?.status === 'queued' || job?.status === 'running') count.running += 1;
      else if (job?.status === 'error' || summary?.outcome === 'failed' || startErrors[kind]) count.failed += 1;
      else if (job || summary) count.ran += 1;
      else count.pending += 1;
      return count;
    },
    { ran: 0, running: 0, failed: 0, pending: 0 },
  );

  return (
    <section className="panel deep-workbench">
      <div className="deep-workbench-head">
        <div>
          <div className="panel-title">{t.shell.deep.title}</div>
          <div className="panel-sub">{t.shell.deep.sub}</div>
        </div>
        <div className="deep-overview" aria-label={t.shell.deep.overviewLabel}>
          <strong>{t.shell.deep.overview(counts.ran, PROVIDERS.length)}</strong>
          {counts.running > 0 && <span className="badge run-running">{t.shell.deep.running(counts.running)}</span>}
          {counts.failed > 0 && <span className="badge run-failed">{t.shell.deep.errors(counts.failed)}</span>}
          <span className="badge">{t.shell.deep.pending(counts.pending)}</span>
        </div>
      </div>

      {loadError && <div className="banner banner-warn deep-load-error">{t.shell.deep.refreshFailed(loadError)}</div>}

      <div className="deep-provider-groups" aria-busy={!loaded}>
        {PROVIDER_GROUPS.map((group) => (
          <section className="deep-provider-group" key={group.id} aria-labelledby={`deep-group-${group.id}`}>
            <h3 className="deep-group-title" id={`deep-group-${group.id}`}>
              {t.shell.deep.group[group.id]}
            </h3>
            <div className="deep-provider-list">
              {group.kinds.map((kind) => {
                const summary = currentRuns.get(kind);
                // Keep the headline and full result on the same execution. Jobs can finish out of order, so the
                // most recently UPDATED job is not necessarily the most recently STARTED run.
                const job = summary
                  ? (jobs.find((candidate) => candidate.id === summary.jobId) ?? currentJobs.get(kind))
                  : currentJobs.get(kind);
                const facts = resultFacts(job);
                const running = !!starting[kind] || job?.status === 'queued' || job?.status === 'running';
                const error =
                  startErrors[kind] ?? (job?.status === 'error' ? (job.error ?? t.shell.deep.failed) : null);
                const outcome = running ? 'running' : error ? 'failed' : summary?.outcome;
                const meta = outcome ? t.shell.runHistory.outcome[outcome] : null;
                const hasRun = !!job || !!summary;
                const card = t.shell.deep.provider[kind];

                return (
                  <article className={`deep-provider-row${outcome ? ` is-${outcome}` : ''}`} key={kind}>
                    <span className="deep-provider-icon" aria-hidden="true">
                      {ICONS[kind]}
                    </span>
                    <div className="deep-provider-identity">
                      <strong>{card.title}</strong>
                      <p>{card.desc}</p>
                    </div>
                    <div className="deep-provider-result" aria-live="polite">
                      {!loaded && !running ? (
                        <span className="hint">{t.shell.deep.loading}</span>
                      ) : running ? (
                        <>
                          <span className="deep-result-line">
                            <span className="spinner" />
                            <strong>{t.shell.runHistory.outcome.running.label}</strong>
                          </span>
                          <span className="hint">{t.shell.deep.runningBody}</span>
                        </>
                      ) : error ? (
                        <>
                          <span className="deep-result-line">
                            <span className="run-dot run-failed" aria-hidden="true" />
                            <strong>{t.shell.runHistory.outcome.failed.label}</strong>
                          </span>
                          <span className="deep-result-copy">{error}</span>
                        </>
                      ) : summary ? (
                        <>
                          <span className="deep-result-line" title={meta?.means}>
                            <span className={`run-dot ${OUTCOME_CLASS[summary.outcome]}`} aria-hidden="true" />
                            <span className={`badge ${OUTCOME_CLASS[summary.outcome]}`}>{meta?.label}</span>
                            {facts.findings !== null && <span>{t.shell.deep.findings(facts.findings)}</span>}
                          </span>
                          <strong className="deep-result-headline">{summary.headline}</strong>
                          {job?.result !== null && job?.result !== undefined && (
                            <details className="deep-result-details">
                              <summary>{t.shell.deep.resultDetails}</summary>
                              <DeepAnalysisDetails imageId={imageId} kind={kind} value={job.result} />
                              {facts.reason && facts.reason !== summary.headline && (
                                <span className="deep-result-copy">{facts.reason}</span>
                              )}
                            </details>
                          )}
                          <span className="deep-result-meta">
                            {summary.bound && <span>{summary.bound}</span>}
                            <time dateTime={new Date(summary.startedAt).toISOString()}>
                              {t.shell.deep.lastRun(ago(summary.startedAt, t.shell.runHistory.ago))}
                            </time>
                          </span>
                        </>
                      ) : job?.status === 'done' ? (
                        <>
                          <span className="deep-result-line">
                            <span className="run-dot run-empty" aria-hidden="true" />
                            <strong>{t.shell.deep.completed}</strong>
                            {facts.findings !== null && <span>{t.shell.deep.findings(facts.findings)}</span>}
                          </span>
                          {facts.reason && <span className="deep-result-copy">{facts.reason}</span>}
                          {job.result !== null && job.result !== undefined && (
                            <details className="deep-result-details">
                              <summary>{t.shell.deep.resultDetails}</summary>
                              <DeepAnalysisDetails imageId={imageId} kind={kind} value={job.result} />
                            </details>
                          )}
                        </>
                      ) : (
                        <>
                          <strong className="deep-result-idle">{t.shell.deep.notRun}</strong>
                          <span className="hint">{t.shell.deep.notRunBody}</span>
                        </>
                      )}
                    </div>
                    <button
                      type="button"
                      className={`btn btn-sm ${hasRun ? '' : 'btn-primary'}`}
                      disabled={running}
                      aria-label={
                        running
                          ? t.shell.deep.runningProvider(card.title)
                          : hasRun
                            ? t.shell.deep.runAgainProvider(card.title)
                            : t.shell.deep.runProvider(card.title)
                      }
                      onClick={() => void run(kind)}
                    >
                      {running ? (
                        <span className="spinner" aria-hidden="true" />
                      ) : hasRun ? (
                        t.shell.deep.runAgain
                      ) : (
                        t.common.run
                      )}
                    </button>
                  </article>
                );
              })}
            </div>
          </section>
        ))}
      </div>

      <RunHistory imageId={imageId} kinds={PROVIDERS} runKind="deepAnalysis" refreshKey={historyKey} />
    </section>
  );
}
