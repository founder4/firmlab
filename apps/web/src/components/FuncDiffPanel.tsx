/**
 * Function-level diff against a baseline — the reader and trigger for `POST/GET /api/images/:id/funcdiff`.
 *
 * The provider's hardest-won distinction is that an EMPTY function list means one of three unrelated things: the
 * builds are identical, nothing was comparable, or the builds differ so broadly that the list was withheld as noise.
 * `funcDiffOutcome` decides which from what the result actually carries, and each gets its own sentence — a panel
 * that rendered "0 changed" for all three would state a rebuild as a clean bill of health.
 *
 * The baseline is the image chosen in the Diff section's picker, so this panel never offers a second picker that
 * could disagree with the one above it. This image is the NEWER build, as the route defines it.
 */
import { type JSX, useEffect, useState } from 'react';
import { type FuncDiffBinaryView, type FuncDiffResultView, type Job, api } from '../api';
import { useMessages } from '../i18n';

export type FuncDiffOutcome =
  | 'blocked'
  | 'identical-bytes'
  | 'identical-functions'
  | 'nothing-comparable'
  | 'not-localized'
  | 'changes';

/** Pure: which of the empty-or-not readings a stored result supports. */
export function funcDiffOutcome(r: FuncDiffResultView): FuncDiffOutcome {
  if (!r.available) return 'blocked';
  const diffs = r.diffs ?? [];
  const complete = !r.notAnalyzed;
  if (diffs.some((d) => d.verdict === 'patched')) return 'changes';
  if (diffs.length === 0) {
    // Only "every shared binary hashed equal" licenses identical; zero pairs is nothing comparable.
    return complete && (r.paired ?? 0) > 0 && r.identical === r.paired ? 'identical-bytes' : 'nothing-comparable';
  }
  if (complete && diffs.every((d) => d.verdict === 'identical')) return 'identical-functions';
  if (diffs.some((d) => d.verdict === 'recompiled')) return 'not-localized';
  return 'nothing-comparable';
}

type SortKey = 'binary' | 'name' | 'ninstrs' | 'nbbs' | 'cc' | 'size';
interface Row {
  binary: string;
  name: string;
  ninstrs: number;
  nbbs: number;
  cc: number;
  size: number;
}

function changedRows(diffs: FuncDiffBinaryView[]): Row[] {
  return diffs.flatMap((d) =>
    (d.functions ?? [])
      .filter((f) => f.status === 'changed' && f.delta)
      .map((f) => ({
        binary: d.path,
        name: f.name,
        ninstrs: f.delta?.ninstrs ?? 0,
        nbbs: f.delta?.nbbs ?? 0,
        cc: f.delta?.cc ?? 0,
        size: f.delta?.size ?? 0,
      })),
  );
}

async function waitForJob(jobId: string, onLog: (log: string) => void): Promise<Job> {
  for (;;) {
    const job = await api.job(jobId);
    onLog(job.log);
    if (job.status === 'done' || job.status === 'error') return job;
    await new Promise((resolve) => window.setTimeout(resolve, 900));
  }
}

const sum = (diffs: FuncDiffBinaryView[], k: 'changed' | 'added' | 'removed' | 'unmatchable'): number =>
  diffs.reduce((n, d) => n + (d[k] ?? 0), 0);

export function FuncDiffPanel({ imageId, against }: { imageId: string; against: string }): JSX.Element {
  const t = useMessages();
  const f = t.funcdiff;
  const [result, setResult] = useState<FuncDiffResultView | null>(null);
  const [loading, setLoading] = useState(false);
  const [running, setRunning] = useState(false);
  const [log, setLog] = useState('');
  const [error, setError] = useState('');
  // Default: smallest movement first, which is the provider's own order and the one worth reading.
  const [sort, setSort] = useState<{ key: SortKey; desc: boolean } | null>(null);

  useEffect(() => {
    let alive = true;
    setResult(null);
    setError('');
    if (!against) return () => undefined;
    setLoading(true);
    api
      .funcdiffResult(imageId, against)
      .then((r) => alive && setResult(r))
      .catch(() => alive && setResult(null))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [imageId, against]);

  const run = async (): Promise<void> => {
    if (!against) {
      setError(f.chooseBaseline);
      return;
    }
    setError('');
    setLog('');
    setRunning(true);
    try {
      const { jobId } = await api.runFuncdiff(imageId, against);
      const job = await waitForJob(jobId, setLog);
      if (job.status === 'done') setResult(job.result as FuncDiffResultView);
      else setError(job.error ?? t.imageDetail.job.failed);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setRunning(false);
    }
  };

  const diffs = result?.diffs ?? [];
  const outcome = result ? funcDiffOutcome(result) : null;
  const rows = changedRows(diffs);
  if (sort) {
    const { key, desc } = sort;
    rows.sort((a, b) => {
      const c = key === 'binary' || key === 'name' ? a[key].localeCompare(b[key]) : Math.abs(a[key]) - Math.abs(b[key]);
      return desc ? -c : c;
    });
  }
  const cols: { key: SortKey; label: string }[] = [
    { key: 'binary', label: f.colBinary },
    { key: 'name', label: f.colFunction },
    { key: 'ninstrs', label: f.colInstrs },
    { key: 'nbbs', label: f.colBlocks },
    { key: 'cc', label: f.colCc },
    { key: 'size', label: f.colSize },
  ];
  const signed = (n: number): string => (n > 0 ? `+${n}` : String(n));

  return (
    <div className="panel" data-testid="funcdiff-panel">
      <div className="panel-title">{f.title}</div>
      <div className="panel-sub" style={{ maxWidth: '72ch' }}>
        {f.sub}
      </div>
      <button type="button" className="btn btn-primary" disabled={running} onClick={() => void run()}>
        {running ? (
          <>
            <span className="spinner" /> {f.running}
          </>
        ) : (
          f.run
        )}
      </button>
      {error && (
        <div className="hint" role="alert" style={{ marginTop: 10, maxWidth: '72ch' }}>
          {error}
        </div>
      )}
      {log && (
        <pre
          className="mono"
          style={{ fontSize: 11.5, color: 'var(--text-dim)', whiteSpace: 'pre-wrap', marginTop: 14 }}
        >
          {log}
        </pre>
      )}
      {against && loading && <div className="hint">{f.loading}</div>}
      {against && !loading && !running && !result && <div className="hint">{f.none}</div>}

      {result && outcome && (
        <div data-outcome={outcome} style={{ display: 'grid', gap: 10, marginTop: 14 }}>
          <p style={{ maxWidth: '72ch', margin: 0 }}>
            <strong>
              {outcome === 'blocked'
                ? f.outcome.blocked
                : outcome === 'identical-bytes'
                  ? f.outcome.identicalBytes(result.paired ?? 0)
                  : outcome === 'identical-functions'
                    ? f.outcome.identicalFunctions
                    : outcome === 'not-localized'
                      ? f.outcome.notLocalized
                      : outcome === 'changes'
                        ? f.outcome.changes(sum(diffs, 'changed'), diffs.filter((d) => d.verdict === 'patched').length)
                        : f.outcome.nothingComparable}
            </strong>
          </p>
          {result.available && (
            <>
              <div className="grid grid-2">
                {(['changed', 'added', 'removed', 'unmatchable'] as const).map((k) => (
                  <div key={k} className="stat" data-stat={k}>
                    <div className="stat-label">{k === 'unmatchable' ? f.stats.unmatched : f.stats[k]}</div>
                    <div className="stat-value">{sum(diffs, k)}</div>
                  </div>
                ))}
              </div>
              <div className="hint">
                {f.scope({
                  paired: result.paired ?? 0,
                  identical: result.identical ?? 0,
                  analyzed: result.analyzed ?? 0,
                })}
              </div>
              <div className="hint" data-role="unmatchable" style={{ maxWidth: '72ch' }}>
                {f.unmatchable(sum(diffs, 'unmatchable'))}
              </div>
              {(result.notAnalyzed ?? 0) > 0 && (
                <div className="hint" style={{ maxWidth: '72ch' }}>
                  {f.notAnalyzed(result.notAnalyzed ?? 0)}
                </div>
              )}
              {result.walkTruncated && (
                <div className="hint" style={{ maxWidth: '72ch' }}>
                  {f.walkTruncated}
                </div>
              )}
            </>
          )}
          {result.reason && (
            <div className="hint" style={{ maxWidth: '72ch' }}>
              <strong>{f.reasonLabel}</strong> {result.reason}
            </div>
          )}

          {rows.length > 0 && (
            <>
              <div className="panel-title" style={{ marginTop: 8 }}>
                {f.changedTitle}
              </div>
              <div className="panel-sub">{f.changedSub}</div>
              <div className="table-wrap">
                <table className="data">
                  <thead>
                    <tr>
                      {cols.map((c) => (
                        <th
                          key={c.key}
                          aria-sort={sort?.key === c.key ? (sort.desc ? 'descending' : 'ascending') : 'none'}
                        >
                          <button
                            type="button"
                            className="btn btn-sm btn-ghost"
                            aria-label={f.sortBy(c.label)}
                            onClick={() => setSort((s) => ({ key: c.key, desc: s?.key === c.key ? !s.desc : false }))}
                          >
                            {c.label}
                          </button>
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((r) => (
                      <tr key={`${r.binary}:${r.name}`}>
                        <td className="mono">{r.binary}</td>
                        <td className="mono">{r.name}</td>
                        <td className="mono">{signed(r.ninstrs)}</td>
                        <td className="mono">{signed(r.nbbs)}</td>
                        <td className="mono">{signed(r.cc)}</td>
                        <td className="mono">{signed(r.size)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {diffs.length > 0 && (
            <>
              <div className="panel-title" style={{ marginTop: 8 }}>
                {f.binariesTitle}
              </div>
              <div className="table-wrap">
                <table className="data">
                  <thead>
                    <tr>
                      <th>{f.colBinary}</th>
                      <th>{f.colVerdict}</th>
                      <th>{f.colMatched}</th>
                      <th>{f.colChanged}</th>
                      <th>{f.colUnmatched}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {diffs.map((d) => (
                      <tr key={d.path}>
                        <td className="mono">{d.path}</td>
                        <td>
                          <span className={`badge ${d.verdict === 'patched' ? 'badge-medium' : 'badge-info'}`}>
                            {f.verdict[d.verdict] ?? d.verdict}
                          </span>
                          {d.reason && <div className="hint">{d.reason}</div>}
                        </td>
                        <td className="mono">{d.matched ?? '—'}</td>
                        <td className="mono">{d.changed ?? '—'}</td>
                        <td className="mono">{d.unmatchable ?? '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
