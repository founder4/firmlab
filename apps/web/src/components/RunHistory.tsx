/**
 * Every previous run of a provider, wherever that provider's panel lives.
 *
 * The panels each render one result, because their route returns one: `listJobs().find(…)`, the most recent
 * finished job of that kind. That is fine for "show me the current answer" and silently wrong for everything else
 * — a provider re-run after a fix, a scan repeated on a different budget, a run that was blocked and then worked
 * all look identical from outside, which is to say invisible.
 *
 * This is the small shared piece that closes the gap without rewriting each panel: drop it under a result and the
 * runs behind it become readable. It reads the same ledger and the same pure summarizer the test bench does, so a
 * `blocked` run reads as blocked here too rather than as an empty one.
 *
 * Collapsed by default and silent when there is nothing but the current run, so it costs a panel nothing until it
 * has something to say.
 */
import { useEffect, useState } from 'react';
import { type RunSummary, api } from '../api';

const OUTCOME_LABEL: Record<RunSummary['outcome'], { label: string; cls: string; means: string }> = {
  proven: { label: 'proven', cls: 'run-proven', means: 'A fact was established.' },
  lead: { label: 'lead', cls: 'run-lead', means: 'Worth pursuing. Nothing is proven yet.' },
  empty: {
    label: 'nothing found',
    cls: 'run-empty',
    means: 'This run found nothing — for its input, its budget, its question. Not a clean bill of health.',
  },
  blocked: {
    label: 'blocked',
    cls: 'run-blocked',
    means: 'The question was asked and this deployment could not answer it. NOT a negative result.',
  },
  failed: { label: 'failed', cls: 'run-failed', means: 'The harness broke. No statement either way.' },
  running: { label: 'running', cls: 'run-running', means: 'Still going.' },
};

function ago(ts: number): string {
  const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export function RunHistory({
  imageId,
  kinds,
  label,
  refreshKey,
}: {
  imageId: string;
  /** One or more job kinds this panel drives. */
  kinds: string[];
  /** What to call these runs in the operator's words — the panel's own noun, not the job kind. */
  label: string;
  /** Bump to re-read after the panel starts a run of its own. */
  refreshKey?: number;
}): JSX.Element | null {
  const [runs, setRuns] = useState<RunSummary[] | null>(null);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    api
      .runs(imageId, { kind: kinds.join(',') })
      .then((l) => setRuns(l.runs))
      .catch(() => setRuns([]));
  }, [imageId, kinds.join(','), refreshKey]);

  // Nothing to add while there is at most the one run the panel is already showing.
  if (!runs || runs.length < 2) return null;

  return (
    <div className="run-history">
      <button type="button" className="run-history-toggle" aria-expanded={open} onClick={() => setOpen(!open)}>
        <span>
          {runs.length} {label} run{runs.length === 1 ? '' : 's'} on this image
        </span>
        <span className="hint">{open ? 'hide' : 'show'} history — the panel above shows only the most recent</span>
      </button>
      {open && (
        <div className="run-list">
          {runs.map((r) => {
            const meta = OUTCOME_LABEL[r.outcome];
            return (
              <div className="run-row is-static" key={r.jobId} title={meta.means}>
                <span className={`run-dot ${meta.cls}`} aria-hidden="true" />
                <span className="run-kind">{r.target ?? r.kind}</span>
                {r.question && <span className="run-question mono">{r.question}</span>}
                <span className="run-headline">{r.headline}</span>
                <span className="run-tail">
                  {r.bound && <span className="run-bound">{r.bound}</span>}
                  <span className={`badge ${meta.cls}`}>{meta.label}</span>
                  <time dateTime={new Date(r.startedAt).toISOString()}>{ago(r.startedAt)}</time>
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
