/** Image-wide cancellation controls remain visible whichever analysis section the operator is reading. */
import { useEffect, useRef, useState } from 'react';
import { type Job, api } from '../api';
import { useMessages } from '../i18n';

export function isActiveJobStatus(status: Job['status']): boolean {
  return status === 'queued' || status === 'running' || status === 'cancelling';
}

export function ActiveJobs({ imageId }: { imageId: string }): JSX.Element | null {
  const generation = useRef(0);
  const t = useMessages().shell.runHistory;
  const [jobs, setJobs] = useState<Job[]>([]);
  const [requested, setRequested] = useState<string[]>([]);
  const [sending, setSending] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    generation.current++;
    let live = true;
    setRequested([]);
    setSending([]);
    setError(null);
    setJobs([]);
    const load = async () => {
      try {
        const rows = await api.jobs(imageId);
        if (live) setJobs(rows);
      } catch {
        /* Keep the last known state on a transient polling failure. */
      }
    };
    void load();
    const timer = setInterval(load, 1500);
    return () => {
      generation.current++;
      live = false;
      clearInterval(timer);
    };
  }, [imageId]);

  const visible = jobs.filter(
    (job) =>
      isActiveJobStatus(job.status) ||
      (job.status === 'cancelled' && (requested.includes(job.id) || Boolean(job.error))),
  );
  if (visible.length === 0 && !error) return null;
  return (
    <section className="panel" aria-label={t.activeHeading}>
      <div className="panel-title">{t.activeHeading}</div>
      {error && <p role="alert">{error}</p>}
      {visible.map((job) => (
        <div className="run-row is-static" key={job.id}>
          <span
            className={`run-dot ${job.status === 'cancelled' ? 'run-blocked' : 'run-running'}`}
            aria-hidden="true"
          />
          <span className="run-kind">{job.kind}</span>
          <span className="run-question mono">{job.id}</span>
          <span className="run-headline">
            {job.status === 'cancelled' && job.error && <span role="alert">{job.error}</span>}
            <span className="badge">
              {job.status === 'cancelling' ? t.cancelling : job.status === 'cancelled' ? t.cancelled : job.status}
            </span>
          </span>
          <span className="run-tail">
            {(job.status === 'queued' || job.status === 'running') && (
              <button
                type="button"
                className="btn btn-sm"
                disabled={sending.includes(job.id)}
                onClick={async () => {
                  const current = generation.current;
                  setSending((ids) => [...ids, job.id]);
                  setError(null);
                  try {
                    const updated = await api.cancelJob(job.id);
                    if (current !== generation.current) return;
                    setRequested((ids) => [...ids, job.id]);
                    setJobs((rows) => rows.map((row) => (row.id === updated.id ? updated : row)));
                  } catch (err) {
                    if (current === generation.current) setError(err instanceof Error ? err.message : String(err));
                  } finally {
                    if (current === generation.current) setSending((ids) => ids.filter((id) => id !== job.id));
                  }
                }}
              >
                {sending.includes(job.id) ? t.cancelling : t.cancel}
              </button>
            )}
          </span>
        </div>
      ))}
    </section>
  );
}
