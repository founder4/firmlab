/**
 * Simulation menu — the emulation control surface. Shows the arch/class-aware ranked recipes (user-mode QEMU,
 * full-system QEMU, Renode), whether each is runnable in this deployment, and lets the user launch a user-mode
 * proof against the extracted rootfs, streaming the job log/result.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { type EmulationMenu, type Job, api } from '../api';

const MODE_ICON: Record<string, string> = { 'user-qemu': '▶', 'system-qemu': '🖥', renode: '🔬' };

export function SimulationMenu({ imageId }: { imageId: string }): JSX.Element {
  const [menu, setMenu] = useState<EmulationMenu | null>(null);
  const [job, setJob] = useState<Job | null>(null);
  const [binary, setBinary] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const poll = useRef<number | null>(null);

  const load = useCallback(() => {
    api
      .emulation(imageId)
      .then(setMenu)
      .catch(() => setMenu(null));
  }, [imageId]);
  useEffect(load, [load]);

  useEffect(
    () => () => {
      if (poll.current) window.clearInterval(poll.current);
    },
    [],
  );

  const runUser = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const { jobId } = await api.emulate(imageId, binary || undefined);
      poll.current = window.setInterval(async () => {
        const j = await api.job(jobId);
        setJob(j);
        if (j.status === 'done' || j.status === 'error') {
          if (poll.current) window.clearInterval(poll.current);
          setBusy(false);
        }
      }, 700);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }, [imageId, binary]);

  const extractFirst = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const { jobId } = await api.extract(imageId);
      poll.current = window.setInterval(async () => {
        const j = await api.job(jobId);
        setJob(j);
        if (j.status === 'done' || j.status === 'error') {
          if (poll.current) window.clearInterval(poll.current);
          setBusy(false);
          load();
        }
      }, 800);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }, [imageId, load]);

  if (!menu) return <div className="empty">Loading emulation plan…</div>;

  const result = job?.result as { command?: string; stdout?: string; stderr?: string; timedOut?: boolean } | null;

  return (
    <div>
      {!menu.rootfsReady && (
        <div
          className="banner banner-warn"
          style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
        >
          <span>User-mode emulation needs an extracted rootfs. Run extraction first (requires binwalk).</span>
          <button className="btn btn-sm" disabled={busy} onClick={extractFirst}>
            Extract now
          </button>
        </div>
      )}

      <div className="grid grid-2">
        {menu.recipes.map((r) => (
          <div
            key={r.id}
            className="panel"
            style={{ margin: 0, borderColor: r.runnable ? 'var(--border)' : 'var(--border-soft)' }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
              <span style={{ fontSize: 16 }}>{MODE_ICON[r.mode]}</span>
              <strong style={{ fontSize: 13 }}>{r.title}</strong>
              <span style={{ marginLeft: 'auto' }} className={`badge ${r.runnable ? 'badge-ok' : ''}`}>
                {r.runnable ? 'runnable' : 'needs tools'}
              </span>
            </div>
            <div className="hint" style={{ marginBottom: 10 }}>
              {r.description}
            </div>
            <div
              className="mono"
              style={{
                fontSize: 11.5,
                background: 'var(--bg)',
                border: '1px solid var(--border-soft)',
                borderRadius: 6,
                padding: '8px 10px',
                color: 'var(--text-dim)',
                overflowX: 'auto',
                whiteSpace: 'nowrap',
              }}
            >
              $ {r.command}
            </div>
            {r.notes && (
              <div className="hint" style={{ marginTop: 8 }}>
                ℹ {r.notes}
              </div>
            )}
            {r.mode === 'user-qemu' && r.runnable && (
              <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
                <input
                  className="mono"
                  placeholder={menu.suggestedBinary ?? 'bin/busybox'}
                  value={binary}
                  onChange={(e) => setBinary(e.target.value)}
                  style={{
                    flex: 1,
                    background: 'var(--bg)',
                    border: '1px solid var(--border)',
                    borderRadius: 6,
                    color: 'var(--text)',
                    padding: '6px 10px',
                    fontSize: 12,
                  }}
                />
                <button className="btn btn-primary btn-sm" disabled={busy} onClick={runUser}>
                  {busy ? <span className="spinner" /> : 'Run proof'}
                </button>
              </div>
            )}
          </div>
        ))}
      </div>

      {error && (
        <div className="banner banner-warn" style={{ marginTop: 16 }}>
          {error}
        </div>
      )}

      {job && (
        <div className="panel" style={{ marginTop: 16 }}>
          <div className="panel-title">
            Job {job.id}{' '}
            <span
              className={`badge ${job.status === 'done' ? 'badge-ok' : job.status === 'error' ? 'badge-high' : ''}`}
            >
              {job.status}
            </span>
          </div>
          {job.log && (
            <pre
              className="mono"
              style={{ fontSize: 11.5, color: 'var(--text-dim)', whiteSpace: 'pre-wrap', margin: '8px 0' }}
            >
              {job.log}
            </pre>
          )}
          {result?.command && (
            <>
              {result.timedOut && <div className="badge badge-medium">timed out (likely a long-running daemon)</div>}
              {result.stdout && (
                <pre
                  className="mono"
                  style={{
                    fontSize: 11.5,
                    whiteSpace: 'pre-wrap',
                    background: 'var(--bg)',
                    padding: 10,
                    borderRadius: 6,
                    marginTop: 8,
                  }}
                >
                  {result.stdout.slice(0, 4000)}
                </pre>
              )}
              {result.stderr && (
                <pre
                  className="mono"
                  style={{ fontSize: 11.5, whiteSpace: 'pre-wrap', color: 'var(--warn)', marginTop: 8 }}
                >
                  {result.stderr.slice(0, 2000)}
                </pre>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
