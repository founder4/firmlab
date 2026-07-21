/**
 * Fuzzing panel (AFL++) — coverage-guided fuzzing of one rootfs binary under the isolation sandbox. AFL++ is an
 * opt-in layer, so with it absent the panel says so honestly and offers no run. A reproduced crash is real dynamic
 * evidence and is recorded as a confirmed finding in the ledger; a 0-crash run is a valid, honest outcome.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { type FuzzResult, type HarnessClass, type Job, api } from '../api';

export function FuzzPanel({
  imageId,
  suggestedBinary,
}: { imageId: string; suggestedBinary?: string | null }): JSX.Element {
  const [available, setAvailable] = useState<boolean | null>(null);
  const [prior, setPrior] = useState<FuzzResult | null>(null);
  const [binary, setBinary] = useState('');
  const [seconds, setSeconds] = useState(60);
  const [harness, setHarness] = useState<HarnessClass | 'auto'>('auto');
  const [job, setJob] = useState<Job | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const poll = useRef<number | null>(null);

  useEffect(() => {
    api
      .fuzzStatus()
      .then((s) => setAvailable(s.available))
      .catch(() => setAvailable(false));
    api
      .fuzzResult(imageId)
      .then(setPrior)
      .catch(() => setPrior(null));
  }, [imageId]);

  useEffect(
    () => () => {
      if (poll.current) window.clearInterval(poll.current);
    },
    [],
  );

  const run = useCallback(async () => {
    const target = binary || suggestedBinary;
    if (!target) {
      setError('Enter a rootfs binary path to fuzz (e.g. bin/busybox).');
      return;
    }
    setBusy(true);
    setError(null);
    setJob(null);
    try {
      const { jobId } = await api.runFuzz(imageId, target, seconds, harness);
      poll.current = window.setInterval(async () => {
        const j = await api.job(jobId);
        setJob(j);
        if (j.status === 'done' || j.status === 'error') {
          if (poll.current) window.clearInterval(poll.current);
          setBusy(false);
          if (j.status === 'done') setPrior(j.result as FuzzResult);
        }
      }, 900);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }, [imageId, binary, suggestedBinary, seconds, harness]);

  const result = (job?.result as FuzzResult | undefined) ?? prior;

  return (
    <div className="panel" style={{ marginTop: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
        <span style={{ fontSize: 16 }}>🐛</span>
        <strong style={{ fontSize: 13 }}>Coverage-guided fuzzing (AFL++)</strong>
        {available !== null && (
          <span style={{ marginLeft: 'auto' }} className={`badge ${available ? 'badge-ok' : ''}`}>
            {available ? 'runnable' : 'opt-in layer'}
          </span>
        )}
      </div>
      <div className="hint" style={{ marginBottom: 10 }}>
        Fuzz one extracted binary under the isolation sandbox (qemu mode). A reproduced crash is recorded as a confirmed
        finding; finding nothing is an honest result, not a pass.
      </div>

      {available === false ? (
        <div className="hint">
          AFL++ isn't installed in this deployment — enable the opt-in layer in{' '}
          <span className="mono">Dockerfile.firmware</span> (afl-fuzz + afl-qemu-trace). Nothing is faked without it.
        </div>
      ) : (
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
          <input
            className="mono"
            placeholder={suggestedBinary ?? 'bin/busybox'}
            value={binary}
            onChange={(e) => setBinary(e.target.value)}
            style={{
              flex: 1,
              minWidth: 180,
              background: 'var(--bg)',
              border: '1px solid var(--border)',
              borderRadius: 6,
              color: 'var(--text)',
              padding: '6px 10px',
              fontSize: 12,
            }}
          />
          <label className="hint" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <input
              type="number"
              min={10}
              max={600}
              value={seconds}
              onChange={(e) => setSeconds(Math.min(600, Math.max(10, Number(e.target.value) || 60)))}
              className="mono"
              style={{
                width: 68,
                background: 'var(--bg)',
                border: '1px solid var(--border)',
                borderRadius: 6,
                color: 'var(--text)',
                padding: '6px 8px',
                fontSize: 12,
              }}
            />
            s
          </label>
          <select
            aria-label="Harness"
            className="mono"
            value={harness}
            onChange={(e) => setHarness(e.target.value as HarnessClass | 'auto')}
            title="How the fuzzed input reaches the target"
            style={{
              background: 'var(--bg)',
              border: '1px solid var(--border)',
              borderRadius: 6,
              color: 'var(--text)',
              padding: '6px 8px',
              fontSize: 12,
            }}
          >
            <option value="auto">auto</option>
            <option value="file">file (@@)</option>
            <option value="stdin">stdin</option>
            <option value="network">network (desock)</option>
          </select>
          <button className="btn btn-primary btn-sm" disabled={busy || available === null} onClick={run}>
            {busy ? <span className="spinner" /> : 'Fuzz'}
          </button>
        </div>
      )}

      {error && (
        <div className="banner banner-warn" style={{ marginTop: 12 }}>
          {error}
        </div>
      )}

      {result && (
        <div style={{ marginTop: 12 }}>
          <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
            <Stat label="Binary" value={result.binary} mono />
            <Stat label="Harness" value={result.harness} />
            <Stat label="Execs" value={result.execsDone != null ? result.execsDone.toLocaleString() : '—'} />
            <Stat label="Crashes" value={String(result.crashes)} severity={result.crashes > 0 ? 'high' : 'ok'} />
            <Stat label="Isolation" value={result.isolation} />
          </div>
          {result.harnessNote && (
            <div className="hint" style={{ marginTop: 8 }}>
              ℹ {result.harnessNote}
            </div>
          )}
          {result.crashes > 0 && result.crashSamples.length > 0 && (
            <div style={{ marginTop: 10 }}>
              <div className="hint" style={{ marginBottom: 4 }}>
                Crash inputs (first bytes) — a <span className="mono">fuzz-crash</span> finding was recorded:
              </div>
              <table className="data">
                <tbody>
                  {result.crashSamples.map((c) => (
                    <tr key={c.name}>
                      <td className="mono" style={{ fontSize: 11 }}>
                        {c.name.slice(0, 44)}
                      </td>
                      <td className="mono num" style={{ fontSize: 11, color: 'var(--text-dim)' }}>
                        {c.hexPreview}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {result.crashes === 0 && result.available && (
            <div className="hint" style={{ marginTop: 8 }}>
              No crash in the time budget — an honest negative, not a guarantee of safety.
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Stat({
  label,
  value,
  mono,
  severity,
}: {
  label: string;
  value: string;
  mono?: boolean;
  severity?: 'high' | 'ok';
}): JSX.Element {
  return (
    <div>
      <div className="hint" style={{ fontSize: 10.5, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
        {label}
      </div>
      <div
        className={mono ? 'mono' : undefined}
        style={{
          fontSize: 14,
          fontWeight: 600,
          color: severity === 'high' ? 'var(--sev-high)' : severity === 'ok' ? 'var(--ok)' : 'var(--text)',
        }}
      >
        {value}
      </div>
    </div>
  );
}
