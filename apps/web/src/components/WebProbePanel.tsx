/**
 * Active web-probe panel (FSTM-7) — drive a booted firmware service for command injection / path traversal. Enter
 * the URL of your emulated service (the port a full-system boot forwards, e.g. http://127.0.0.1:8080) and probe it.
 * A reproduced hit is real dynamic evidence (confirmed_in_emulation). Loopback / private targets only — this drives
 * your own sandboxed service, never a third party.
 */
import { useCallback, useRef, useState } from 'react';
import { type WebProbeResult, api } from '../api';

export function WebProbePanel({ imageId }: { imageId: string }): JSX.Element {
  const [url, setUrl] = useState('http://127.0.0.1:8080');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<WebProbeResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const poll = useRef<number | null>(null);

  const run = useCallback(async () => {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const { jobId } = await api.runWebProbe(imageId, url);
      poll.current = window.setInterval(async () => {
        const j = await api.job(jobId);
        if (j.status === 'done' || j.status === 'error') {
          if (poll.current) window.clearInterval(poll.current);
          setBusy(false);
          if (j.status === 'done') setResult(j.result as WebProbeResult);
          else setError(j.error ?? 'probe failed');
        }
      }, 700);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }, [imageId, url]);

  return (
    <div className="panel" style={{ marginTop: 16 }}>
      <div className="panel-title">Active web probe</div>
      <div className="panel-sub">
        Drive a booted service (chroot-service / full-system) for command injection and path traversal. A reproduced hit
        is <span className="mono">confirmed_in_emulation</span> — proves the sandbox, not the device. Loopback / private
        targets only.
      </div>
      <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
        <input
          className="mono"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="http://127.0.0.1:8080"
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
        <button className="btn btn-primary btn-sm" disabled={busy} onClick={run}>
          {busy ? <span className="spinner" /> : 'Probe'}
        </button>
      </div>

      {error && (
        <div className="banner banner-warn" style={{ marginTop: 12 }}>
          {error}
        </div>
      )}

      {result && (
        <div style={{ marginTop: 12 }}>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
            <span className={`badge ${result.available ? 'badge-ok' : 'badge-medium'}`}>
              {result.available ? 'reachable' : 'unreachable'}
            </span>
            <span className="badge">{result.requests} requests</span>
            <span className="badge">{result.points} injection points</span>
            {result.findings.length > 0 && (
              <span className="badge badge-high">{result.findings.length} reproduced</span>
            )}
          </div>
          <div className="hint" style={{ marginTop: 6 }}>
            {result.reason}
          </div>
          {result.findings.map((f) => (
            <div
              key={f.kind + f.title}
              style={{
                display: 'flex',
                gap: 8,
                alignItems: 'baseline',
                background: 'var(--bg)',
                border: '1px solid var(--border-soft)',
                borderRadius: 6,
                padding: '6px 10px',
                marginTop: 6,
              }}
            >
              <span className="badge badge-high">{f.severity}</span>
              <div>
                <div style={{ fontSize: 12.5 }}>{f.title}</div>
                <div className="hint" style={{ marginTop: 2 }}>
                  {f.rationale}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
