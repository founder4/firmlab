/**
 * Active web-probe panel (FSTM-7) — drive a booted firmware service for command injection / path traversal. Enter
 * the URL of your emulated service (the port a full-system boot forwards, e.g. http://127.0.0.1:8080) and probe it.
 * A manually entered URL produces an observation held at needs_runtime_reproduction; only the probe attached to a
 * live QEMU session can claim confirmed_in_emulation. Targets are restricted to loopback.
 *
 * What that proof state CLAIMS is not re-worded here: the panel prints the code and then the gloss from the shared
 * `proofState` namespace, so "it proves the sandbox, never the physical device" has exactly one wording per language
 * and the panel cannot drift from the ledger. The rungs (`chroot-service`, `full-system`), the finding kinds and the
 * severities are identifiers and render as the prober sent them.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { type WebProbeResult, api } from '../api';
import { useMessages } from '../i18n';
import { RunHistory } from './RunHistory';

export function WebProbePanel({ imageId }: { imageId: string }): JSX.Element {
  const t = useMessages();
  const [url, setUrl] = useState('http://127.0.0.1:8080');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<WebProbeResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const poll = useRef<number | null>(null);
  const generation = useRef(0);

  useEffect(() => {
    const current = ++generation.current;
    setResult(null);
    setError(null);
    setBusy(false);
    api
      .webprobeResult(imageId)
      .then((saved) => {
        if (generation.current === current) setResult(saved);
      })
      .catch((e: unknown) => {
        if (generation.current === current) setError(e instanceof Error ? e.message : String(e));
      });
    return () => {
      generation.current++;
      if (poll.current) window.clearInterval(poll.current);
    };
  }, [imageId]);

  const run = useCallback(async () => {
    const current = ++generation.current;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const { jobId } = await api.runWebProbe(imageId, url);
      if (generation.current !== current) return;
      poll.current = window.setInterval(async () => {
        try {
          const j = await api.job(jobId);
          if (generation.current !== current) return;
          if (j.status !== 'done' && j.status !== 'error') return;
          if (poll.current) window.clearInterval(poll.current);
          setBusy(false);
          if (j.status === 'done') setResult(j.result as WebProbeResult);
          else setError(j.error ?? t.panels.webprobe.probeFailed);
        } catch (e) {
          if (generation.current !== current) return;
          if (poll.current) window.clearInterval(poll.current);
          setBusy(false);
          setError(e instanceof Error ? e.message : String(e));
        }
      }, 700);
    } catch (e) {
      if (generation.current !== current) return;
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }, [imageId, url, t]);

  return (
    <div className="panel" style={{ marginTop: 16 }}>
      <div className="panel-title">{t.panels.webprobe.title}</div>
      <div className="panel-sub">
        {t.panels.webprobe.sub.lead} <span className="mono">needs_runtime_reproduction</span>
        {t.panels.webprobe.sub.means} {t.proofState.meaning.needs_runtime_reproduction} {t.panels.webprobe.sub.tail}
      </div>
      <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
        <input
          className="mono"
          value={url}
          aria-label="URL"
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
          {busy ? <span className="spinner" /> : t.panels.webprobe.probe}
        </button>
      </div>

      {error && (
        <div className="banner banner-warn" style={{ marginTop: 12 }}>
          {error}
        </div>
      )}

      {result && (
        <div style={{ marginTop: 12 }}>
          {(result.probeVersion !== 2 || result.revalidation?.required) && (
            <output className="banner banner-warn">{t.panels.webprobe.legacy}</output>
          )}
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
            <span className={`badge ${result.available ? 'badge-ok' : 'badge-medium'}`}>
              {result.available ? t.panels.webprobe.reachable : t.panels.webprobe.unreachable}
            </span>
            <span className="badge">{t.panels.webprobe.requests(result.requests)}</span>
            <span className="badge">{t.panels.webprobe.points(result.points)}</span>
            {result.findings.length > 0 && (
              <span className="badge badge-high">{t.panels.webprobe.reproduced(result.findings.length)}</span>
            )}
          </div>
          <div className="hint" style={{ marginTop: 6 }}>
            {result.reason}
          </div>
          {result.coverage && (
            <div className="hint" style={{ marginTop: 6 }}>
              {t.panels.webprobe.coverage(
                result.coverage.attemptedPoints,
                result.coverage.plannedPoints,
                result.coverage.completedPoints,
                result.coverage.failedRequests,
              )}{' '}
              {t.panels.webprobe.skipped(
                result.coverage.skippedUnsupportedMethod,
                result.coverage.skippedPointLimit,
                result.coverage.skippedBudget,
              )}
            </div>
          )}
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
                <span className="badge">{result.probeVersion === 2 ? f.proofState : 'needs_runtime_reproduction'}</span>
                <div className="hint" style={{ marginTop: 2 }}>
                  {f.rationale}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
      <RunHistory imageId={imageId} kinds={['webprobe']} label={t.panels.webprobe.runLabel} />
    </div>
  );
}
