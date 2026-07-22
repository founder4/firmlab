/**
 * Autonomous scan (opacidad / W9). One button drops the operator out of the manual per-provider clicking: it
 * plans the class-routed worker chain, runs it, and shows the reasoning trace — the plan, each worker's honest
 * outcome, the findings, the attack path, and (crucially) the honest gaps, so "few findings" is never mistaken
 * for "clean". The narrative is composed server-side (deterministically, or via the LLM when configured).
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { type OpacidadResult, api } from '../api';

const STATUS_META: Record<OpacidadResult['steps'][number]['status'], { mark: string; cls: string }> = {
  ran: { mark: '✓', cls: 'badge-ok' },
  degraded: { mark: '⚠', cls: 'badge-medium' },
  skipped: { mark: '–', cls: 'badge' },
  'not-built': { mark: '▢', cls: 'badge' },
};

function sevClass(sev: string): string {
  if (sev === 'critical') return 'badge-crit';
  if (sev === 'high') return 'badge-high';
  if (sev === 'medium') return 'badge-medium';
  return 'badge';
}

export function OpacidadPanel({ imageId }: { imageId: string }): JSX.Element {
  const [result, setResult] = useState<OpacidadResult | null>(null);
  const [running, setRunning] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [log, setLog] = useState<string>('');
  const pollRef = useRef<number | null>(null);

  useEffect(() => {
    api
      .opacidadResult(imageId)
      .then(setResult)
      .catch(() => setResult(null));
    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current);
    };
  }, [imageId]);

  const run = useCallback(async () => {
    setErr(null);
    setRunning(true);
    setLog('');
    try {
      const { jobId } = await api.runOpacidad(imageId);
      pollRef.current = window.setInterval(async () => {
        const job = await api.job(jobId).catch(() => null);
        if (!job) return;
        setLog(job.log ?? '');
        if (job.status === 'done') {
          if (pollRef.current) window.clearInterval(pollRef.current);
          setResult(job.result as OpacidadResult);
          setRunning(false);
        } else if (job.status === 'error') {
          if (pollRef.current) window.clearInterval(pollRef.current);
          setErr(job.error ?? 'Autonomous scan failed');
          setRunning(false);
        }
      }, 800);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
      setRunning(false);
    }
  }, [imageId]);

  return (
    <div className="panel">
      <div className="panel-title">Autonomous scan (opacidad)</div>
      <div className="panel-sub">
        Plan the class-appropriate worker chain, run it end-to-end, and compose the reasoning trace — one action instead
        of clicking each provider by hand. Honest by design: skipped and not-yet-built workers are shown, never hidden.
      </div>

      <div style={{ display: 'flex', gap: 8, marginTop: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <button className="btn btn-primary btn-sm" disabled={running} onClick={run}>
          {running ? 'Scanning…' : result ? 'Re-run autonomous scan' : 'Run autonomous scan'}
        </button>
        {result && (
          <span className="badge prov-agent" title="How the narrative was written">
            narrative: {result.narrativeSource}
            {result.llm ? ` (${result.llm.provider}/${result.llm.model})` : ''}
          </span>
        )}
      </div>

      {err && (
        <div className="banner banner-warn" style={{ marginTop: 10 }}>
          {err}
        </div>
      )}
      {running && log && (
        <pre className="mono" style={logStyle}>
          {log.split('\n').slice(-12).join('\n')}
        </pre>
      )}

      {result && (
        <div style={{ marginTop: 14, display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div>
            <span className="badge badge-accent mono">{result.firmwareClass}</span>{' '}
            <span className="badge mono">{result.arch}</span>
            {result.classRationale && (
              <div className="hint" style={{ marginTop: 6 }}>
                {result.classRationale}
              </div>
            )}
          </div>

          <Section title="Workers">
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
              {result.steps.map((s) => {
                const meta = STATUS_META[s.status];
                return (
                  <div key={s.worker} style={{ ...rowStyle, ...(s.origin === 'replan' ? { marginLeft: 16 } : {}) }}>
                    <span className={`badge ${meta.cls}`} style={{ minWidth: 22, textAlign: 'center' }}>
                      {s.origin === 'replan' ? '↳' : meta.mark}
                    </span>
                    <strong style={{ fontSize: 12.5 }}>{s.worker}</strong>
                    {s.origin === 'replan' && (
                      <span className="badge" style={{ fontSize: 10 }} title={s.trigger}>
                        re-planned
                      </span>
                    )}
                    <span className="hint" style={{ flex: 1 }}>
                      {s.summary}
                      {s.note ? ` — ${s.note}` : ''}
                    </span>
                    {typeof s.findingCount === 'number' && s.findingCount > 0 && (
                      <span className="badge mono">{s.findingCount}</span>
                    )}
                  </div>
                );
              })}
            </div>
          </Section>

          <Section title={`Findings (${result.findings.total})`}>
            {result.findings.top.length === 0 ? (
              <div className="hint">No findings surfaced by the workers that ran.</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {result.findings.top.map((f) => (
                  <div key={`${f.source}:${f.title}`} style={rowStyle}>
                    <span className={`badge ${sevClass(f.severity)}`}>{f.severity}</span>
                    <span style={{ flex: 1, fontSize: 12.5 }}>{f.title}</span>
                    <span className="hint mono">{f.proofState}</span>
                  </div>
                ))}
              </div>
            )}
          </Section>

          {result.attackPath.length > 0 && (
            <Section title="Attack path (chain of evidence)">
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {result.attackPath.map((p) => (
                  <div key={p} className="mono" style={{ fontSize: 12 }}>
                    {p}
                  </div>
                ))}
              </div>
            </Section>
          )}

          <Section title="Narrative">
            <pre className="narrative" style={narrativeStyle}>
              {result.narrative}
            </pre>
          </Section>

          {result.honestGaps.length > 0 && (
            <Section title="Honest gaps — what did NOT run">
              <ul style={{ margin: 0, paddingLeft: 18, display: 'flex', flexDirection: 'column', gap: 4 }}>
                {result.honestGaps.map((g) => (
                  <li key={g} className="hint" style={{ fontSize: 12 }}>
                    {g}
                  </li>
                ))}
              </ul>
            </Section>
          )}
        </div>
      )}
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }): JSX.Element {
  return (
    <div>
      <div className="eyebrow" style={{ marginBottom: 6 }}>
        {title}
      </div>
      {children}
    </div>
  );
}

const rowStyle: React.CSSProperties = {
  display: 'flex',
  gap: 8,
  alignItems: 'center',
  background: 'var(--bg)',
  border: '1px solid var(--border-soft)',
  borderRadius: 6,
  padding: '5px 9px',
};

const logStyle: React.CSSProperties = {
  marginTop: 10,
  fontSize: 11.5,
  background: 'var(--bg)',
  border: '1px solid var(--border-soft)',
  borderRadius: 6,
  padding: '8px 10px',
  maxHeight: 180,
  overflow: 'auto',
  whiteSpace: 'pre-wrap',
};

const narrativeStyle: React.CSSProperties = {
  fontSize: 12.5,
  lineHeight: 1.6,
  background: 'var(--bg)',
  border: '1px solid var(--border-soft)',
  borderRadius: 8,
  padding: '12px 14px',
  whiteSpace: 'pre-wrap',
  fontFamily: 'inherit',
  overflowX: 'auto',
};
