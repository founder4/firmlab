/**
 * Autonomous scan (opacidad / W9). One button drops the operator out of the manual per-provider clicking: it
 * plans the class-routed worker chain, runs it, and shows the reasoning trace — the plan, each worker's honest
 * outcome, the findings, the attack path, and (crucially) the honest gaps, so "few findings" is never mistaken
 * for "clean". The narrative is composed server-side (deterministically, or via the LLM when configured).
 *
 * Everything the SERVER decided renders as it was sent: the worker ids, the step statuses, the severities, the
 * proof states, the narrative and the honest gaps are data, and translating any of them would be inventing a
 * value the workbench does not use. What comes from the catalogue is the prose around them — including the gloss
 * on each status mark, which is where the panel says out loud that a `skipped` or `not-built` stage is one
 * nothing was asked of, and therefore never a stage that passed.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { type OpacidadResult, api } from '../api';
import { useMessages } from '../i18n';
import { RunHistory } from './RunHistory';

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
  const t = useMessages();
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
          setErr(job.error ?? t.panels.opacidad.failed);
          setRunning(false);
        }
      }, 800);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
      setRunning(false);
    }
  }, [imageId, t]);

  // The gloss for a proof state lives in the shared `proofState` namespace and is never restated here. A state this
  // build does not know still renders its CODE — only the tooltip goes missing, which is the honest degradation.
  const proofMeaning = (state: string): string | undefined =>
    (t.proofState.meaning as Record<string, string | undefined>)[state];

  return (
    <div className="panel">
      <div className="panel-title">{t.panels.opacidad.title}</div>
      <div className="panel-sub">{t.panels.opacidad.sub}</div>

      <div style={{ display: 'flex', gap: 8, marginTop: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <button className="btn btn-primary btn-sm" disabled={running} onClick={run}>
          {running ? t.panels.opacidad.running : result ? t.panels.opacidad.rerun : t.panels.opacidad.run}
        </button>
        {result && (
          <span className="badge prov-agent" title={t.panels.opacidad.narrativeTitle}>
            {t.panels.opacidad.narrativeLabel} {result.narrativeSource}
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

          <Section title={t.panels.opacidad.workers}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
              {result.steps.map((s) => {
                const meta = STATUS_META[s.status];
                return (
                  <div key={s.worker} style={{ ...rowStyle, ...(s.origin === 'replan' ? { marginLeft: 16 } : {}) }}>
                    <span
                      className={`badge ${meta.cls}`}
                      style={{ minWidth: 22, textAlign: 'center' }}
                      title={t.panels.opacidad.status[s.status]}
                    >
                      {s.origin === 'replan' ? '↳' : meta.mark}
                    </span>
                    <strong style={{ fontSize: 12.5 }}>{s.worker}</strong>
                    {s.origin === 'replan' && (
                      <span className="badge" style={{ fontSize: 10 }} title={s.trigger}>
                        {t.panels.opacidad.replanned}
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

          <Section title={t.panels.opacidad.findings(result.findings.total)}>
            {result.findings.top.length === 0 ? (
              <div className="hint">{t.panels.opacidad.noFindings}</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {result.findings.top.map((f) => (
                  <div key={`${f.source}:${f.title}`} style={rowStyle}>
                    <span className={`badge ${sevClass(f.severity)}`}>{f.severity}</span>
                    <span style={{ flex: 1, fontSize: 12.5 }}>{f.title}</span>
                    <span className="hint mono" title={proofMeaning(f.proofState)}>
                      {f.proofState}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </Section>

          {result.attackPath.length > 0 && (
            <Section title={t.panels.opacidad.attackPath}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {result.attackPath.map((p) => (
                  <div key={p} className="mono" style={{ fontSize: 12 }}>
                    {p}
                  </div>
                ))}
              </div>
            </Section>
          )}

          <Section title={t.panels.opacidad.narrative}>
            <pre className="narrative" style={narrativeStyle}>
              {result.narrative}
            </pre>
          </Section>

          {result.honestGaps.length > 0 && (
            <Section title={t.panels.opacidad.honestGaps}>
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
      <RunHistory imageId={imageId} kinds={['opacidad']} label={t.panels.opacidad.runLabel} />
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
