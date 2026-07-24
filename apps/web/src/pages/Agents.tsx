import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { type AgentStatus, type ImageSummary, api } from '../api';
import { Icon } from '../icons';

/**
 * Agents — a console over FirmLab's existing autonomous engine (the Opacidad one-click scan and the conscious
 * Agent session), lifted to workspace level: pick a target, launch a run, and drop into its live steps + evidence.
 * The deep run view lives on the image (opacidad / agent sections); this is the launch-and-monitor surface.
 */
export function Agents(): JSX.Element {
  const [images, setImages] = useState<ImageSummary[]>([]);
  const [status, setStatus] = useState<AgentStatus | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([api.listImages().catch(() => []), api.agentStatus().catch(() => null)]).then(([im, st]) => {
      setImages(im);
      setStatus(st);
      setLoading(false);
    });
  }, []);

  const ready = images.filter((i) => i.status === 'ready');

  return (
    <div>
      <div className="page-head">
        <div className="eyebrow">Autonomy</div>
        <h1 className="page-title">Agents</h1>
        <div className="page-desc">
          Launch and monitor autonomous analysis runs. Every step is recorded and every claim keeps its proof state —
          the agent runs the pipeline, it never invents findings.
        </div>
      </div>

      <div className="grid grid-2" style={{ marginBottom: 16 }}>
        <div className="panel">
          <div className="panel-title" style={{ gap: 8 }}>
            <Icon.shield size={16} /> Autonomous scan
            <span className="badge badge-accent" style={{ marginLeft: 'auto' }}>
              deterministic
            </span>
          </div>
          <div className="panel-sub">
            One click plans a class-routed worker chain, runs it end-to-end, and returns a reasoning trace with honest
            gaps. No LLM key required.
          </div>
        </div>
        <div className="panel">
          <div className="panel-title" style={{ gap: 8 }}>
            <Icon.agent size={16} /> Conscious agent
            {status?.enabled ? (
              <span className="badge badge-ok" style={{ marginLeft: 'auto' }}>
                {status.provider} · {status.model}
              </span>
            ) : (
              <span className="badge" style={{ marginLeft: 'auto' }}>
                off
              </span>
            )}
          </div>
          <div className="panel-sub">
            {status?.enabled
              ? 'LLM decision nodes (triage, target selection) with a human approval gate before emulation and a governor capping steps, tokens, cost and time.'
              : 'Disabled — set FIRMLAB_AGENT=1 and an API key to enable LLM-driven decision nodes. The deterministic scan above still runs.'}
          </div>
        </div>
      </div>

      <div className="panel panel-flush">
        <div className="panel-head" style={{ padding: 'var(--panel-pad)', marginBottom: 0 }}>
          <span className="panel-title" style={{ margin: 0 }}>
            Launch on a target
          </span>
          <span className="mono" style={{ color: 'var(--text-faint)', fontSize: '0.8rem' }}>
            {ready.length} ready
          </span>
        </div>
        {loading ? (
          <div style={{ padding: 16, display: 'grid', gap: 8 }}>
            {[0, 1, 2].map((i) => (
              <div key={i} className="skeleton" style={{ height: 34 }} />
            ))}
          </div>
        ) : ready.length === 0 ? (
          <div className="empty" style={{ padding: 28 }}>
            <div className="empty-title">No targets yet</div>
            <div className="empty-body">
              Upload firmware in <Link to="/analyze">Local analysis</Link> — analyzed images become agent targets here.
            </div>
          </div>
        ) : (
          <div className="table-wrap" style={{ border: 'none', borderTop: '1px solid var(--border)', borderRadius: 0 }}>
            <table className="data">
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Class</th>
                  <th>Arch</th>
                  <th style={{ width: 260, textAlign: 'right' }}>Launch</th>
                </tr>
              </thead>
              <tbody>
                {ready.map((im) => (
                  <tr key={im.id}>
                    <td className="mono" style={{ color: 'var(--text)' }}>
                      {im.filename}
                    </td>
                    <td>
                      <span className="badge">{im.identity?.firmwareClass ?? 'unknown'}</span>
                    </td>
                    <td className="mono">{im.identity?.arch ?? '—'}</td>
                    <td style={{ textAlign: 'right' }}>
                      <div style={{ display: 'inline-flex', gap: 6 }}>
                        <Link to={`/image/${im.id}/opacidad`} className="btn btn-sm btn-primary">
                          <Icon.play size={13} /> Autonomous scan
                        </Link>
                        <Link to={`/image/${im.id}/agent`} className="btn btn-sm">
                          Agent
                        </Link>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="banner banner-info" style={{ marginTop: 16 }}>
        <Icon.shield size={15} />
        <span>
          Live run status, the step transcript and captured evidence render inside each target's Autonomous scan / Agent
          view. A unified cross-target run history is coming to this console.
        </span>
      </div>
    </div>
  );
}
