import { useCallback, useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { type AgentStatus, type ImageSummary, api } from '../api';
import { Icon } from '../icons';
import { toast } from '../toast';

/**
 * Agents — the console over FirmLab's autonomous engine, lifted to workspace level. It launches the two run
 * kinds (the deterministic Opacidad scan and the conscious LLM Agent) on any target and keeps a unified run
 * history across every image, with live status; opening a run drops into its steps + evidence on the target.
 */

interface Run {
  key: string;
  type: 'scan' | 'agent';
  imageId: string;
  filename: string;
  status: string;
  at: number;
  detail: string;
  to: string;
}

const STATUS_CLASS: Record<string, string> = {
  done: 'badge-ok',
  running: 'badge-medium',
  queued: 'badge-medium',
  awaiting_approval: 'badge-warn',
  error: 'badge-crit',
  halted: 'badge-crit',
};
const isLive = (s: string): boolean => s === 'running' || s === 'queued' || s === 'awaiting_approval';

export function Agents(): JSX.Element {
  const [images, setImages] = useState<ImageSummary[]>([]);
  const [status, setStatus] = useState<AgentStatus | null>(null);
  const [runs, setRuns] = useState<Run[] | null>(null);
  const nav = useNavigate();

  useEffect(() => {
    api
      .listImages()
      .then(setImages)
      .catch(() => setImages([]));
    api
      .agentStatus()
      .then(setStatus)
      .catch(() => setStatus(null));
  }, []);

  // Assemble the cross-target run history: Opacidad scans surface as image jobs, the Agent as a per-image session.
  const loadRuns = useCallback(async () => {
    const imgs = await api.listImages().catch(() => [] as ImageSummary[]);
    setImages(imgs);
    const collected = await Promise.all(
      imgs.map(async (im) => {
        const out: Run[] = [];
        const [jobs, view] = await Promise.all([
          api.jobs(im.id).catch(() => []),
          api.agentSession(im.id).catch(() => null),
        ]);
        for (const j of jobs.filter((x) => x.kind === 'opacidad')) {
          const r = j.result as { findings?: { total?: number } } | null;
          out.push({
            key: `scan-${j.id}`,
            type: 'scan',
            imageId: im.id,
            filename: im.filename,
            status: j.status,
            at: j.createdAt,
            detail: j.status === 'done' ? `${r?.findings?.total ?? 0} findings` : j.status,
            to: `/image/${im.id}/opacidad`,
          });
        }
        if (view?.session) {
          const s = view.session;
          out.push({
            key: `agent-${s.id}`,
            type: 'agent',
            imageId: im.id,
            filename: im.filename,
            status: s.status,
            at: s.createdAt,
            detail: `${view.steps.length} steps${s.goal ? ` · ${s.goal}` : ''}`,
            to: `/image/${im.id}/agent`,
          });
        }
        return out;
      }),
    );
    setRuns(collected.flat().sort((a, b) => b.at - a.at));
  }, []);

  useEffect(() => {
    loadRuns();
  }, [loadRuns]);

  // Poll while anything is live.
  useEffect(() => {
    if (!runs?.some((r) => isLive(r.status))) return;
    const t = setInterval(loadRuns, 4000);
    return () => clearInterval(t);
  }, [runs, loadRuns]);

  const launchScan = useCallback(
    async (im: ImageSummary) => {
      try {
        await api.runOpacidad(im.id);
        toast.success(`Autonomous scan launched on ${im.filename}`);
        nav(`/image/${im.id}/opacidad`);
      } catch (e) {
        toast.error(e);
      }
    },
    [nav],
  );

  const ready = images.filter((i) => i.status === 'ready');
  const liveCount = runs?.filter((r) => isLive(r.status)).length ?? 0;

  return (
    <div>
      <div className="page-head">
        <div className="eyebrow">Autonomy</div>
        <h1 className="page-title">Agents</h1>
        <div className="page-desc">
          Launch and monitor autonomous analysis runs across every target. Each run records its steps and keeps every
          claim's proof state — the agent drives the pipeline, it never invents findings.
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
            One click plans a class-routed worker chain, runs it end-to-end and returns a reasoning trace with honest
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
              ? 'LLM decision nodes with a human approval gate before emulation and a governor capping steps, tokens, cost and time.'
              : 'Disabled — set FIRMLAB_AGENT=1 and an API key for LLM-driven decisions. The deterministic scan still runs.'}
          </div>
        </div>
      </div>

      {/* Run history — the console's spine */}
      <div className="panel panel-flush">
        <div className="panel-head" style={{ padding: 'var(--panel-pad)', marginBottom: 0 }}>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
            <span className="panel-title" style={{ margin: 0 }}>
              Run history
            </span>
            {liveCount > 0 && (
              <span className="badge badge-medium">
                <span className="spinner" style={{ width: 10, height: 10 }} /> {liveCount} live
              </span>
            )}
          </div>
          <button type="button" className="btn btn-sm btn-ghost" onClick={loadRuns} title="Refresh">
            <Icon.refresh size={14} /> Refresh
          </button>
        </div>

        {runs === null ? (
          <div style={{ padding: 16, display: 'grid', gap: 8 }}>
            {[0, 1, 2].map((i) => (
              <div key={i} className="skeleton" style={{ height: 34 }} />
            ))}
          </div>
        ) : runs.length === 0 ? (
          <div className="empty" style={{ padding: 32 }}>
            <div className="empty-mark">
              <Icon.agent size={20} />
            </div>
            <div className="empty-title">No runs yet</div>
            <div className="empty-body">
              Launch an autonomous scan on a ready target below. Runs appear here with live status, and open into their
              step transcript and evidence.
            </div>
          </div>
        ) : (
          <div className="table-wrap" style={{ border: 'none', borderTop: '1px solid var(--border)', borderRadius: 0 }}>
            <table className="data">
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Kind</th>
                  <th>Status</th>
                  <th>Detail</th>
                  <th style={{ width: 80 }} />
                </tr>
              </thead>
              <tbody>
                {runs.map((r) => (
                  <tr key={r.key} className="row-link" onClick={() => nav(r.to)}>
                    <td className="mono" style={{ color: 'var(--text)' }}>
                      {r.filename}
                    </td>
                    <td>
                      <span className="badge">{r.type === 'scan' ? 'scan' : 'agent'}</span>
                    </td>
                    <td>
                      <span className={`badge ${STATUS_CLASS[r.status] ?? ''}`}>
                        {isLive(r.status) && <span className="spinner" style={{ width: 9, height: 9 }} />}
                        {r.status}
                      </span>
                    </td>
                    <td className="mono" style={{ color: 'var(--text-dim)', fontSize: '0.78rem' }}>
                      {r.detail}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <span className="btn btn-sm btn-ghost">View</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Launch */}
      <div className="panel panel-flush" style={{ marginTop: 16 }}>
        <div className="panel-head" style={{ padding: 'var(--panel-pad)', marginBottom: 0 }}>
          <span className="panel-title" style={{ margin: 0 }}>
            Launch on a target
          </span>
          <span className="mono" style={{ color: 'var(--text-faint)', fontSize: '0.8rem' }}>
            {ready.length} ready
          </span>
        </div>
        {ready.length === 0 ? (
          <div className="empty" style={{ padding: 28 }}>
            <div className="empty-title">No targets yet</div>
            <div className="empty-body">
              Upload firmware in <Link to="/analyze">Local analysis</Link> — analyzed images become agent targets here.
            </div>
          </div>
        ) : (
          <div className="table-wrap" style={{ border: 'none', borderTop: '1px solid var(--border)', borderRadius: 0 }}>
            <table className="data">
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
                        <button type="button" className="btn btn-sm btn-primary" onClick={() => launchScan(im)}>
                          <Icon.play size={13} /> Scan
                        </button>
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
    </div>
  );
}
