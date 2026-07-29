import { useCallback, useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { type AgentStatus, type ImageSummary, type OpacidadResult, api } from '../api';
import { OpacidadPanel } from '../components/OpacidadPanel';
import { useMessages } from '../i18n';
import { Icon } from '../icons';
import { toast } from '../toast';
import { AgentPanel } from './ImageDetail';

/**
 * Agents — the console over FirmLab's autonomous engine.
 *
 * **The unit is a RUN, and that is the whole re-architecture.** The previous version listed images and every click
 * navigated to `/image/:id/opacidad`, which is the static-analysis shell: opening a result dropped the reader into
 * a different section, under a pipeline strip about a different activity, with no route back to the console. So
 * the run view lives here (`/agents/:imageId/scan`), reusing the very same panels the image section renders, and
 * leaving for the image is one labelled link rather than the side effect of a click.
 *
 * **A row states an outcome, not a status.** `done` says a process finished and says nothing about what was
 * learned. `725 findings` says less than nothing on its own — it is the exact number the coverage discipline
 * exists to qualify. `summariseRun` therefore leads with how much of the plan actually ran and names the workers
 * that did not, because a total drawn from an incomplete plan is the misreading this workbench is built to
 * prevent, and a console that hides it is where that misreading starts.
 *
 * Statuses, filenames, worker ids and provider/model names render verbatim: they are records, not chrome.
 */

interface Run {
  key: string;
  type: 'scan' | 'agent';
  imageId: string;
  filename: string;
  status: string;
  at: number;
  /** The stored result, when the run produced one. Absent while queued/running, and after an error. */
  scan?: OpacidadResult;
  steps?: number;
}

const STATUS_CLASS: Record<string, string> = {
  done: 'badge-ok',
  running: 'badge-medium',
  queued: 'badge-medium',
  awaiting_approval: 'badge-warn',
  error: 'badge-crit',
  halted: 'badge-crit',
};
const isLive = (s: string): boolean => s === 'running' || s === 'queued';

/** Where a run opens. Inside this section, always. */
const runPath = (r: Pick<Run, 'type' | 'imageId'>): string => `/agents/${r.imageId}/${r.type}`;

const fmtWhen = (ms: number): string => new Date(ms).toISOString().slice(0, 16).replace('T', ' ');

// === The console ===

export function Agents(): JSX.Element {
  const [images, setImages] = useState<ImageSummary[]>([]);
  const [status, setStatus] = useState<AgentStatus | null>(null);
  const [runs, setRuns] = useState<Run[] | null>(null);
  const nav = useNavigate();
  const t = useMessages();

  useEffect(() => {
    api
      .agentStatus()
      .then(setStatus)
      .catch(() => setStatus(null));
  }, []);

  // Assemble the cross-target run list: scans surface as image jobs, the agent as a per-image session.
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
          out.push({
            key: `scan-${j.id}`,
            type: 'scan',
            imageId: im.id,
            filename: im.filename,
            status: j.status,
            at: j.createdAt,
            ...(j.result ? { scan: j.result as OpacidadResult } : {}),
          });
        }
        if (view?.session) {
          out.push({
            key: `agent-${view.session.id}`,
            type: 'agent',
            imageId: im.id,
            filename: im.filename,
            status: view.session.status,
            at: view.session.createdAt,
            steps: view.steps.length,
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

  useEffect(() => {
    if (!runs?.some((r) => isLive(r.status))) return;
    const id = setInterval(loadRuns, 4000);
    return () => clearInterval(id);
  }, [runs, loadRuns]);

  const launchScan = useCallback(
    async (im: ImageSummary) => {
      try {
        await api.runOpacidad(im.id);
        toast.success(t.agents.launch.launched(im.filename));
        nav(`/agents/${im.id}/scan`);
      } catch (e) {
        toast.error(e);
      }
    },
    [nav, t],
  );

  const ready = images.filter((i) => i.status === 'ready');
  const liveCount = runs?.filter((r) => isLive(r.status)).length ?? 0;

  return (
    <div>
      <div className="page-head">
        <div className="eyebrow">{t.agents.eyebrow}</div>
        <h1 className="page-title">{t.agents.title}</h1>
        <div className="page-desc">{t.agents.desc}</div>
      </div>

      {/* The two engines, as one strip. What each one IS belongs here once; what a run DID belongs in its row. */}
      <div className="engine-strip">
        <div className="engine">
          <div className="engine-head">
            <Icon.shield size={15} />
            <strong>{t.agents.engine.scanName}</strong>
            <span className="badge badge-accent">{t.agents.engine.scanKind}</span>
            <span className="badge badge-ok">{t.agents.engine.scanReady}</span>
          </div>
          <div className="hint">{t.agents.engine.scanWhat}</div>
        </div>
        <div className="engine">
          <div className="engine-head">
            <Icon.agent size={15} />
            <strong>{t.agents.engine.agentName}</strong>
            {status?.enabled ? (
              <span className="badge badge-ok mono">
                {status.provider} · {status.model}
              </span>
            ) : (
              <span className="badge">{t.agents.engine.agentOff}</span>
            )}
          </div>
          <div className="hint">
            {t.agents.engine.agentWhat}
            {!status?.enabled && ` ${t.agents.engine.agentDisabled}`}
          </div>
        </div>
      </div>

      <div className="panel panel-flush" style={{ marginTop: 16 }}>
        <div className="panel-head" style={{ padding: 'var(--panel-pad)', marginBottom: 0 }}>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
            <span className="panel-title" style={{ margin: 0 }}>
              {t.agents.runs.title}
            </span>
            {liveCount > 0 && (
              <span className="badge badge-medium">
                <span className="spinner" style={{ width: 10, height: 10 }} /> {t.agents.runs.live(liveCount)}
              </span>
            )}
          </div>
          <button type="button" className="btn btn-sm btn-ghost" onClick={loadRuns} title={t.agents.runs.refresh}>
            <Icon.refresh size={14} /> {t.agents.runs.refresh}
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
            <div className="empty-title">{t.agents.runs.emptyTitle}</div>
            <div className="empty-body">{t.agents.runs.emptyBody}</div>
          </div>
        ) : (
          <div className="table-wrap" style={{ border: 'none', borderTop: '1px solid var(--border)', borderRadius: 0 }}>
            <table className="data">
              <thead>
                <tr>
                  <th>{t.agents.runs.colTarget}</th>
                  <th>{t.agents.runs.colOutcome}</th>
                  <th style={{ width: 150 }}>{t.agents.runs.colWhen}</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((r) => (
                  <tr key={r.key} className="row-link" onClick={() => nav(runPath(r))}>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                        <span className="badge">
                          {r.type === 'scan' ? t.agents.runs.kindScan : t.agents.runs.kindAgent}
                        </span>
                        <span className="mono" style={{ color: 'var(--text)' }}>
                          {r.filename}
                        </span>
                      </div>
                    </td>
                    <td>
                      <RunOutcome run={r} />
                    </td>
                    <td className="mono hint" style={{ fontSize: '0.75rem' }}>
                      {fmtWhen(r.at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="panel panel-flush" style={{ marginTop: 16 }}>
        <div className="panel-head" style={{ padding: 'var(--panel-pad)', marginBottom: 0 }}>
          <span className="panel-title" style={{ margin: 0 }}>
            {t.agents.launch.title}
          </span>
          <span className="mono" style={{ color: 'var(--text-faint)', fontSize: '0.8rem' }}>
            {t.agents.launch.ready(ready.length)}
          </span>
        </div>
        {ready.length === 0 ? (
          <div className="empty" style={{ padding: 28 }}>
            <div className="empty-title">{t.agents.launch.emptyTitle}</div>
            <div className="empty-body">
              {t.agents.launch.emptyLead} <Link to="/analyze">{t.agents.launch.emptyLink}</Link>{' '}
              {t.agents.launch.emptyTail}
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
                      <span className="badge">{im.identity?.firmwareClass ?? t.common.unknown}</span>
                    </td>
                    <td className="mono hint">{im.identity?.arch ?? '—'}</td>
                    <td style={{ textAlign: 'right' }}>
                      <div style={{ display: 'inline-flex', gap: 6 }}>
                        <button type="button" className="btn btn-sm btn-primary" onClick={() => launchScan(im)}>
                          <Icon.play size={13} /> {t.agents.launch.scan}
                        </button>
                        <Link to={`/agents/${im.id}/agent`} className="btn btn-sm">
                          {t.agents.launch.agent}
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

/**
 * What came of a run, in the order a reader needs it.
 *
 * The plan's completion comes FIRST and the finding total second, because the total is only readable once you know
 * how much of the plan produced it. `not-built` and `skipped` workers are counted as not completing — they are
 * stages nothing was asked of, never stages that passed, and the whole honest-gaps machinery exists to keep those
 * two apart. A run with no stored result says so rather than rendering an empty cell that reads as "found
 * nothing".
 */
function RunOutcome({ run }: { run: Run }): JSX.Element {
  const t = useMessages();
  const status = (
    <span className={`badge ${STATUS_CLASS[run.status] ?? ''}`}>
      {isLive(run.status) && <span className="spinner" style={{ width: 9, height: 9 }} />}
      {run.status}
    </span>
  );

  if (run.status === 'awaiting_approval') {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        {status}
        <span style={{ fontSize: 12.5, color: 'var(--sev-medium, #e6b45c)' }}>{t.agents.runs.needsYou}</span>
      </div>
    );
  }

  if (run.type === 'agent') {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        {status}
        <span className="hint" style={{ fontSize: 12.5 }}>
          {t.agents.runs.steps(run.steps ?? 0)}
        </span>
      </div>
    );
  }

  const scan = run.scan;
  if (!scan) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        {status}
        <span className="hint" style={{ fontSize: 12.5 }}>
          {t.agents.runs.pending}
        </span>
      </div>
    );
  }

  const total = scan.steps.length;
  const ran = scan.steps.filter((s) => s.status === 'ran').length;
  const incomplete = total - ran;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
      {status}
      <span style={{ fontSize: 12.5 }}>{t.agents.runs.workers(ran, total)}</span>
      <span className="hint">·</span>
      <span style={{ fontSize: 12.5 }}>{t.agents.runs.findings(scan.findings.total)}</span>
      {incomplete > 0 && (
        <span
          className="badge badge-medium"
          title={scan.steps
            .filter((s) => s.status !== 'ran')
            .map((s) => s.worker)
            .join(', ')}
        >
          {t.agents.runs.incomplete(incomplete)}
        </span>
      )}
    </div>
  );
}

// === One run, inside this section ===

/**
 * The run view. It renders the SAME panels the image section does — the trace is the trace — inside this
 * section's frame, so opening a result never silently changes which part of the workbench you are in.
 */
export function AgentsRun(): JSX.Element {
  const { imageId = '', kind = 'scan' } = useParams();
  const t = useMessages();
  const [image, setImage] = useState<ImageSummary | null>(null);
  const [missing, setMissing] = useState(false);

  useEffect(() => {
    api
      .getImage(imageId)
      .then(setImage)
      .catch(() => setMissing(true));
  }, [imageId]);

  if (missing) {
    return (
      <div className="empty" style={{ padding: 32 }}>
        <div className="empty-title">{t.agents.run.notFound}</div>
        <div className="empty-body">
          <Link to="/agents">{t.agents.run.back}</Link>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="page-head">
        <Link to="/agents" className="btn btn-sm btn-ghost" style={{ paddingLeft: 0, marginBottom: 4 }}>
          <Icon.back size={13} /> {t.agents.run.back}
        </Link>
        <h1 className="page-title">{kind === 'agent' ? t.agents.run.agentTitle : t.agents.run.scanTitle}</h1>
        <div className="hint mono" style={{ wordBreak: 'break-all' }}>
          {image?.filename ?? imageId}
          {image?.identity ? ` · ${image.identity.firmwareClass} · ${image.identity.arch}` : ''}
        </div>
      </div>

      {kind === 'agent' ? <AgentPanel imageId={imageId} /> : <OpacidadPanel imageId={imageId} />}

      {/* The one way out, labelled. Leaving for the static-analysis shell is a choice made here, never the
          unannounced result of clicking a row. */}
      <div className="panel" style={{ marginTop: 16 }}>
        <Link to={`/image/${imageId}/dossier`} className="btn btn-sm">
          {t.agents.run.openImage}
        </Link>
        <div className="hint" style={{ marginTop: 6 }}>
          {t.agents.run.openImageHint}
        </div>
      </div>
    </div>
  );
}
