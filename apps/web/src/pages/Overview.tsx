import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { type ImageSummary, type ToolStatus, api, fmtBytes } from '../api';
import { Icon } from '../icons';

/**
 * Dashboard — the global summary: a read-only panorama across the whole workspace (fleet, storage, tool health,
 * network posture) with jump-offs into the working sections. "Datos de todo", not a place you act.
 */
export function Overview(): JSX.Element {
  const [images, setImages] = useState<ImageSummary[]>([]);
  const [usage, setUsage] = useState<Awaited<ReturnType<typeof api.storage>> | null>(null);
  const [tools, setTools] = useState<ToolStatus[]>([]);
  const [health, setHealth] = useState<Awaited<ReturnType<typeof api.health>> | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      api.listImages().catch(() => []),
      api.storage().catch(() => null),
      api
        .tools()
        .then((t) => t.tools)
        .catch(() => []),
      api.health().catch(() => null),
    ]).then(([im, st, to, he]) => {
      setImages(im);
      setUsage(st);
      setTools(to);
      setHealth(he);
      setLoading(false);
    });
  }, []);

  const byClass = useMemo(() => {
    const m = new Map<string, number>();
    for (const im of images)
      m.set(im.identity?.firmwareClass ?? 'unknown', (m.get(im.identity?.firmwareClass ?? 'unknown') ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }, [images]);

  const analyzing = images.filter((i) => i.status === 'analyzing').length;
  const errored = images.filter((i) => i.status === 'error').length;
  const toolsUp = tools.filter((t) => t.available).length;
  const posture = health?.exposedToNetwork ? (health.trustedProxy ? 'auth-gated' : 'bound to network') : 'local-only';
  const postureClass = health?.exposedToNetwork ? (health.trustedProxy ? 'warn' : 'danger') : 'ok';

  const recent = images.slice(-6).reverse();

  return (
    <div>
      <div className="page-head">
        <div className="eyebrow">Workspace</div>
        <h1 className="page-title">Dashboard</h1>
        <div className="page-desc">
          Everything at a glance across your firmware corpus — fleet, capacity, and posture.
        </div>
      </div>

      {loading ? (
        <div className="grid grid-3">
          {[0, 1, 2].map((i) => (
            <div key={i} className="skeleton" style={{ height: 92, borderRadius: 8 }} />
          ))}
        </div>
      ) : (
        <>
          {/* summary strip */}
          <div className="panel">
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 20 }}>
              <SummaryStat
                label="Images"
                value={String(images.length)}
                sub={`${analyzing} analyzing · ${errored} error`}
              />
              <SummaryStat
                label="On disk"
                value={usage ? fmtBytes(usage.totalBytes) : '—'}
                sub={usage?.quotaBytes ? `of ${fmtBytes(usage.quotaBytes)}` : 'local store'}
              />
              <SummaryStat label="Tools" value={`${toolsUp}/${tools.length}`} sub="available in this deployment" />
              <div className="stat">
                <div className="stat-label">Network posture</div>
                <div style={{ marginTop: 4 }}>
                  <span className={`health ${postureClass}`}>{posture}</span>
                </div>
              </div>
            </div>
          </div>

          <div className="grid grid-2" style={{ marginTop: 16 }}>
            {/* recent images */}
            <div className="panel panel-flush">
              <div className="panel-head" style={{ padding: 'var(--panel-pad)', marginBottom: 0 }}>
                <span className="panel-title" style={{ margin: 0 }}>
                  Recent images
                </span>
                <Link to="/analyze" className="btn btn-sm btn-ghost">
                  Local analysis
                  <span style={{ display: 'inline-flex', transform: 'rotate(180deg)' }}>
                    <Icon.back size={13} />
                  </span>
                </Link>
              </div>
              {recent.length === 0 ? (
                <div className="empty" style={{ padding: 28 }}>
                  <div className="empty-title">No firmware yet</div>
                  <div className="empty-body">
                    Head to <Link to="/analyze">Local analysis</Link> to upload your first image.
                  </div>
                </div>
              ) : (
                <div
                  className="table-wrap"
                  style={{ border: 'none', borderTop: '1px solid var(--border)', borderRadius: 0 }}
                >
                  <table className="data">
                    <tbody>
                      {recent.map((im) => (
                        <tr
                          key={im.id}
                          className="row-link"
                          onClick={() => (window.location.hash = `#/image/${im.id}/overview`)}
                        >
                          <td className="mono" style={{ color: 'var(--text)' }}>
                            {im.filename}
                          </td>
                          <td>
                            <span className="badge">{im.identity?.firmwareClass ?? 'unknown'}</span>
                          </td>
                          <td className="mono">{im.identity?.arch ?? '—'}</td>
                          <td className="num" style={{ textAlign: 'right' }}>
                            {fmtBytes(im.size)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* class breakdown + entry points */}
            <div>
              <div className="panel">
                <div className="panel-title">Fleet by class</div>
                {byClass.length === 0 ? (
                  <div className="hint" style={{ marginTop: 8 }}>
                    No images yet.
                  </div>
                ) : (
                  <div style={{ marginTop: 10, display: 'grid', gap: 8 }}>
                    {byClass.map(([cls, n]) => (
                      <div key={cls} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        <span className="mono" style={{ fontSize: '0.8rem', minWidth: 130 }}>
                          {cls}
                        </span>
                        <div className="meter" style={{ flex: 1 }}>
                          <span style={{ width: `${(n / images.length) * 100}%` }} />
                        </div>
                        <span className="mono" style={{ fontSize: '0.8rem', color: 'var(--text-dim)' }}>
                          {n}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="panel">
                <div className="panel-title">Jump to</div>
                <div style={{ display: 'grid', gap: 8, marginTop: 10 }}>
                  <EntryLink
                    to="/analyze"
                    icon="overview"
                    title="Local analysis"
                    desc="Upload & read firmware as signal"
                  />
                  <EntryLink to="/agents" icon="agent" title="Agents" desc="Launch & monitor autonomous runs" />
                  <EntryLink
                    to="/updates"
                    icon="capture"
                    title="Proxy / Updates"
                    desc="Intercept & analyze OTA updates"
                  />
                  <EntryLink to="/corpus" icon="corpus" title="Corpus" desc="Cross-image priors & reuse" />
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function SummaryStat({ label, value, sub }: { label: string; value: string; sub?: string }): JSX.Element {
  return (
    <div className="stat">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {sub && (
        <div className="hint" style={{ fontSize: '0.72rem' }}>
          {sub}
        </div>
      )}
    </div>
  );
}

function EntryLink({
  to,
  icon,
  title,
  desc,
}: { to: string; icon: 'overview' | 'agent' | 'capture' | 'corpus'; title: string; desc: string }): JSX.Element {
  const Glyph = Icon[icon];
  return (
    <Link to={to} className="nav-item" style={{ border: '1px solid var(--border)', padding: '10px 12px', gap: 12 }}>
      <span className="nav-ico" style={{ color: 'var(--accent)' }}>
        <Glyph size={18} />
      </span>
      <span>
        <span style={{ display: 'block', color: 'var(--text)', fontWeight: 600 }}>{title}</span>
        <span className="hint" style={{ fontSize: '0.75rem' }}>
          {desc}
        </span>
      </span>
    </Link>
  );
}
