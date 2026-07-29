import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { type ImageSummary, type ToolStatus, api, fmtBytes } from '../api';
import { useLocale, useMessages } from '../i18n';
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
  const t = useMessages();
  const locale = useLocale();

  // The tool table carries the locale and the effect re-runs on a switch: each tool's `unlocks` gloss is composed
  // by the API from the binaries on this box at request time — interface copy about the deployment, recomputed on
  // every read. The counts it feeds (`toolsUp`/`tools.length`) are the same numbers in either language.
  useEffect(() => {
    Promise.all([
      api.listImages().catch(() => []),
      api.storage().catch(() => null),
      api
        .tools(locale)
        .then((r) => r.tools)
        .catch(() => []),
      api.health().catch(() => null),
    ]).then(([im, st, to, he]) => {
      setImages(im);
      setUsage(st);
      setTools(to);
      setHealth(he);
      setLoading(false);
    });
  }, [locale]);

  // The class breakdown is keyed by the firmware-class ID, which is data and stays in its identifier spelling; only
  // the fallback for an image with no class at all is a word, and that one is localised.
  const byClass = useMemo(() => {
    const m = new Map<string, number>();
    for (const im of images) {
      const cls = im.identity?.firmwareClass ?? t.common.unknown;
      m.set(cls, (m.get(cls) ?? 0) + 1);
    }
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  }, [images, t]);

  const analyzing = images.filter((i) => i.status === 'analyzing').length;
  const errored = images.filter((i) => i.status === 'error').length;
  const toolsUp = tools.filter((tool) => tool.available).length;
  const posture = health?.exposedToNetwork
    ? health.trustedProxy
      ? t.overview.stats.postureProxied
      : t.overview.stats.postureExposed
    : t.overview.stats.postureLocal;
  const postureClass = health?.exposedToNetwork ? (health.trustedProxy ? 'warn' : 'danger') : 'ok';

  const recent = images.slice(-6).reverse();

  return (
    <div>
      <div className="page-head">
        <div className="eyebrow">{t.overview.eyebrow}</div>
        <h1 className="page-title">{t.overview.title}</h1>
        <div className="page-desc">{t.overview.desc}</div>
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
                label={t.overview.stats.images}
                value={String(images.length)}
                sub={t.overview.stats.imagesSub(analyzing, errored)}
              />
              <SummaryStat
                label={t.overview.stats.onDisk}
                value={usage ? fmtBytes(usage.totalBytes) : '—'}
                sub={
                  usage?.quotaBytes ? t.overview.stats.quotaOf(fmtBytes(usage.quotaBytes)) : t.overview.stats.localStore
                }
              />
              <SummaryStat
                label={t.overview.stats.tools}
                value={`${toolsUp}/${tools.length}`}
                sub={t.overview.stats.toolsSub}
              />
              <div className="stat">
                <div className="stat-label">{t.overview.stats.posture}</div>
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
                  {t.overview.recent.title}
                </span>
                <Link to="/analyze" className="btn btn-sm btn-ghost">
                  {t.overview.recent.link}
                  <span style={{ display: 'inline-flex', transform: 'rotate(180deg)' }}>
                    <Icon.back size={13} />
                  </span>
                </Link>
              </div>
              {recent.length === 0 ? (
                <div className="empty" style={{ padding: 28 }}>
                  <div className="empty-title">{t.overview.recent.emptyTitle}</div>
                  <div className="empty-body">
                    {t.overview.recent.emptyLead} <Link to="/analyze">{t.overview.recent.link}</Link>{' '}
                    {t.overview.recent.emptyTail}
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
                          onClick={() => {
                            window.location.hash = `#/image/${im.id}/overview`;
                          }}
                        >
                          <td className="mono" style={{ color: 'var(--text)' }}>
                            {im.filename}
                          </td>
                          <td>
                            <span className="badge">{im.identity?.firmwareClass ?? t.common.unknown}</span>
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
                <div className="panel-title">{t.overview.byClass.title}</div>
                {byClass.length === 0 ? (
                  <div className="hint" style={{ marginTop: 8 }}>
                    {t.overview.byClass.empty}
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
                <div className="panel-title">{t.overview.jump.title}</div>
                <div style={{ display: 'grid', gap: 8, marginTop: 10 }}>
                  <EntryLink
                    to="/analyze"
                    icon="overview"
                    title={t.overview.jump.analysis}
                    desc={t.overview.jump.analysisDesc}
                  />
                  <EntryLink
                    to="/agents"
                    icon="agent"
                    title={t.overview.jump.agents}
                    desc={t.overview.jump.agentsDesc}
                  />
                  <EntryLink
                    to="/updates"
                    icon="capture"
                    title={t.overview.jump.capture}
                    desc={t.overview.jump.captureDesc}
                  />
                  <EntryLink
                    to="/corpus"
                    icon="corpus"
                    title={t.overview.jump.corpus}
                    desc={t.overview.jump.corpusDesc}
                  />
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
