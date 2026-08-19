import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { type CoverageSummary, type ImageSummary, api, fmtBytes } from '../api';
import { useLocale, useMessages } from '../i18n';
import { Icon } from '../icons';
import { toast } from '../toast';

type SortKey = 'filename' | 'firmwareClass' | 'arch' | 'size' | 'status' | 'coverage' | 'findings';
type SortDir = 'asc' | 'desc';

const STATUS_BADGE: Record<string, string> = { ready: 'badge-ok', error: 'badge-crit', analyzing: 'badge-medium' };

/**
 * One image's coverage as a table cell. A corpus listing that shows only filename/class/size presents an image
 * nothing has ever analyzed and a fully-scanned one identically — which is the exact conflation the per-image
 * coverage banner exists to prevent, reintroduced at corpus scale. So the cell states it: nothing run at all is
 * called `unexamined` and is never dressed as a neutral zero; a partial run shows how much of the applicable plan
 * actually executed. The full sentence is on the title, one hover away.
 *
 * That hover sentence is `c.verdict`, and it is NOT a stored measurement: `providers/coverage.ts` recomposes it
 * from the stage table on every request, and what it describes is the analysis RUN — which stages this deployment
 * routed to and which of them executed — not the firmware. So it arrives already written in the locale the page
 * asked for, and there is nothing to translate here. A finding's title is the opposite case and is shown as the
 * provider recorded it.
 */
function CoverageCell({ c }: { c: CoverageSummary | undefined }): JSX.Element {
  const t = useMessages();
  if (!c) return <span className="hint">—</span>;
  if (c.executed === 0) {
    return (
      <div className="coverage-cell" title={c.verdict}>
        <span className="badge badge-medium mono">{t.dashboard.coverage.unexamined}</span>
        <span className="coverage-track" aria-hidden="true">
          <span style={{ width: 0 }} />
        </span>
      </div>
    );
  }
  const complete = c.executed >= c.applicable;
  const pct = c.applicable > 0 ? Math.min(100, (c.executed / c.applicable) * 100) : 0;
  return (
    <div className="coverage-cell" title={c.verdict}>
      <span className={`mono coverage-value ${complete ? 'is-complete' : ''}`}>
        {t.dashboard.coverage.stages(c.executed, c.applicable)}
      </span>
      <span className="coverage-track" aria-hidden="true">
        <span style={{ width: `${pct}%` }} />
      </span>
    </div>
  );
}

function FindingsCell({ c }: { c: CoverageSummary | undefined }): JSX.Element {
  const t = useMessages();
  if (!c || c.executed === 0) return <span className="hint">—</span>;
  return (
    <div className="findings-count" title={c.verdict}>
      <strong className="num">{c.findingCount}</strong>
      <span>{t.dashboard.list.findingsLabel(c.findingCount)}</span>
    </div>
  );
}

/**
 * A small confirm dialog that escapes its container (replaces window.confirm).
 *
 * The action label is passed in rather than derived. It used to be `title.startsWith('Delete') ? 'Delete' :
 * 'Confirm'`, which reads the button off English prose — under any other language every dialog would have
 * silently offered "Confirm" for a destructive action.
 */
function Confirm({
  title,
  body,
  confirmLabel,
  danger,
  onCancel,
  onConfirm,
}: {
  title: string;
  body: string;
  confirmLabel: string;
  danger?: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}): JSX.Element {
  const t = useMessages();
  return (
    <div
      className="modal-scrim"
      onClick={onCancel}
      onKeyDown={(e) => e.key === 'Escape' && onCancel()}
      role="presentation"
    >
      {/* biome-ignore lint/a11y/useSemanticElements: a portal-free modal; focus is placed on the confirm button and the scrim closes on click/Escape. */}
      <div className="dialog" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <div className="dialog-title">{title}</div>
        <p className="hint" style={{ margin: '0 0 16px' }}>
          {body}
        </p>
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button type="button" className="btn btn-sm" onClick={onCancel}>
            {t.common.cancel}
          </button>
          <button
            type="button"
            className={`btn btn-sm ${danger ? 'btn-danger' : 'btn-primary'}`}
            onClick={onConfirm}
            ref={(el) => el?.focus()}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

export function Dashboard(): JSX.Element {
  const [images, setImages] = useState<ImageSummary[]>([]);
  const [coverage, setCoverage] = useState<Map<string, CoverageSummary>>(new Map());
  const [usage, setUsage] = useState<Awaited<ReturnType<typeof api.storage>> | null>(null);
  const [query, setQuery] = useState('');
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [sort, setSort] = useState<{ key: SortKey; dir: SortDir }>({ key: 'filename', dir: 'asc' });
  const [loading, setLoading] = useState(true);
  const [editingTag, setEditingTag] = useState<string | null>(null);
  const [tagDraft, setTagDraft] = useState('');
  const [confirm, setConfirm] = useState<{
    title: string;
    body: string;
    confirmLabel: string;
    run: () => void;
  } | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const tagInputRef = useRef<HTMLInputElement>(null);
  const nav = useNavigate();
  const t = useMessages();
  const locale = useLocale();

  // Focus the inline tag field when it opens (only one row edits at a time).
  useEffect(() => {
    if (editingTag) tagInputRef.current?.focus();
  }, [editingTag]);

  const refresh = useCallback(() => {
    api
      .listImages()
      .then(setImages)
      .catch(() => setImages([]))
      .finally(() => setLoading(false));
    api
      .storage()
      .then(setUsage)
      .catch(() => setUsage(null));
    // The corpus coverage carries the locale, and `refresh` therefore depends on it: the verdict behind every
    // row's hover is recomposed per request, so a language switch has to re-ask for it. The listing and the
    // storage figures beside it are data and would come back identical — they ride along because they are one
    // refresh, not because they move.
    api
      .coverageAll(locale)
      .then((rows) => setCoverage(new Map(rows.map((r) => [r.imageId, r]))))
      .catch(() => setCoverage(new Map()));
  }, [locale]);
  useEffect(refresh, [refresh]);

  /**
   * How much of the corpus has never been touched — the one number a listing of 16 images otherwise hides. Counted
   * only over images whose coverage actually loaded: a failed report means we do not KNOW, and claiming those are
   * unexamined would be the same fabrication in the opposite direction.
   */
  const unexamined = useMemo(
    () => images.filter((im) => coverage.get(im.id)?.executed === 0).length,
    [images, coverage],
  );

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    const filtered = q
      ? images.filter(
          (im) =>
            im.filename.toLowerCase().includes(q) ||
            (im.identity?.arch ?? '').toLowerCase().includes(q) ||
            (im.identity?.firmwareClass ?? '').toLowerCase().includes(q) ||
            im.tags.some((tag) => tag.toLowerCase().includes(q)),
        )
      : images;
    const val = (im: ImageSummary): string | number =>
      sort.key === 'size'
        ? im.size
        : sort.key === 'filename'
          ? im.filename.toLowerCase()
          : sort.key === 'status'
            ? im.status
            : // Sorted by how much of the applicable plan ran, so "show me what nobody has looked at" is one click.
              sort.key === 'coverage'
              ? (coverage.get(im.id)?.executed ?? -1)
              : sort.key === 'findings'
                ? (coverage.get(im.id)?.findingCount ?? -1)
                : (im.identity?.[sort.key] ?? '').toString().toLowerCase();
    return [...filtered].sort((a, b) => {
      const av = val(a);
      const bv = val(b);
      const cmp = av < bv ? -1 : av > bv ? 1 : 0;
      return sort.dir === 'asc' ? cmp : -cmp;
    });
  }, [images, query, sort, coverage]);

  const toggleSort = useCallback((key: SortKey) => {
    setSort((s) => (s.key === key ? { key, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'asc' }));
  }, []);

  const toggleSelect = useCallback((id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const editTags = useCallback(
    async (img: ImageSummary, action: 'add' | 'remove', tag: string) => {
      const next = action === 'add' ? [...new Set([...img.tags, tag])] : img.tags.filter((x) => x !== tag);
      try {
        await api.setTags(img.id, next);
        refresh();
      } catch (e) {
        toast.error(e);
      }
    },
    [refresh],
  );

  const upload = useCallback(
    async (file: File) => {
      setUploading(true);
      setError(null);
      try {
        const img = await api.upload(file);
        refresh();
        nav(`/image/${img.id}`);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
        toast.error(e);
      } finally {
        setUploading(false);
      }
    },
    [nav, refresh],
  );

  const askDelete = useCallback(
    (title: string, body: string, run: () => void) => setConfirm({ title, body, confirmLabel: t.common.delete, run }),
    [t],
  );

  const hasImages = images.length > 0;

  const dropHandlers = {
    onDragOver: (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(true);
    },
    onDragLeave: () => setDragOver(false),
    onDrop: (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      const f = e.dataTransfer.files[0];
      if (f) upload(f);
    },
  };

  const hiddenInput = (
    <input
      ref={fileRef}
      type="file"
      hidden
      onChange={(e) => {
        const f = e.target.files?.[0];
        if (f) upload(f);
      }}
    />
  );

  // Large, teaching dropzone when the workspace is empty; a slim bar once there are images.
  const EmptyDropzone = (
    <button
      type="button"
      data-tour="upload"
      className="panel"
      {...dropHandlers}
      onClick={() => fileRef.current?.click()}
      style={{
        width: '100%',
        cursor: 'pointer',
        textAlign: 'center',
        padding: '48px 24px',
        border: `1.5px dashed ${dragOver ? 'var(--accent)' : 'var(--border-strong)'}`,
        background: dragOver ? 'var(--accent-soft)' : 'var(--bg-panel)',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        gap: 6,
      }}
    >
      <div className="empty-mark" style={{ width: 52, height: 52, color: 'var(--accent)' }}>
        {uploading ? <span className="spinner" /> : <Icon.upload size={22} />}
      </div>
      <div style={{ fontSize: '1.05rem', fontWeight: 650, color: 'var(--text)' }}>
        {uploading ? t.dashboard.upload.analyzing : t.dashboard.upload.dropTitle}
      </div>
      <div className="empty-body">{t.dashboard.upload.dropBody}</div>
      {/* File extensions, not prose. */}
      <div className="mono" style={{ marginTop: 6, fontSize: '0.72rem', color: 'var(--text-faint)' }}>
        .bin · .img · .trx · .squashfs · .ubi · .jffs2 · .elf · .dtb
      </div>
    </button>
  );

  const SlimDropzone = (
    <div
      data-tour="upload"
      className="panel"
      {...dropHandlers}
      style={{
        border: `1.5px dashed ${dragOver ? 'var(--accent)' : 'var(--border-strong)'}`,
        background: dragOver ? 'var(--accent-soft)' : 'var(--bg-panel)',
        display: 'flex',
        alignItems: 'center',
        gap: 14,
        flexWrap: 'wrap',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, flex: '1 1 320px' }}>
        <div className="empty-mark" style={{ width: 38, height: 38, margin: 0, color: 'var(--accent)' }}>
          <Icon.upload size={18} />
        </div>
        <div style={{ minWidth: 0 }}>
          <div style={{ fontWeight: 600 }}>{t.dashboard.upload.another}</div>
          <div className="mono hint" style={{ marginTop: 2, fontSize: '0.72rem' }}>
            {t.dashboard.upload.anotherHint}
          </div>
        </div>
      </div>
      <button type="button" className="btn btn-primary" disabled={uploading} onClick={() => fileRef.current?.click()}>
        {uploading ? (
          <>
            <span className="spinner" /> {t.dashboard.upload.analyzing}
          </>
        ) : (
          <>
            <Icon.upload size={15} /> {t.dashboard.upload.dropOrSelect}
          </>
        )}
      </button>
    </div>
  );

  const Th = ({ k, children, num }: { k: SortKey; children: React.ReactNode; num?: boolean }) => (
    <th className="sortable" onClick={() => toggleSort(k)} style={num ? { textAlign: 'right' } : undefined}>
      {children}
      {sort.key === k && <span aria-hidden="true"> {sort.dir === 'asc' ? '↑' : '↓'}</span>}
    </th>
  );

  return (
    <div>
      <div className="page-head">
        <div className="eyebrow">{t.dashboard.eyebrow}</div>
        <h1 className="page-title">{t.dashboard.title}</h1>
        <div className="page-desc">{t.dashboard.desc}</div>
      </div>

      {hiddenInput}
      {!hasImages && !loading ? (
        EmptyDropzone
      ) : (
        <>
          {SlimDropzone}
          {error && (
            <div className="banner banner-warn" style={{ marginTop: 12 }}>
              {error}
            </div>
          )}

          <div className="panel panel-flush" style={{ marginTop: 16 }}>
            <div className="panel-head" style={{ padding: 'var(--panel-pad)', marginBottom: 0, alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
                <span className="panel-title" style={{ margin: 0 }}>
                  {t.dashboard.list.title}
                </span>
                <span className="mono" style={{ color: 'var(--text-faint)', fontSize: '0.8rem' }}>
                  {images.length}
                </span>
              </div>
              {/* The corpus-level reading of the same coverage the rows show — "0 findings" across an unscanned
                  workspace is not a quiet corpus, and this is where that would otherwise go unsaid. */}
              {unexamined > 0 && (
                <span className="badge badge-medium" title={t.dashboard.coverage.unexaminedTitle}>
                  {t.dashboard.coverage.unexaminedCount(unexamined, images.length)}
                </span>
              )}
              <div style={{ flex: 1 }} />
              {selected.size > 0 && (
                <button
                  type="button"
                  className="btn btn-sm btn-danger"
                  onClick={() =>
                    askDelete(t.dashboard.del.manyTitle(selected.size), t.dashboard.del.manyBody, async () => {
                      const ids = [...selected];
                      try {
                        await api.deleteImages(ids);
                        toast.success(t.dashboard.del.done(ids.length));
                      } catch (e) {
                        toast.error(e);
                      }
                      setSelected(new Set());
                      setConfirm(null);
                      refresh();
                    })
                  }
                >
                  {t.dashboard.del.selected(selected.size)}
                </button>
              )}
              <div style={{ position: 'relative', flex: '0 1 300px' }}>
                <span
                  style={{
                    position: 'absolute',
                    left: 10,
                    top: '50%',
                    transform: 'translateY(-50%)',
                    color: 'var(--text-faint)',
                    pointerEvents: 'none',
                  }}
                >
                  <Icon.search size={14} />
                </span>
                <input
                  className="input"
                  placeholder={t.dashboard.list.filterPlaceholder}
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  style={{ paddingLeft: 30 }}
                />
              </div>
            </div>

            {loading ? (
              <div style={{ padding: 16, display: 'grid', gap: 8 }}>
                {[0, 1, 2].map((i) => (
                  <div key={i} className="skeleton" style={{ height: 36 }} />
                ))}
              </div>
            ) : shown.length === 0 ? (
              <div style={{ padding: 20 }}>
                <div className="empty">
                  <div className="empty-title">{t.dashboard.list.noMatches}</div>
                  <div className="empty-body">{t.dashboard.list.noMatchesBody(query, images.length)}</div>
                  <button type="button" className="btn btn-sm" onClick={() => setQuery('')}>
                    {t.dashboard.list.clearFilter}
                  </button>
                </div>
              </div>
            ) : (
              <div
                className="table-wrap"
                style={{ border: 'none', borderTop: '1px solid var(--border)', borderRadius: 0 }}
              >
                <table className="data firmware-table">
                  <thead>
                    <tr>
                      <th style={{ width: 36 }} />
                      <Th k="filename">{t.dashboard.list.colFilename}</Th>
                      <th>{t.dashboard.list.colTags}</th>
                      <Th k="findings" num>
                        {t.dashboard.list.colFindings}
                      </Th>
                      <Th k="coverage">{t.dashboard.list.colCoverage}</Th>
                      <Th k="status">{t.dashboard.list.colStatus}</Th>
                      <th style={{ width: 40 }} />
                    </tr>
                  </thead>
                  <tbody>
                    {shown.map((img) => (
                      <tr key={img.id} className="row-link" onClick={() => nav(`/image/${img.id}`)}>
                        <td onClick={(e) => e.stopPropagation()}>
                          <input
                            type="checkbox"
                            aria-label={t.dashboard.list.select(img.filename)}
                            checked={selected.has(img.id)}
                            onChange={() => toggleSelect(img.id)}
                          />
                        </td>
                        {/* Filename, class and arch are data the analysis produced — never translated. */}
                        <td className="firmware-primary">
                          <div className="firmware-name mono">{img.filename}</div>
                          <div className="firmware-meta">
                            <span className="badge">{img.identity?.firmwareClass ?? t.common.unknown}</span>
                            <span className="mono">{img.identity?.arch ?? '—'}</span>
                            <span className="mono">{fmtBytes(img.size)}</span>
                          </div>
                        </td>
                        <td onClick={(e) => e.stopPropagation()} style={{ maxWidth: 240 }}>
                          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', alignItems: 'center' }}>
                            {img.tags.map((tag) => (
                              <button
                                type="button"
                                key={tag}
                                className="badge"
                                title={t.dashboard.list.removeTag}
                                onClick={() => editTags(img, 'remove', tag)}
                                style={{ cursor: 'pointer' }}
                              >
                                {tag}{' '}
                                <span aria-hidden="true" style={{ opacity: 0.6 }}>
                                  ✕
                                </span>
                              </button>
                            ))}
                            {editingTag === img.id ? (
                              <input
                                ref={tagInputRef}
                                className="input"
                                value={tagDraft}
                                placeholder={t.dashboard.list.tagPlaceholder}
                                onChange={(e) => setTagDraft(e.target.value)}
                                onBlur={() => {
                                  const tag = tagDraft.trim();
                                  if (tag) editTags(img, 'add', tag);
                                  setEditingTag(null);
                                  setTagDraft('');
                                }}
                                onKeyDown={(e) => {
                                  if (e.key === 'Enter') {
                                    const tag = tagDraft.trim();
                                    if (tag) editTags(img, 'add', tag);
                                    setEditingTag(null);
                                    setTagDraft('');
                                  } else if (e.key === 'Escape') {
                                    setEditingTag(null);
                                    setTagDraft('');
                                  }
                                }}
                                style={{ height: 24, width: 88, padding: '0 6px', fontSize: '0.72rem' }}
                              />
                            ) : (
                              <button
                                type="button"
                                className="icon-btn"
                                title={t.dashboard.list.addTag}
                                aria-label={t.dashboard.list.addTag}
                                style={{ width: 22, height: 22 }}
                                onClick={() => {
                                  setEditingTag(img.id);
                                  setTagDraft('');
                                }}
                              >
                                <Icon.plus size={13} />
                              </button>
                            )}
                          </div>
                        </td>
                        <td className="num findings-column">
                          <FindingsCell c={coverage.get(img.id)} />
                        </td>
                        <td>
                          <CoverageCell c={coverage.get(img.id)} />
                        </td>
                        <td>
                          <span className={`badge ${STATUS_BADGE[img.status] ?? ''}`} title={img.status}>
                            {img.status === 'ready'
                              ? t.dashboard.list.statusReady
                              : img.status === 'analyzing'
                                ? t.dashboard.list.statusAnalyzing
                                : img.status === 'error'
                                  ? t.dashboard.list.statusError
                                  : img.status}
                          </span>
                        </td>
                        <td onClick={(e) => e.stopPropagation()}>
                          <button
                            type="button"
                            className="icon-btn"
                            aria-label={t.dashboard.list.deleteImage(img.filename)}
                            title={t.common.delete}
                            onClick={() =>
                              askDelete(t.dashboard.del.oneTitle(img.filename), t.dashboard.del.oneBody, () => {
                                api
                                  .deleteImage(img.id)
                                  .then(() => {
                                    setConfirm(null);
                                    refresh();
                                  })
                                  .catch(toast.error);
                              })
                            }
                          >
                            <Icon.trash size={15} />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {usage && usage.quotaBytes > 0 && (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                  padding: '10px var(--panel-pad)',
                  borderTop: '1px solid var(--border)',
                }}
              >
                <span className="mono" style={{ fontSize: '0.72rem', color: 'var(--text-faint)' }}>
                  {fmtBytes(usage.totalBytes)} / {fmtBytes(usage.quotaBytes)}
                </span>
                <div className="meter" style={{ flex: 1, maxWidth: 240 }}>
                  <span style={{ width: `${Math.min(100, (usage.totalBytes / usage.quotaBytes) * 100)}%` }} />
                </div>
              </div>
            )}
          </div>
        </>
      )}

      {confirm && (
        <Confirm
          title={confirm.title}
          body={confirm.body}
          confirmLabel={confirm.confirmLabel}
          danger
          onCancel={() => setConfirm(null)}
          onConfirm={confirm.run}
        />
      )}
    </div>
  );
}
