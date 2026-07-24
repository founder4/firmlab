import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { type ImageSummary, api, fmtBytes } from '../api';
import { Icon } from '../icons';
import { toast } from '../toast';

type SortKey = 'filename' | 'firmwareClass' | 'arch' | 'size' | 'status';
type SortDir = 'asc' | 'desc';

const STATUS_BADGE: Record<string, string> = { ready: 'badge-ok', error: 'badge-crit', analyzing: 'badge-medium' };

/** A small confirm dialog that escapes its container (replaces window.confirm). */
function Confirm({
  title,
  body,
  danger,
  onCancel,
  onConfirm,
}: {
  title: string;
  body: string;
  danger?: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}): JSX.Element {
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
            Cancel
          </button>
          <button
            type="button"
            className={`btn btn-sm ${danger ? 'btn-danger' : 'btn-primary'}`}
            onClick={onConfirm}
            ref={(el) => el?.focus()}
          >
            {title.startsWith('Delete') ? 'Delete' : 'Confirm'}
          </button>
        </div>
      </div>
    </div>
  );
}

export function Dashboard(): JSX.Element {
  const [images, setImages] = useState<ImageSummary[]>([]);
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
  const [confirm, setConfirm] = useState<{ title: string; body: string; run: () => void } | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const tagInputRef = useRef<HTMLInputElement>(null);
  const nav = useNavigate();

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
  }, []);
  useEffect(refresh, [refresh]);

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    const filtered = q
      ? images.filter(
          (im) =>
            im.filename.toLowerCase().includes(q) ||
            (im.identity?.arch ?? '').toLowerCase().includes(q) ||
            (im.identity?.firmwareClass ?? '').toLowerCase().includes(q) ||
            im.tags.some((t) => t.toLowerCase().includes(q)),
        )
      : images;
    const val = (im: ImageSummary): string | number =>
      sort.key === 'size'
        ? im.size
        : sort.key === 'filename'
          ? im.filename.toLowerCase()
          : sort.key === 'status'
            ? im.status
            : (im.identity?.[sort.key] ?? '').toString().toLowerCase();
    return [...filtered].sort((a, b) => {
      const av = val(a);
      const bv = val(b);
      const cmp = av < bv ? -1 : av > bv ? 1 : 0;
      return sort.dir === 'asc' ? cmp : -cmp;
    });
  }, [images, query, sort]);

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
      const next = action === 'add' ? [...new Set([...img.tags, tag])] : img.tags.filter((t) => t !== tag);
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

  const askDelete = useCallback((title: string, body: string, run: () => void) => setConfirm({ title, body, run }), []);

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
        {uploading ? 'Analyzing…' : 'Drop a firmware image to begin'}
      </div>
      <div className="empty-body">
        Get an instant identity, structure map, entropy profile, and secret scan — analyzed entirely on this machine, no
        toolchain required.
      </div>
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
          <div style={{ fontWeight: 600 }}>Analyze another image</div>
          <div className="mono hint" style={{ marginTop: 2, fontSize: '0.72rem' }}>
            drop a file, or select — nothing leaves this machine
          </div>
        </div>
      </div>
      <button type="button" className="btn btn-primary" disabled={uploading} onClick={() => fileRef.current?.click()}>
        {uploading ? (
          <>
            <span className="spinner" /> Analyzing…
          </>
        ) : (
          <>
            <Icon.upload size={15} /> Drop or select
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
        <div className="eyebrow">Workspace</div>
        <h1 className="page-title">Local analysis</h1>
        <div className="page-desc">
          Upload an image to analyze it locally, then read it as signal, deepen with tool-backed jobs, and compare
          across your corpus.
        </div>
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
                  Images
                </span>
                <span className="mono" style={{ color: 'var(--text-faint)', fontSize: '0.8rem' }}>
                  {images.length}
                </span>
              </div>
              <div style={{ flex: 1 }} />
              {selected.size > 0 && (
                <button
                  type="button"
                  className="btn btn-sm btn-danger"
                  onClick={() =>
                    askDelete(
                      `Delete ${selected.size} image${selected.size === 1 ? '' : 's'}?`,
                      'This removes each image and any carved rootfs. This cannot be undone.',
                      async () => {
                        const ids = [...selected];
                        try {
                          await api.deleteImages(ids);
                          toast.success(`Deleted ${ids.length} image${ids.length === 1 ? '' : 's'}`);
                        } catch (e) {
                          toast.error(e);
                        }
                        setSelected(new Set());
                        setConfirm(null);
                        refresh();
                      },
                    )
                  }
                >
                  Delete selected ({selected.size})
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
                  placeholder="Filter by filename, arch, class, or tag…"
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
                  <div className="empty-title">No matches</div>
                  <div className="empty-body">
                    No image matches “{query}”. Clear the filter to see all {images.length}.
                  </div>
                  <button type="button" className="btn btn-sm" onClick={() => setQuery('')}>
                    Clear filter
                  </button>
                </div>
              </div>
            ) : (
              <div
                className="table-wrap"
                style={{ border: 'none', borderTop: '1px solid var(--border)', borderRadius: 0 }}
              >
                <table className="data">
                  <thead>
                    <tr>
                      <th style={{ width: 36 }} />
                      <Th k="filename">Filename</Th>
                      <Th k="firmwareClass">Class</Th>
                      <Th k="arch">Arch</Th>
                      <th>Tags</th>
                      <Th k="size" num>
                        Size
                      </Th>
                      <Th k="status">Status</Th>
                      <th style={{ width: 40 }} />
                    </tr>
                  </thead>
                  <tbody>
                    {shown.map((img) => (
                      <tr key={img.id} className="row-link" onClick={() => nav(`/image/${img.id}`)}>
                        <td onClick={(e) => e.stopPropagation()}>
                          <input
                            type="checkbox"
                            aria-label={`Select ${img.filename}`}
                            checked={selected.has(img.id)}
                            onChange={() => toggleSelect(img.id)}
                          />
                        </td>
                        <td className="mono" style={{ color: 'var(--text)', fontWeight: 500 }}>
                          {img.filename}
                        </td>
                        <td>
                          <span className="badge">{img.identity?.firmwareClass ?? 'unknown'}</span>
                        </td>
                        <td className="mono">{img.identity?.arch ?? '—'}</td>
                        <td onClick={(e) => e.stopPropagation()} style={{ maxWidth: 240 }}>
                          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', alignItems: 'center' }}>
                            {img.tags.map((t) => (
                              <button
                                type="button"
                                key={t}
                                className="badge"
                                title="Remove tag"
                                onClick={() => editTags(img, 'remove', t)}
                                style={{ cursor: 'pointer' }}
                              >
                                {t}{' '}
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
                                placeholder="tag…"
                                onChange={(e) => setTagDraft(e.target.value)}
                                onBlur={() => {
                                  const t = tagDraft.trim();
                                  if (t) editTags(img, 'add', t);
                                  setEditingTag(null);
                                  setTagDraft('');
                                }}
                                onKeyDown={(e) => {
                                  if (e.key === 'Enter') {
                                    const t = tagDraft.trim();
                                    if (t) editTags(img, 'add', t);
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
                                title="Add tag"
                                aria-label="Add tag"
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
                        <td className="num" style={{ textAlign: 'right' }}>
                          {fmtBytes(img.size)}
                        </td>
                        <td>
                          <span className={`badge ${STATUS_BADGE[img.status] ?? ''}`}>{img.status}</span>
                        </td>
                        <td onClick={(e) => e.stopPropagation()}>
                          <button
                            type="button"
                            className="icon-btn"
                            aria-label={`Delete ${img.filename}`}
                            title="Delete"
                            onClick={() =>
                              askDelete(
                                `Delete ${img.filename}?`,
                                'This removes the image and any carved rootfs.',
                                () => {
                                  api
                                    .deleteImage(img.id)
                                    .then(() => {
                                      setConfirm(null);
                                      refresh();
                                    })
                                    .catch(toast.error);
                                },
                              )
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
          danger
          onCancel={() => setConfirm(null)}
          onConfirm={confirm.run}
        />
      )}
    </div>
  );
}
