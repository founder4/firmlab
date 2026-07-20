import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { type ImageSummary, api, fmtBytes } from '../api';
import { Icon } from '../icons';
import { toast } from '../toast';

type SortKey = 'filename' | 'firmwareClass' | 'arch' | 'size' | 'status';
type SortDir = 'asc' | 'desc';

const STATUS_BADGE: Record<string, string> = { ready: 'badge-ok', error: 'badge-crit', analyzing: 'badge-medium' };

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
  const fileRef = useRef<HTMLInputElement>(null);
  const nav = useNavigate();

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

  const deleteSelected = useCallback(async () => {
    const ids = [...selected];
    if (
      !window.confirm(
        `Delete ${ids.length} image${ids.length === 1 ? '' : 's'}? This removes the image and any carved rootfs.`,
      )
    )
      return;
    try {
      await api.deleteImages(ids);
      toast.success(`Deleted ${ids.length} image${ids.length === 1 ? '' : 's'}`);
    } catch (e) {
      toast.error(e);
    }
    setSelected(new Set());
    refresh();
  }, [selected, refresh]);

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

  const hasImages = images.length > 0;

  const Uploader = (
    <div
      data-tour="upload"
      className="panel"
      onDragOver={(e) => {
        e.preventDefault();
        setDragOver(true);
      }}
      onDragLeave={() => setDragOver(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragOver(false);
        const f = e.dataTransfer.files[0];
        if (f) upload(f);
      }}
      style={{
        border: `1.5px dashed ${dragOver ? 'var(--accent)' : 'var(--border-strong)'}`,
        background: dragOver ? 'color-mix(in srgb, var(--accent) 6%, var(--bg-panel))' : 'var(--bg-panel)',
        display: 'flex',
        alignItems: 'center',
        gap: 16,
        flexWrap: 'wrap',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, flex: '1 1 300px' }}>
        <div
          style={{
            width: 40,
            height: 40,
            borderRadius: 'var(--r-md)',
            display: 'grid',
            placeItems: 'center',
            background: 'var(--bg-inset)',
            color: 'var(--accent)',
            flexShrink: 0,
          }}
        >
          <Icon.upload size={20} />
        </div>
        <div style={{ minWidth: 0 }}>
          <div style={{ fontWeight: 600 }}>Analyze a firmware image</div>
          <div className="hint mono" style={{ marginTop: 2 }}>
            .bin .img .trx .squashfs .ubi .jffs2 .elf .dtb … — analyzed locally, nothing leaves this machine
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
            <Icon.upload size={15} /> Drop or select image
          </>
        )}
      </button>
      <input
        ref={fileRef}
        type="file"
        hidden
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) upload(f);
        }}
      />
      {error && (
        <div className="banner banner-warn" style={{ width: '100%', margin: 0 }}>
          {error}
        </div>
      )}
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
        <div>
          <div className="eyebrow">Workspace</div>
          <h1 className="page-title">Dashboard</h1>
          <div className="page-desc">
            Upload firmware to analyze it locally, then explore, compare, and manage your images.
          </div>
        </div>
        <div className="grid grid-3" style={{ gap: 10, gridTemplateColumns: 'repeat(2, minmax(120px, 1fr))' }}>
          <div className="stat is-accent">
            <div className="stat-label">Images</div>
            <div className="stat-value mono">{images.length}</div>
          </div>
          <div className="stat">
            <div className="stat-label">On disk</div>
            <div className="stat-value mono">{usage ? fmtBytes(usage.totalBytes) : '—'}</div>
          </div>
        </div>
      </div>

      {Uploader}

      <div className="panel panel-flush">
        <div className="panel-head">
          <div className="panel-title" style={{ margin: 0 }}>
            Images
          </div>
          {hasImages && (
            <div className="tip" style={{ position: 'relative', flex: '1 1 220px', maxWidth: 340 }}>
              <span
                style={{
                  position: 'absolute',
                  left: 10,
                  top: '50%',
                  transform: 'translateY(-50%)',
                  color: 'var(--text-faint)',
                }}
              >
                <Icon.search size={14} />
              </span>
              <input
                className="input"
                placeholder="Filter by filename, arch, class, or tag…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                style={{ width: '100%', paddingLeft: 30 }}
              />
            </div>
          )}
          <div style={{ flex: 1 }} />
          {selected.size > 0 && (
            <button type="button" className="btn btn-sm btn-danger" onClick={deleteSelected}>
              Delete selected ({selected.size})
            </button>
          )}
          {usage && usage.quotaBytes > 0 && (
            <span className="hint">
              {fmtBytes(usage.totalBytes)} / {fmtBytes(usage.quotaBytes)} quota
            </span>
          )}
        </div>

        {loading ? (
          <div style={{ padding: 16, display: 'grid', gap: 8 }}>
            {[0, 1, 2].map((i) => (
              <div key={i} className="skeleton" style={{ height: 34 }} />
            ))}
          </div>
        ) : !hasImages ? (
          <div style={{ padding: 20 }}>
            <div className="empty">
              <div className="empty-mark">0x0000</div>
              <div className="empty-title">No firmware yet</div>
              <div className="empty-body">
                Upload an image above to get an instant structure map, entropy profile, identity, and secret scan — no
                toolchain required.
              </div>
            </div>
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
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th style={{ width: 34 }} />
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
                  <tr key={img.id} style={{ cursor: 'pointer' }} onClick={() => nav(`/image/${img.id}`)}>
                    <td onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        aria-label={`Select ${img.filename}`}
                        checked={selected.has(img.id)}
                        onChange={() => toggleSelect(img.id)}
                      />
                    </td>
                    <td className="mono">{img.filename}</td>
                    <td>{img.identity?.firmwareClass ?? '—'}</td>
                    <td className="mono">{img.identity?.arch ?? '—'}</td>
                    <td onClick={(e) => e.stopPropagation()} style={{ maxWidth: 220 }}>
                      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', alignItems: 'center' }}>
                        {img.tags.map((t) => (
                          <button
                            type="button"
                            key={t}
                            className="badge"
                            title="Remove tag"
                            onClick={() => editTags(img, 'remove', t)}
                          >
                            {t} <span aria-hidden="true">✕</span>
                          </button>
                        ))}
                        <button
                          type="button"
                          className="btn btn-sm btn-ghost"
                          title="Add tag"
                          style={{ padding: '1px 6px' }}
                          onClick={() => {
                            const t = window.prompt(`Add tag to ${img.filename}`)?.trim();
                            if (t) editTags(img, 'add', t);
                          }}
                        >
                          ＋
                        </button>
                      </div>
                    </td>
                    <td className="num">{fmtBytes(img.size)}</td>
                    <td>
                      <span className={`badge ${STATUS_BADGE[img.status] ?? ''}`}>{img.status}</span>
                    </td>
                    <td onClick={(e) => e.stopPropagation()}>
                      <button
                        type="button"
                        className="btn btn-sm btn-ghost btn-danger"
                        aria-label={`Delete ${img.filename}`}
                        title="Delete"
                        onClick={() => {
                          if (window.confirm(`Delete ${img.filename}?`)) api.deleteImage(img.id).then(refresh);
                        }}
                      >
                        ✕
                      </button>
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
