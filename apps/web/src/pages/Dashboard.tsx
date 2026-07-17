import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { type ImageSummary, type StorageUsage, api, fmtBytes } from '../api';
import { toast } from '../toast';

export function Dashboard(): JSX.Element {
  const [images, setImages] = useState<ImageSummary[]>([]);
  const [usage, setUsage] = useState<StorageUsage | null>(null);
  const [query, setQuery] = useState('');
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const nav = useNavigate();

  const refresh = useCallback(() => {
    api
      .listImages()
      .then(setImages)
      .catch(() => setImages([]));
    api
      .storage()
      .then(setUsage)
      .catch(() => setUsage(null));
  }, []);
  useEffect(refresh, [refresh]);

  const [selected, setSelected] = useState<Set<string>>(new Set());

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return images;
    return images.filter(
      (im) =>
        im.filename.toLowerCase().includes(q) ||
        (im.identity?.arch ?? '').toLowerCase().includes(q) ||
        (im.identity?.firmwareClass ?? '').toLowerCase().includes(q) ||
        im.tags.some((t) => t.toLowerCase().includes(q)),
    );
  }, [images, query]);

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

  return (
    <div>
      <div
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
          border: `1.5px dashed ${dragOver ? 'var(--accent)' : 'var(--border)'}`,
          background: dragOver ? 'rgba(77,181,255,0.05)' : 'var(--bg-panel)',
          textAlign: 'center',
          padding: '38px 20px',
        }}
      >
        <div style={{ fontSize: 30, marginBottom: 8 }}>⬆</div>
        <div style={{ fontWeight: 600, marginBottom: 4 }}>Drop a firmware image, or click to browse</div>
        <div className="hint" style={{ marginBottom: 16 }}>
          .bin .img .trx .squashfs .ubi .jffs2 .elf .dtb … — analyzed locally, nothing leaves this machine
        </div>
        <button className="btn btn-primary" disabled={uploading} onClick={() => fileRef.current?.click()}>
          {uploading ? (
            <>
              <span className="spinner" /> Analyzing…
            </>
          ) : (
            'Select firmware image'
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
          <div className="banner banner-warn" style={{ marginTop: 16 }}>
            {error}
          </div>
        )}
      </div>

      <div className="panel">
        <div className="panel-title">
          Images
          {usage && (
            <span className="hint" style={{ marginLeft: 'auto', fontWeight: 400 }}>
              {fmtBytes(usage.totalBytes)} on disk
              {usage.quotaBytes > 0 ? ` / ${fmtBytes(usage.quotaBytes)} quota` : ''}
            </span>
          )}
        </div>
        <div className="panel-sub">
          {images.length} analyzed image{images.length === 1 ? '' : 's'}
        </div>
        {images.length > 0 && (
          <div style={{ display: 'flex', gap: 8, marginBottom: 14, flexWrap: 'wrap', alignItems: 'center' }}>
            <input
              className="input"
              placeholder="Filter by filename, arch, class, or tag…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              style={{ flex: '1 1 220px', minWidth: 0 }}
            />
            {selected.size > 0 && (
              <button className="btn btn-sm" onClick={deleteSelected}>
                Delete selected ({selected.size})
              </button>
            )}
          </div>
        )}
        {images.length === 0 ? (
          <div className="empty">No images yet — upload one above to begin.</div>
        ) : shown.length === 0 ? (
          <div className="empty">No images match “{query}”.</div>
        ) : (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th />
                  <th>Filename</th>
                  <th>Class</th>
                  <th>Arch</th>
                  <th>Tags</th>
                  <th>Size</th>
                  <th>Status</th>
                  <th />
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
                            className="badge badge-info"
                            title="Remove tag"
                            onClick={() => editTags(img, 'remove', t)}
                          >
                            {t} ✕
                          </button>
                        ))}
                        <button
                          type="button"
                          className="btn btn-sm"
                          style={{ padding: '2px 7px' }}
                          onClick={() => {
                            const t = window.prompt(`Add tag to ${img.filename}`)?.trim();
                            if (t) editTags(img, 'add', t);
                          }}
                        >
                          ＋
                        </button>
                      </div>
                    </td>
                    <td className="mono">{fmtBytes(img.size)}</td>
                    <td>
                      <span
                        className={`badge ${img.status === 'ready' ? 'badge-ok' : img.status === 'error' ? 'badge-high' : ''}`}
                      >
                        {img.status}
                      </span>
                    </td>
                    <td onClick={(e) => e.stopPropagation()}>
                      <button
                        className="btn btn-sm"
                        onClick={() => {
                          api.deleteImage(img.id).then(refresh);
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
