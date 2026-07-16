import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { type ImageSummary, api, fmtBytes } from '../api';

export function Dashboard(): JSX.Element {
  const [images, setImages] = useState<ImageSummary[]>([]);
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
  }, []);
  useEffect(refresh, [refresh]);

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
        <div className="panel-title">Images</div>
        <div className="panel-sub">
          {images.length} analyzed image{images.length === 1 ? '' : 's'}
        </div>
        {images.length === 0 ? (
          <div className="empty">No images yet — upload one above to begin.</div>
        ) : (
          <table className="data">
            <thead>
              <tr>
                <th>Filename</th>
                <th>Class</th>
                <th>Arch</th>
                <th>Filesystems</th>
                <th>Size</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {images.map((img) => (
                <tr key={img.id} style={{ cursor: 'pointer' }} onClick={() => nav(`/image/${img.id}`)}>
                  <td className="mono">{img.filename}</td>
                  <td>{img.identity?.firmwareClass ?? '—'}</td>
                  <td className="mono">{img.identity?.arch ?? '—'}</td>
                  <td className="mono">{img.identity?.filesystems.join(', ') || '—'}</td>
                  <td className="mono">{fmtBytes(img.size)}</td>
                  <td>
                    <span
                      className={`badge ${img.status === 'ready' ? 'badge-ok' : img.status === 'error' ? 'badge-high' : ''}`}
                    >
                      {img.status}
                    </span>
                  </td>
                  <td>
                    <button
                      className="btn btn-sm"
                      onClick={(e) => {
                        e.stopPropagation();
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
        )}
      </div>
    </div>
  );
}
