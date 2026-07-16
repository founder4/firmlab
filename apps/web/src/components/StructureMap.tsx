/**
 * Structure map — the "binwalk graphical view": a proportional horizontal ribbon of the image, each segment
 * colored by its signature category (filesystem, compression, bootloader, executable…). Hovering a segment
 * shows its offset range, label, and any decoded header fields. This is the at-a-glance layout of the image.
 */
import { useState } from 'react';
import type { StructureSegment } from '../api';
import { categoryColor, fmtBytes, fmtHex } from '../api';

interface Props {
  segments: StructureSegment[];
  size: number;
}

export function StructureMap({ segments, size }: Props): JSX.Element {
  const [active, setActive] = useState<number | null>(null);
  const total = size || 1;

  return (
    <div>
      <div
        style={{
          display: 'flex',
          width: '100%',
          height: 54,
          borderRadius: 8,
          overflow: 'hidden',
          border: '1px solid var(--border)',
        }}
      >
        {segments.map((seg, i) => {
          const pct = ((seg.end - seg.start) / total) * 100;
          const color = categoryColor(seg.category);
          return (
            <div
              key={i}
              onMouseEnter={() => setActive(i)}
              onMouseLeave={() => setActive((cur) => (cur === i ? null : cur))}
              title={`${seg.label} (${fmtHex(seg.start)}–${fmtHex(seg.end)})`}
              style={{
                width: `${pct}%`,
                minWidth: pct < 0.4 ? 2 : undefined,
                background: color,
                opacity: active === null || active === i ? 0.92 : 0.5,
                borderRight: '1px solid rgba(0,0,0,0.35)',
                cursor: 'pointer',
                transition: 'opacity 0.12s',
              }}
            />
          );
        })}
      </div>

      {/* Offset ruler */}
      <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4 }} className="hint mono">
        <span>0x0</span>
        <span>{fmtHex(Math.round(size / 2))}</span>
        <span>{fmtHex(size)}</span>
      </div>

      {/* Detail of the hovered / first segment */}
      <div className="panel" style={{ marginTop: 14, marginBottom: 0, background: 'var(--bg-panel-2)' }}>
        {(() => {
          const seg = active !== null ? segments[active] : null;
          if (!seg) return <span className="hint">Hover a segment to inspect it.</span>;
          return (
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                <span
                  className="legend-swatch"
                  style={{ background: categoryColor(seg.category), width: 13, height: 13 }}
                />
                <strong>{seg.label}</strong>
                <span className="badge">{seg.category}</span>
                <span className="badge">{seg.confidence}</span>
              </div>
              <div className="mono hint">
                {fmtHex(seg.start)} – {fmtHex(seg.end)} · {fmtBytes(seg.end - seg.start)}
              </div>
              {seg.meta && (
                <div className="mono hint" style={{ marginTop: 6 }}>
                  {Object.entries(seg.meta).map(([k, v]) => (
                    <span key={k} style={{ marginRight: 14 }}>
                      {k}=<span style={{ color: 'var(--text)' }}>{String(v)}</span>
                    </span>
                  ))}
                </div>
              )}
            </div>
          );
        })()}
      </div>

      <Legend segments={segments} />
    </div>
  );
}

function Legend({ segments }: { segments: StructureSegment[] }): JSX.Element {
  const cats = [...new Set(segments.map((s) => s.category))];
  return (
    <div className="legend" style={{ marginTop: 14 }}>
      {cats.map((c) => (
        <div className="legend-item" key={c}>
          <span className="legend-swatch" style={{ background: categoryColor(c) }} />
          {c}
        </div>
      ))}
    </div>
  );
}
