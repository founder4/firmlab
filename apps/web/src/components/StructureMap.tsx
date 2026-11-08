/**
 * Structure map — the "binwalk graphical view": a proportional horizontal ribbon of the image, each segment
 * colored by its signature category (filesystem, compression, bootloader, executable…). Selecting or hovering
 * a segment shows its offset range, label and recorded header fields. The native selector works without hover.
 *
 * **What a band claims.** A segment is a signature match: a magic number saying what it believes starts at that
 * offset. It is not a verdict on what the bytes are, and the stretch between two matches is unclaimed rather than
 * empty — a ribbon drawn edge to edge invites the opposite reading, so the caveat under it is part of the picture.
 *
 * Controls and explanatory sentences are localised. Segment labels, categories, confidences and header fields are
 * what the carve recorded, and the `0x…` ruler and byte counts are notation; all of them render as produced.
 */
import { useEffect, useId, useState } from 'react';
import type { StructureSegment } from '../api';
import { categoryColor, fmtBytes, fmtHex } from '../api';
import { useMessages } from '../i18n';

interface Props {
  segments: StructureSegment[];
  size: number;
}

export function StructureMap({ segments, size }: Props): JSX.Element {
  const t = useMessages();
  const id = useId();
  const [hovered, setHovered] = useState<number | null>(null);
  const [selected, setSelected] = useState<number | null>(null);
  const active = hovered ?? selected;
  const total = size || 1;
  useEffect(() => {
    setHovered(null);
    setSelected(null);
  }, [segments, size]);

  return (
    <div>
      <div
        aria-hidden="true"
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
              onMouseEnter={() => setHovered(i)}
              onMouseLeave={() => setHovered((cur) => (cur === i ? null : cur))}
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

      {segments.length > 0 && (
        <div className="structure-inspector">
          <label htmlFor={`${id}-segment`}>{t.visuals.structure.inspectLabel}</label>
          <select
            id={`${id}-segment`}
            className="select"
            value={selected === null ? '' : String(selected)}
            aria-controls={`${id}-details`}
            onFocus={() => setHovered(null)}
            onChange={(event) => {
              setHovered(null);
              setSelected(event.target.value === '' ? null : Number(event.target.value));
            }}
          >
            <option value="">{t.visuals.structure.chooseSegment}</option>
            {segments.map((segment, index) => (
              <option key={`${segment.start}-${index}`} value={index}>
                {fmtHex(segment.start)}–{fmtHex(segment.end)} · {segment.label}
              </option>
            ))}
          </select>
        </div>
      )}

      {/* Hover previews the map; an explicit selection stays available after pointer or keyboard focus leaves. */}
      <section
        id={`${id}-details`}
        aria-label={t.visuals.structure.detailsLabel}
        className="panel structure-segment-details"
        style={{ marginTop: 14, marginBottom: 0, background: 'var(--bg-panel-2)' }}
      >
        {(() => {
          const seg = active !== null ? segments[active] : null;
          if (!seg)
            return (
              <span className="hint">
                {segments.length > 0 ? t.visuals.structure.hoverPrompt : t.visuals.structure.emptyPrompt}
              </span>
            );
          return (
            <div>
              <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 10, marginBottom: 6 }}>
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
      </section>

      <Legend segments={segments} />

      {/* The ribbon fills the width whatever the carve found, so what it does NOT claim has to be written down. */}
      <p className="hint" style={{ margin: '10px 0 0', maxWidth: '72ch' }}>
        {t.visuals.structure.caveat}
      </p>
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
