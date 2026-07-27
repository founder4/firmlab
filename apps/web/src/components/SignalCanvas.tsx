/*
 * SignalCanvas — the workbench's centrepiece. The firmware image is a spatial "tape" you read left-to-right along
 * its byte axis: the entropy profile is the signal trace (the lime), the carved structure is a band beneath it on
 * the SAME 0x0…size axis, and findings are markers pinned at their byte offset. Scrub it to read the exact offset,
 * local entropy, the segment you're over, and any finding there. Everything else in the image view is a lens over
 * this one anchor.
 */
import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { type EntropyProfile, type Finding, type StructureSegment, api } from '../api';

interface Props {
  imageId: string;
  size: number;
  findings: Finding[];
  /** Byte offset the user parked on, lifted to the parent so lenses can react to it. */
  onScrub?: (offset: number | null) => void;
}

const TRACE_H = 150; // entropy band height
const BAND_H = 26; // structure band height
const MARK_H = 14; // finding-marker gutter
const AXIS_H = 18;
const HEIGHT = MARK_H + TRACE_H + BAND_H + AXIS_H;

const CAT_VAR = (c: string): string => `var(--cat-${c}, var(--cat-other))`;
const hex = (n: number): string => `0x${Math.round(n).toString(16)}`;

function findingOffset(f: Finding): number | null {
  const ev = f.evidence as Record<string, unknown> | undefined;
  const o = ev?.offset;
  return typeof o === 'number' ? o : null;
}

export function SignalCanvas({ imageId, size, findings, onScrub }: Props): JSX.Element {
  const [profile, setProfile] = useState<EntropyProfile | null>(null);
  const [segments, setSegments] = useState<StructureSegment[]>([]);
  const [loading, setLoading] = useState(true);
  const [w, setW] = useState(900);
  const [hoverX, setHoverX] = useState<number | null>(null);
  const wrapRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    Promise.all([api.entropy(imageId).catch(() => null), api.structure(imageId).catch(() => null)]).then(([e, s]) => {
      if (!alive) return;
      setProfile(e?.entropy ?? null);
      setSegments(s?.structure ?? []);
      setLoading(false);
    });
    return () => {
      alive = false;
    };
  }, [imageId]);

  useLayoutEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      const cw = entries[0]?.contentRect.width;
      if (cw) setW(Math.max(320, cw));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const total = size || profile?.samples.at(-1)?.offset || 1;
  const xOf = (offset: number): number => (offset / total) * w;
  const traceTop = MARK_H;
  const bandTop = MARK_H + TRACE_H;

  // Entropy area path (downsampled to the pixel width so a 512-KB image doesn't draw 100k points).
  const samples = profile?.samples ?? [];
  let tracePath = '';
  let areaPath = '';
  if (samples.length > 1) {
    const step = Math.max(1, Math.floor(samples.length / Math.max(1, w)));
    const pts: [number, number][] = [];
    for (let i = 0; i < samples.length; i += step) {
      const s = samples[i] as { offset: number; entropy: number };
      pts.push([xOf(s.offset), traceTop + (1 - s.entropy / 8) * TRACE_H]);
    }
    const last = samples.at(-1) as { offset: number; entropy: number };
    pts.push([xOf(last.offset), traceTop + (1 - last.entropy / 8) * TRACE_H]);
    tracePath = pts.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(1)} ${y.toFixed(1)}`).join(' ');
    areaPath = `${tracePath} L${pts.at(-1)?.[0].toFixed(1)} ${traceTop + TRACE_H} L${pts[0]?.[0].toFixed(1)} ${traceTop + TRACE_H} Z`;
  }

  const marks = findings
    .map((f) => ({ f, off: findingOffset(f) }))
    .filter((m): m is { f: Finding; off: number } => m.off !== null);

  // What sits under the cursor.
  const hoverOffset = hoverX !== null ? (hoverX / w) * total : null;
  const hoverSeg =
    hoverOffset !== null ? (segments.find((s) => hoverOffset >= s.start && hoverOffset < s.end) ?? null) : null;
  const hoverEnt =
    hoverOffset !== null && samples.length
      ? (samples.reduce((best, s) =>
          Math.abs(s.offset - hoverOffset) < Math.abs(best.offset - hoverOffset) ? s : best,
        ).entropy as number)
      : null;
  const hoverMark =
    hoverOffset !== null ? (marks.find((m) => Math.abs(xOf(m.off) - (hoverX ?? -99)) < 6)?.f ?? null) : null;

  const cats = [...new Set(segments.map((s) => s.category))];

  return (
    <div>
      <div
        ref={wrapRef}
        style={{ position: 'relative', width: '100%', userSelect: 'none' }}
        onMouseMove={(e) => {
          const r = wrapRef.current?.getBoundingClientRect();
          if (!r) return;
          const x = Math.min(w, Math.max(0, e.clientX - r.left));
          setHoverX(x);
          onScrub?.((x / w) * total);
        }}
        onMouseLeave={() => {
          setHoverX(null);
          onScrub?.(null);
        }}
      >
        {loading ? (
          <div className="skeleton" style={{ height: HEIGHT, borderRadius: 8 }} />
        ) : (
          <svg width={w} height={HEIGHT} style={{ display: 'block' }} aria-label="Signal tape">
            <title>Firmware signal tape</title>
            <defs>
              <linearGradient id="sigGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.5" />
                <stop offset="100%" stopColor="var(--accent)" stopOpacity="0.04" />
              </linearGradient>
            </defs>

            {/* entropy gridlines at 2/4/6 bits */}
            {[2, 4, 6].map((b) => {
              const y = traceTop + (1 - b / 8) * TRACE_H;
              return <line key={b} x1={0} y1={y} x2={w} y2={y} stroke="var(--border-soft)" strokeWidth={1} />;
            })}
            {/* 7.2 compressed/encrypted floor */}
            <line
              x1={0}
              y1={traceTop + (1 - 7.2 / 8) * TRACE_H}
              x2={w}
              y2={traceTop + (1 - 7.2 / 8) * TRACE_H}
              stroke="var(--warn)"
              strokeWidth={1}
              strokeDasharray="4 4"
              opacity={0.7}
            />

            {/* entropy signal */}
            {areaPath && <path d={areaPath} fill="url(#sigGrad)" />}
            {tracePath && <path d={tracePath} fill="none" stroke="var(--accent)" strokeWidth={1.4} />}

            {/* structure band */}
            {segments.map((s, i) => (
              <rect
                key={`${s.start}-${i}`}
                x={xOf(s.start)}
                y={bandTop}
                width={Math.max(1, xOf(s.end) - xOf(s.start))}
                height={BAND_H}
                fill={CAT_VAR(s.category)}
                opacity={hoverSeg && hoverSeg !== s ? 0.4 : 0.9}
                stroke="var(--bg)"
                strokeWidth={0.75}
              />
            ))}

            {/* finding markers */}
            {marks.map(({ f, off }, i) => (
              <polygon
                key={f.id ?? i}
                points={`${xOf(off) - 4},0 ${xOf(off) + 4},0 ${xOf(off)},${MARK_H - 2}`}
                fill={`var(--sev-${f.severity})`}
              />
            ))}

            {/* axis ticks */}
            {[0, 0.25, 0.5, 0.75, 1].map((f) => {
              const x = f * w;
              return (
                <text
                  key={f}
                  x={Math.min(w - 2, Math.max(2, x))}
                  y={HEIGHT - 5}
                  fontSize={10}
                  fontFamily="var(--mono)"
                  fill="var(--text-faint)"
                  textAnchor={f === 0 ? 'start' : f === 1 ? 'end' : 'middle'}
                >
                  {hex(f * total)}
                </text>
              );
            })}

            {/* scrub crosshair */}
            {hoverX !== null && (
              <line
                x1={hoverX}
                y1={0}
                x2={hoverX}
                y2={bandTop + BAND_H}
                stroke="var(--accent)"
                strokeWidth={1}
                opacity={0.8}
              />
            )}
          </svg>
        )}

        {/* scrub readout */}
        {hoverX !== null && hoverOffset !== null && (
          <div
            className="mono"
            style={{
              position: 'absolute',
              top: 4,
              left: Math.min(w - 220, Math.max(0, hoverX + 10)),
              pointerEvents: 'none',
              background: 'var(--bg-elev)',
              border: '1px solid var(--border-strong)',
              borderRadius: 'var(--r-md)',
              padding: '6px 9px',
              fontSize: '0.72rem',
              lineHeight: 1.5,
              boxShadow: 'var(--shadow-2)',
              whiteSpace: 'nowrap',
              zIndex: 2,
            }}
          >
            <div style={{ color: 'var(--accent)' }}>{hex(hoverOffset)}</div>
            {hoverEnt !== null && <div style={{ color: 'var(--text-dim)' }}>H {hoverEnt.toFixed(2)} bits</div>}
            {hoverSeg && <div style={{ color: CAT_VAR(hoverSeg.category) }}>{hoverSeg.label || hoverSeg.category}</div>}
            {hoverMark && <div style={{ color: `var(--sev-${hoverMark.severity})` }}>● {hoverMark.title}</div>}
          </div>
        )}
      </div>

      {/* category legend */}
      {cats.length > 0 && (
        <div className="legend" style={{ marginTop: 10 }}>
          {cats.map((c) => (
            <span key={c} className="legend-item">
              <span className="legend-swatch" style={{ background: CAT_VAR(c) }} />
              {c}
            </span>
          ))}
          {marks.length > 0 && (
            <span className="legend-item" style={{ marginLeft: 'auto', color: 'var(--text-faint)' }}>
              ▲ {marks.length} finding{marks.length === 1 ? '' : 's'} pinned to offsets
            </span>
          )}
        </div>
      )}
    </div>
  );
}
