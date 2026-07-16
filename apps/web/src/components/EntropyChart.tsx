/**
 * Entropy graph — Shannon entropy (bits/byte, 0..8) across the image offset. High-entropy bands
 * (compressed/encrypted) are shaded so the eye lands on them immediately; the 7.2 threshold line marks the
 * compressed/encrypted floor. Pure SVG, no chart library, so it stays fast and self-contained.
 */
import { useMemo, useState } from 'react';
import type { EntropyProfile } from '../api';
import { fmtHex } from '../api';

interface Props {
  entropy: EntropyProfile;
  size: number;
  height?: number;
}

const PAD = { top: 12, right: 12, bottom: 26, left: 34 };

export function EntropyChart({ entropy, size, height = 220 }: Props): JSX.Element {
  const [hover, setHover] = useState<{ x: number; offset: number; value: number } | null>(null);
  const width = 900;
  const plotW = width - PAD.left - PAD.right;
  const plotH = height - PAD.top - PAD.bottom;

  const { path, area, points } = useMemo(() => {
    const samples = entropy.samples;
    if (samples.length === 0)
      return { path: '', area: '', points: [] as { x: number; y: number; s: (typeof samples)[0] }[] };
    const maxOff = size || 1;
    const pts = samples.map((s) => {
      const x = PAD.left + (s.offset / maxOff) * plotW;
      const y = PAD.top + (1 - s.entropy / 8) * plotH;
      return { x, y, s };
    });
    const line = pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');
    const areaPath = `${line} L${pts[pts.length - 1]?.x.toFixed(1)},${(PAD.top + plotH).toFixed(1)} L${pts[0]?.x.toFixed(1)},${(PAD.top + plotH).toFixed(1)} Z`;
    return { path: line, area: areaPath, points: pts };
  }, [entropy, size, plotW, plotH]);

  const thresholdY = PAD.top + (1 - 7.2 / 8) * plotH;

  function onMove(e: React.MouseEvent<SVGSVGElement>): void {
    const rect = e.currentTarget.getBoundingClientRect();
    const px = ((e.clientX - rect.left) / rect.width) * width;
    if (px < PAD.left || px > PAD.left + plotW || points.length === 0) {
      setHover(null);
      return;
    }
    const ratio = (px - PAD.left) / plotW;
    const idx = Math.min(points.length - 1, Math.max(0, Math.round(ratio * (points.length - 1))));
    const p = points[idx];
    if (p) setHover({ x: p.x, offset: p.s.offset, value: p.s.entropy });
  }

  return (
    <div>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        style={{ width: '100%', height: 'auto', display: 'block' }}
        onMouseMove={onMove}
        onMouseLeave={() => setHover(null)}
        role="img"
        aria-label="Entropy across image offset"
      >
        <defs>
          <linearGradient id="entGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#4db5ff" stopOpacity="0.35" />
            <stop offset="100%" stopColor="#4db5ff" stopOpacity="0.02" />
          </linearGradient>
        </defs>

        {/* High-entropy region shading */}
        {entropy.highEntropyRegions.map((r, i) => {
          const x1 = PAD.left + (r.start / (size || 1)) * plotW;
          const x2 = PAD.left + (r.end / (size || 1)) * plotW;
          return (
            <rect key={i} x={x1} y={PAD.top} width={Math.max(1, x2 - x1)} height={plotH} fill="#f5b642" opacity={0.1} />
          );
        })}

        {/* Y grid + labels (0,2,4,6,8) */}
        {[0, 2, 4, 6, 8].map((v) => {
          const y = PAD.top + (1 - v / 8) * plotH;
          return (
            <g key={v}>
              <line x1={PAD.left} y1={y} x2={PAD.left + plotW} y2={y} stroke="#202839" strokeWidth={1} />
              <text x={PAD.left - 6} y={y + 3} fontSize={10} fill="#5b6577" textAnchor="end">
                {v}
              </text>
            </g>
          );
        })}

        {/* Threshold line at 7.2 */}
        <line
          x1={PAD.left}
          y1={thresholdY}
          x2={PAD.left + plotW}
          y2={thresholdY}
          stroke="#f5b642"
          strokeWidth={1}
          strokeDasharray="4 4"
          opacity={0.6}
        />

        {area && <path d={area} fill="url(#entGrad)" />}
        {path && <path d={path} fill="none" stroke="#4db5ff" strokeWidth={1.2} />}

        {/* X offset labels */}
        {[0, 0.25, 0.5, 0.75, 1].map((f) => {
          const x = PAD.left + f * plotW;
          return (
            <text key={f} x={x} y={height - 8} fontSize={10} fill="#5b6577" textAnchor="middle">
              {fmtHex(Math.round(f * size))}
            </text>
          );
        })}

        {hover && (
          <g>
            <line
              x1={hover.x}
              y1={PAD.top}
              x2={hover.x}
              y2={PAD.top + plotH}
              stroke="#d7dce6"
              strokeWidth={0.6}
              opacity={0.4}
            />
            <circle cx={hover.x} cy={PAD.top + (1 - hover.value / 8) * plotH} r={3} fill="#4db5ff" />
          </g>
        )}
      </svg>
      <div className="hint" style={{ minHeight: 18, marginTop: 4 }}>
        {hover ? (
          <span className="mono">
            offset {fmtHex(hover.offset)} · H = {hover.value.toFixed(2)} bits/byte
          </span>
        ) : (
          <span>
            Mean {entropy.mean.toFixed(2)} · Max {entropy.max.toFixed(2)} · dashed line = 7.2 compressed/encrypted floor
          </span>
        )}
      </div>
    </div>
  );
}
