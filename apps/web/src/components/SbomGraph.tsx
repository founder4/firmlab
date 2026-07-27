/*
 * SbomGraph — the SBOM stage as a graph instead of a flat table. The extracted rootfs sits at the centre; every
 * inventoried component hangs off it, grouped by ecosystem (deb, apk, npm, binary…) around the ring and coloured
 * by the worst CVE that affects it. Vulnerable components pull toward the centre with a hotter edge, so a glance
 * shows where the risk clusters. Hover a node to read its version and CVEs. Pure: it renders whatever SBOM it is
 * given.
 */
import { useLayoutEffect, useRef, useState } from 'react';
import type { SbomResult } from '../api';

type Sev = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'none';
const SEV_ORDER: Sev[] = ['critical', 'high', 'medium', 'low', 'info', 'none'];
const SEV_VAR: Record<Sev, string> = {
  critical: 'var(--sev-critical)',
  high: 'var(--sev-high)',
  medium: 'var(--sev-medium)',
  low: 'var(--sev-low)',
  info: 'var(--sev-info)',
  none: 'var(--text-faint)',
};

interface Node {
  name: string;
  version: string;
  type: string;
  worst: Sev;
  cves: { id: string; severity: string }[];
}

function normSev(s: string): Sev {
  const l = s.toLowerCase();
  return (['critical', 'high', 'medium', 'low', 'info'] as Sev[]).includes(l as Sev) ? (l as Sev) : 'info';
}

export function SbomGraph({ sbom }: { sbom: SbomResult }): JSX.Element {
  const [w, setW] = useState(760);
  const [hover, setHover] = useState<Node | null>(null);
  const wrapRef = useRef<HTMLDivElement>(null);

  useLayoutEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver((e) => {
      const cw = e[0]?.contentRect.width;
      if (cw) setW(Math.max(360, cw));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Match CVEs to components; keep the worst severity per component.
  const cveByPkg = new Map<string, { id: string; severity: string }[]>();
  for (const v of sbom.vulnerabilities ?? []) {
    const list = cveByPkg.get(v.packageName) ?? [];
    list.push({ id: v.id, severity: v.severity });
    cveByPkg.set(v.packageName, list);
  }
  const nodes: Node[] = (sbom.packages ?? []).map((p) => {
    const cves = cveByPkg.get(p.name) ?? [];
    const worst =
      cves.reduce<Sev>((acc, c) => {
        const s = normSev(c.severity);
        return SEV_ORDER.indexOf(s) < SEV_ORDER.indexOf(acc) ? s : acc;
      }, 'none') ?? 'none';
    return { name: p.name, version: p.version, type: p.type || 'other', worst, cves };
  });

  // Group by ecosystem and order so each ecosystem occupies a contiguous arc; vulnerable nodes first within a group.
  const groups = [...new Set(nodes.map((n) => n.type))].sort();
  const ordered = groups.flatMap((g) =>
    nodes.filter((n) => n.type === g).sort((a, b) => SEV_ORDER.indexOf(a.worst) - SEV_ORDER.indexOf(b.worst)),
  );

  const height = Math.min(680, Math.max(420, w * 0.62));
  const cx = w / 2;
  const cy = height / 2;
  const R = Math.min(cx, cy) - 54;
  const N = Math.max(1, ordered.length);

  const pos = (i: number, r: number): [number, number] => {
    const a = (i / N) * 2 * Math.PI - Math.PI / 2;
    return [cx + Math.cos(a) * r, cy + Math.sin(a) * r];
  };

  const vulnCount = nodes.filter((n) => n.worst !== 'none').length;

  return (
    <div>
      <div ref={wrapRef} style={{ position: 'relative', width: '100%' }}>
        <svg width={w} height={height} style={{ display: 'block' }} aria-label="SBOM component graph">
          <title>SBOM component graph</title>
          {/* edges */}
          {ordered.map((n, i) => {
            const vuln = n.worst !== 'none';
            const [x, y] = pos(i, vuln ? R * 0.82 : R);
            return (
              <line
                key={`e-${n.name}-${i}`}
                x1={cx}
                y1={cy}
                x2={x}
                y2={y}
                stroke={vuln ? SEV_VAR[n.worst] : 'var(--border)'}
                strokeWidth={vuln ? 1.2 : 0.6}
                opacity={vuln ? 0.7 : 0.4}
              />
            );
          })}
          {/* ecosystem arc labels */}
          {groups.map((g) => {
            const idxs = ordered.map((n, i) => (n.type === g ? i : -1)).filter((i) => i >= 0);
            const mid = idxs[Math.floor(idxs.length / 2)] ?? 0;
            const [x, y] = pos(mid, R + 30);
            return (
              <text
                key={`g-${g}`}
                x={x}
                y={y}
                fontSize={10}
                fontFamily="var(--mono)"
                fill="var(--text-faint)"
                textAnchor={x < cx - 10 ? 'end' : x > cx + 10 ? 'start' : 'middle'}
                dominantBaseline="middle"
              >
                {g} · {idxs.length}
              </text>
            );
          })}
          {/* component nodes */}
          {ordered.map((n, i) => {
            const vuln = n.worst !== 'none';
            const [x, y] = pos(i, vuln ? R * 0.82 : R);
            const rr = 3 + Math.min(6, n.cves.length * 1.6) + (n === hover ? 2 : 0);
            return (
              <circle
                key={`n-${n.name}-${i}`}
                cx={x}
                cy={y}
                r={rr}
                fill={SEV_VAR[n.worst]}
                stroke="var(--bg)"
                strokeWidth={0.75}
                opacity={hover && n !== hover ? 0.5 : 1}
                style={{ cursor: 'pointer' }}
                onMouseEnter={() => setHover(n)}
                onMouseLeave={() => setHover(null)}
              />
            );
          })}
          {/* centre: the rootfs */}
          <circle cx={cx} cy={cy} r={26} fill="var(--bg-inset)" stroke="var(--accent)" strokeWidth={1.5} />
          <text x={cx} y={cy - 2} fontSize={11} fontFamily="var(--mono)" fill="var(--accent)" textAnchor="middle">
            rootfs
          </text>
          <text x={cx} y={cy + 11} fontSize={9} fontFamily="var(--mono)" fill="var(--text-dim)" textAnchor="middle">
            {nodes.length} pkgs
          </text>
        </svg>

        {hover && (
          <div
            className="mono"
            style={{
              position: 'absolute',
              top: 8,
              left: 8,
              pointerEvents: 'none',
              background: 'var(--bg-elev)',
              border: '1px solid var(--border-strong)',
              borderRadius: 'var(--r-md)',
              padding: '8px 10px',
              fontSize: '0.72rem',
              boxShadow: 'var(--shadow-2)',
              maxWidth: 260,
            }}
          >
            <div style={{ color: 'var(--text)' }}>
              {hover.name} <span style={{ color: 'var(--text-dim)' }}>{hover.version}</span>
            </div>
            <div style={{ color: 'var(--text-faint)' }}>{hover.type}</div>
            {hover.cves.length > 0 ? (
              <div style={{ marginTop: 4, color: SEV_VAR[hover.worst] }}>
                {hover.cves
                  .slice(0, 6)
                  .map((c) => c.id)
                  .join(', ')}
                {hover.cves.length > 6 ? ` +${hover.cves.length - 6}` : ''}
              </div>
            ) : (
              <div style={{ marginTop: 4, color: 'var(--text-faint)' }}>no known CVEs</div>
            )}
          </div>
        )}
      </div>

      <div className="legend" style={{ marginTop: 10 }}>
        {(['critical', 'high', 'medium', 'low'] as Sev[]).map((s) => (
          <span key={s} className="legend-item">
            <span className="legend-swatch" style={{ background: SEV_VAR[s], borderRadius: '50%' }} />
            {s}
          </span>
        ))}
        <span className="legend-item">
          <span className="legend-swatch" style={{ background: SEV_VAR.none, borderRadius: '50%' }} />
          no CVE
        </span>
        <span className="legend-item" style={{ marginLeft: 'auto', color: 'var(--text-faint)' }}>
          {vulnCount} of {nodes.length} components affected · node size = CVE count
        </span>
      </div>
    </div>
  );
}
