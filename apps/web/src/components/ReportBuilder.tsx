/*
 * ReportBuilder — the Findings & report stage. Compose a firmware security report from the analysis on the left
 * (toggle sections, reorder, fill the cover), see a live paper preview on the right, and export it as a
 * self-contained HTML file, Markdown, or PDF (via the browser's print-to-PDF). One report model feeds all three
 * renderers, so the preview and the exports never drift.
 */
import { useEffect, useMemo, useState } from 'react';
import { type Finding, type ImageSummary, type Job, type SbomResult, type StaticAnalysis, api, fmtBytes } from '../api';

type Block =
  | { kind: 'p'; text: string }
  | { kind: 'kv'; rows: [string, string][] }
  | { kind: 'table'; head: string[]; rows: string[][] }
  | { kind: 'findings'; rows: { sev: string; title: string; offset: string; source: string; proof: string }[] }
  | { kind: 'ul'; items: string[] };
interface Section {
  id: string;
  title: string;
  blocks: Block[];
}

const SEV_HEX: Record<string, string> = {
  critical: '#d3454f',
  high: '#bd671f',
  medium: '#977915',
  low: '#2c72af',
  info: '#67737f',
};
const PROOF_LABEL: Record<string, string> = {
  confirmed_full_system: 'confirmed (full-system)',
  confirmed_in_emulation: 'confirmed (emulated)',
  static_confirmed: 'static-confirmed',
  needs_runtime_reproduction: 'needs reproduction',
  blocked_by_platform: 'blocked (platform)',
  blocked_by_security: 'blocked (control)',
  false_positive: 'false positive',
};

const ALL_SECTIONS = [
  'summary',
  'identity',
  'entropy',
  'structure',
  'coverage',
  'findings',
  'sbom',
  'appendix',
] as const;
const SECTION_LABEL = {
  summary: 'Executive summary',
  identity: 'Firmware identity',
  entropy: 'Entropy profile',
  structure: 'Structure map',
  coverage: 'Analysis coverage',
  findings: 'Findings',
  sbom: 'Software bill of materials',
  appendix: 'Appendix — artefacts',
} as const;
const labelOf = (id: string): string => (SECTION_LABEL as Record<string, string>)[id] ?? id;

const hex = (n: number): string => `0x${n.toString(16)}`;
const esc = (s: string): string => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

export function ReportBuilder({
  imageId,
  image,
  analysis,
}: {
  imageId: string;
  image: ImageSummary;
  analysis: StaticAnalysis | null;
}): JSX.Element {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [sbom, setSbom] = useState<SbomResult | null>(null);
  const [order, setOrder] = useState<string[]>([...ALL_SECTIONS]);
  const [enabled, setEnabled] = useState<Record<string, boolean>>(
    Object.fromEntries(ALL_SECTIONS.map((s) => [s, true])),
  );
  const [title, setTitle] = useState(`${image.filename} — Firmware Security Assessment`);
  const [preparedBy, setPreparedBy] = useState('');
  const [classification, setClassification] = useState('Confidential');

  useEffect(() => {
    api
      .findings(imageId)
      .then(setFindings)
      .catch(() => setFindings([]));
    api
      .jobs(imageId)
      .then(setJobs)
      .catch(() => setJobs([]));
    api
      .sbom(imageId)
      .then(setSbom)
      .catch(() => setSbom(null));
  }, [imageId]);

  const ranKind = (k: string): boolean => jobs.some((j) => j.kind === k && j.status === 'done');
  const sevCount = (s: string): number => findings.filter((f) => f.severity === s).length;

  const sections = useMemo<Section[]>(() => {
    const idn = image.identity;
    const ent = analysis?.entropy;
    const build: Record<string, Section> = {
      summary: {
        id: 'summary',
        title: SECTION_LABEL.summary,
        blocks: [
          {
            kind: 'p',
            text:
              `This report covers the static firmware analysis of ${image.filename} ` +
              `(${fmtBytes(image.size)}), classified as ${idn?.firmwareClass ?? 'unknown'} on ` +
              `${idn?.arch ?? 'unknown'}/${idn?.endianness ?? 'unknown'}. ` +
              `${findings.length} finding${findings.length === 1 ? '' : 's'} were recorded` +
              `${sevCount('critical') || sevCount('high') ? ` — ${sevCount('critical')} critical, ${sevCount('high')} high` : ''}. ` +
              'Each finding carries an explicit proof state; a stage that has not run is reported as such rather than implied clean.',
          },
        ],
      },
      identity: {
        id: 'identity',
        title: SECTION_LABEL.identity,
        blocks: [
          {
            kind: 'kv',
            rows: [
              ['Class', idn?.firmwareClass ?? 'unknown'],
              ['Architecture', `${idn?.arch ?? 'unknown'} / ${idn?.endianness ?? 'unknown'}`],
              ['Filesystems', idn?.filesystems.join(', ') || '—'],
              ['Bootloader', idn?.bootloader ?? '—'],
              ['Vendor / model', [idn?.vendor, idn?.model].filter(Boolean).join(' / ') || '—'],
            ],
          },
          ...(idn?.classRationale ? [{ kind: 'p' as const, text: idn.classRationale }] : []),
        ],
      },
      entropy: {
        id: 'entropy',
        title: SECTION_LABEL.entropy,
        blocks: ent
          ? [
              {
                kind: 'kv',
                rows: [
                  ['Mean entropy', `${ent.mean.toFixed(2)} bits/byte`],
                  ['Max entropy', `${ent.max.toFixed(2)} bits/byte`],
                  ['Likely encrypted', ent.likelyEncrypted ? 'yes' : 'no'],
                  ['Likely compressed', ent.likelyCompressed ? 'yes' : 'no'],
                  ['High-entropy regions', String(ent.highEntropyRegions.length)],
                ],
              },
            ]
          : [{ kind: 'p', text: 'No entropy profile available.' }],
      },
      structure: {
        id: 'structure',
        title: SECTION_LABEL.structure,
        blocks: analysis?.structure?.length
          ? [
              {
                kind: 'table',
                head: ['Range', 'Category', 'Label'],
                rows: analysis.structure
                  .slice(0, 24)
                  .map((s) => [`${hex(s.start)}–${hex(s.end)}`, s.category, s.label || '—']),
              },
            ]
          : [{ kind: 'p', text: 'No structural segments carved.' }],
      },
      coverage: {
        id: 'coverage',
        title: SECTION_LABEL.coverage,
        blocks: [
          {
            kind: 'ul',
            items: [
              `${image.status === 'ready' ? '✓' : '×'} Static analysis`,
              `${ranKind('extract') ? '✓' : '○'} Extraction (rootfs)`,
              `${ranKind('sbom') ? '✓' : '○'} SBOM & CVEs`,
              `${ranKind('gitleaks') ? '✓' : '○'} Deep secret scan`,
              `${ranKind('decompile') ? '✓' : '○'} Binary triage`,
              `${jobs.some((j) => j.kind.startsWith('emulate') && j.status === 'done') ? '✓' : '○'} Emulation`,
            ],
          },
        ],
      },
      findings: {
        id: 'findings',
        title: `${SECTION_LABEL.findings} (${findings.length})`,
        blocks: findings.length
          ? [
              {
                kind: 'findings',
                rows: [...findings]
                  .sort(
                    (a, b) =>
                      ['critical', 'high', 'medium', 'low', 'info'].indexOf(a.severity) -
                      ['critical', 'high', 'medium', 'low', 'info'].indexOf(b.severity),
                  )
                  .map((f) => {
                    const off = (f.evidence as Record<string, unknown> | undefined)?.offset;
                    return {
                      sev: f.severity,
                      title: f.title,
                      offset: typeof off === 'number' ? hex(off) : '—',
                      source: f.source,
                      proof: PROOF_LABEL[f.proofState] ?? f.proofState,
                    };
                  }),
              },
            ]
          : [{ kind: 'p', text: 'No findings recorded. Note: zero findings is not the same as clean.' }],
      },
      sbom: {
        id: 'sbom',
        title: SECTION_LABEL.sbom,
        blocks:
          sbom?.available && sbom.packages?.length
            ? [
                {
                  kind: 'p',
                  text: `${sbom.packages.length} components inventoried; ${sbom.vulnerabilities?.length ?? 0} known vulnerabilities.`,
                },
                ...(sbom.vulnerabilities?.length
                  ? [
                      {
                        kind: 'table' as const,
                        head: ['CVE', 'Severity', 'Component', 'Fixed in'],
                        rows: sbom.vulnerabilities
                          .slice(0, 40)
                          .map((v) => [v.id, v.severity, `${v.packageName} ${v.packageVersion}`, v.fixedIn ?? '—']),
                      },
                    ]
                  : []),
              ]
            : [{ kind: 'p', text: 'No SBOM generated (needs extraction + syft). Not run.' }],
      },
      appendix: {
        id: 'appendix',
        title: SECTION_LABEL.appendix,
        blocks: [
          {
            kind: 'kv',
            rows: [
              ['SHA-256', image.sha256],
              ['Size', `${fmtBytes(image.size)} (${image.size} bytes)`],
              ['Image id', image.id],
            ],
          },
        ],
      },
    };
    return order
      .filter((id) => enabled[id])
      .map((id) => build[id])
      .filter((s): s is Section => s !== undefined);
  }, [order, enabled, image, analysis, findings, jobs, sbom, ranKind, sevCount]);

  const coverMeta = [classification, preparedBy && `Prepared by ${preparedBy}`, `${findings.length} findings`]
    .filter(Boolean)
    .join('  ·  ');

  const move = (id: string, dir: -1 | 1): void => {
    setOrder((o) => {
      const i = o.indexOf(id);
      const j = i + dir;
      if (j < 0 || j >= o.length) return o;
      const next = [...o];
      [next[i], next[j]] = [next[j] as string, next[i] as string];
      return next;
    });
  };

  const download = (name: string, mime: string, text: string): void => {
    const url = URL.createObjectURL(new Blob([text], { type: mime }));
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
  };
  const base = image.filename.replace(/\.[^.]+$/, '');

  return (
    <div className="report-builder">
      <div className="report-config">
        <div className="panel">
          <div className="panel-title">Report</div>
          <div style={{ display: 'grid', gap: 8, marginTop: 10 }}>
            <label className="eyebrow" htmlFor="rb-title">
              Title
            </label>
            <input id="rb-title" className="input" value={title} onChange={(e) => setTitle(e.target.value)} />
            <label className="eyebrow" htmlFor="rb-by">
              Prepared by
            </label>
            <input
              id="rb-by"
              className="input"
              placeholder="analyst / team"
              value={preparedBy}
              onChange={(e) => setPreparedBy(e.target.value)}
            />
            <label className="eyebrow" htmlFor="rb-cls">
              Classification
            </label>
            <input
              id="rb-cls"
              className="input"
              value={classification}
              onChange={(e) => setClassification(e.target.value)}
            />
          </div>

          <div className="eyebrow" style={{ marginTop: 16, marginBottom: 4 }}>
            Sections
          </div>
          {order.map((id, i) => (
            <div key={id} className={`report-toggle ${enabled[id] ? '' : 'off'}`}>
              <input
                type="checkbox"
                id={`rb-${id}`}
                checked={!!enabled[id]}
                onChange={() => setEnabled((e) => ({ ...e, [id]: !e[id] }))}
              />
              <label className="rt-label" htmlFor={`rb-${id}`}>
                {labelOf(id)}
              </label>
              <button
                type="button"
                className="report-move"
                disabled={i === 0}
                aria-label="Move up"
                onClick={() => move(id, -1)}
              >
                ↑
              </button>
              <button
                type="button"
                className="report-move"
                disabled={i === order.length - 1}
                aria-label="Move down"
                onClick={() => move(id, 1)}
              >
                ↓
              </button>
            </div>
          ))}

          <div style={{ display: 'grid', gap: 8, marginTop: 16 }}>
            <button type="button" className="btn btn-primary btn-sm" onClick={() => window.print()}>
              Print / Save as PDF
            </button>
            <div style={{ display: 'flex', gap: 8 }}>
              <button
                type="button"
                className="btn btn-sm"
                style={{ flex: 1 }}
                onClick={() => download(`${base}-report.html`, 'text/html', toHtml(title, coverMeta, sections))}
              >
                HTML
              </button>
              <button
                type="button"
                className="btn btn-sm"
                style={{ flex: 1 }}
                onClick={() => download(`${base}-report.md`, 'text/markdown', toMarkdown(title, coverMeta, sections))}
              >
                Markdown
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* live paper preview — the same model the exports use */}
      <div className="report-doc">
        <h1>{title}</h1>
        <div className="rd-cover-meta">{coverMeta}</div>
        {sections.map((s) => (
          <section key={s.id}>
            <h2>{s.title}</h2>
            {s.blocks.map((b, i) => (
              <PreviewBlock key={`${s.id}-${i}`} block={b} />
            ))}
          </section>
        ))}
      </div>
    </div>
  );
}

function PreviewBlock({ block }: { block: Block }): JSX.Element {
  switch (block.kind) {
    case 'p':
      return <p>{block.text}</p>;
    case 'kv':
      return (
        <dl className="rd-kv">
          {block.rows.map(([k, v]) => (
            <div key={k} style={{ display: 'contents' }}>
              <dt>{k}</dt>
              <dd className={/^0x|^[a-f0-9]{16,}/i.test(v) ? 'rd-mono' : undefined}>{v}</dd>
            </div>
          ))}
        </dl>
      );
    case 'ul':
      return (
        <ul>
          {block.items.map((it) => (
            <li key={it}>{it}</li>
          ))}
        </ul>
      );
    case 'table':
      return (
        <table>
          <thead>
            <tr>
              {block.head.map((h) => (
                <th key={h}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {block.rows.map((r, i) => (
              <tr key={i}>
                {r.map((c, j) => (
                  <td key={j} className={j === 0 ? 'rd-mono' : undefined}>
                    {c}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      );
    case 'findings':
      return (
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Finding</th>
              <th>Offset</th>
              <th>Source</th>
              <th>Proof state</th>
            </tr>
          </thead>
          <tbody>
            {block.rows.map((r, i) => (
              <tr key={i}>
                <td>
                  <span className="rd-sev" style={{ background: SEV_HEX[r.sev] ?? '#67737f' }} />
                  {r.sev}
                </td>
                <td>{r.title}</td>
                <td className="rd-mono">{r.offset}</td>
                <td className="rd-mono">{r.source}</td>
                <td>{r.proof}</td>
              </tr>
            ))}
          </tbody>
        </table>
      );
  }
}

// --- exporters (same model → HTML / Markdown) ---

function blockToHtml(b: Block): string {
  switch (b.kind) {
    case 'p':
      return `<p>${esc(b.text)}</p>`;
    case 'kv':
      return `<dl class="kv">${b.rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>`;
    case 'ul':
      return `<ul>${b.items.map((i) => `<li>${esc(i)}</li>`).join('')}</ul>`;
    case 'table':
      return `<table><thead><tr>${b.head.map((h) => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${b.rows
        .map((r) => `<tr>${r.map((c) => `<td>${esc(c)}</td>`).join('')}</tr>`)
        .join('')}</tbody></table>`;
    case 'findings':
      return `<table><thead><tr><th>Severity</th><th>Finding</th><th>Offset</th><th>Source</th><th>Proof state</th></tr></thead><tbody>${b.rows
        .map(
          (r) =>
            `<tr><td><span class="sev" style="background:${SEV_HEX[r.sev] ?? '#67737f'}"></span>${esc(r.sev)}</td><td>${esc(r.title)}</td><td class="mono">${esc(r.offset)}</td><td class="mono">${esc(r.source)}</td><td>${esc(r.proof)}</td></tr>`,
        )
        .join('')}</tbody></table>`;
  }
}

function toHtml(title: string, meta: string, sections: Section[]): string {
  const body = sections
    .map((s) => `<section><h2>${esc(s.title)}</h2>${s.blocks.map(blockToHtml).join('')}</section>`)
    .join('');
  return `<!doctype html><html><head><meta charset="utf-8"><title>${esc(title)}</title><style>
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#1b1d21;max-width:820px;margin:40px auto;padding:0 24px;line-height:1.62}
    h1{font-size:26px;letter-spacing:-.02em;margin:0 0 4px}.meta{color:#5b616b;font-size:13px;border-bottom:2px solid #1b1d21;padding-bottom:18px;margin-bottom:26px}
    h2{font-size:15px;text-transform:uppercase;letter-spacing:.06em;margin:30px 0 12px;padding-bottom:6px;border-bottom:1px solid #d9dce1}
    table{width:100%;border-collapse:collapse;font-size:12.5px;margin:6px 0 14px}th{text-align:left;border-bottom:1.5px solid #1b1d21;padding:6px 8px;font-size:10.5px;text-transform:uppercase;color:#4a505a}
    td{border-bottom:1px solid #e6e8ec;padding:6px 8px;vertical-align:top}.mono{font-family:ui-monospace,Menlo,monospace}
    .kv{display:grid;grid-template-columns:190px 1fr;gap:4px 16px}.kv dt{color:#5b616b}.kv dd{margin:0;font-weight:500}
    .sev{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;vertical-align:middle}ul{padding-left:20px}
  </style></head><body><h1>${esc(title)}</h1><div class="meta">${esc(meta)}</div>${body}</body></html>`;
}

function blockToMd(b: Block): string {
  switch (b.kind) {
    case 'p':
      return `${b.text}\n`;
    case 'kv':
      return `${b.rows.map(([k, v]) => `**${k}:** ${v}`).join('  \n')}\n`;
    case 'ul':
      return `${b.items.map((i) => `- ${i}`).join('\n')}\n`;
    case 'table':
      return `| ${b.head.join(' | ')} |\n| ${b.head.map(() => '---').join(' | ')} |\n${b.rows
        .map((r) => `| ${r.join(' | ')} |`)
        .join('\n')}\n`;
    case 'findings':
      return `| Severity | Finding | Offset | Source | Proof state |\n| --- | --- | --- | --- | --- |\n${b.rows
        .map((r) => `| ${r.sev} | ${r.title} | ${r.offset} | ${r.source} | ${r.proof} |`)
        .join('\n')}\n`;
  }
}

function toMarkdown(title: string, meta: string, sections: Section[]): string {
  return `# ${title}\n\n_${meta}_\n\n${sections.map((s) => `## ${s.title}\n\n${s.blocks.map(blockToMd).join('\n')}`).join('\n')}`;
}
