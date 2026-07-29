/*
 * ReportBuilder — the Findings & report stage. Compose a firmware security report from the analysis on the left
 * (toggle sections, reorder, fill the cover), see a live paper preview on the right, and export it as a
 * self-contained HTML file, Markdown, or PDF (via the browser's print-to-PDF). One report model feeds all three
 * renderers, so the preview and the exports never drift.
 *
 * **Its strings are the deliverable, not decoration.** This document leaves the workbench: nobody who reads the
 * exported PDF can check a claim against the panel it came from. So the scaffolding is localised through the
 * `report` namespace and the honesty sentences are carried there by name — that every finding has an explicit
 * proof state and an unrun stage is reported as such rather than implied clean, that operator assertions count
 * towards neither the total nor any stage, and that zero findings is not the same as clean.
 *
 * The proof-state gloss and the section names that also name a screen are read from the SHARED `proofState` and
 * `sections` namespaces. This file used to keep private `PROOF_LABEL` and `SECTION_LABEL` maps that duplicated
 * them, which is two copies of one meaning free to drift — and the copy nobody edits is the one that ships.
 * `section.findings` stays local because `sections.findings` names the SCREEN ("Findings & report"), which is
 * self-referential as a heading inside the report itself.
 */
import { useEffect, useMemo, useState } from 'react';
import { type Finding, type ImageSummary, type Job, type SbomResult, type StaticAnalysis, api, fmtBytes } from '../api';
import { type Messages, messages, useMessages } from '../i18n';

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

/** One place the eight headings are named, drawing from `sections` wherever that namespace already holds the word. */
const labelOf = (id: string, t: Messages): string => {
  switch (id) {
    case 'summary':
      return t.report.section.summary;
    case 'identity':
      return t.report.section.identity;
    case 'entropy':
      return t.sections.entropy;
    case 'structure':
      return t.sections.structure;
    case 'coverage':
      return t.report.section.coverage;
    case 'findings':
      return t.report.section.findings;
    case 'sbom':
      return t.sections.sbom;
    case 'appendix':
      return t.report.section.appendix;
    default:
      return id;
  }
};

/** The findings table's column headers, shared by the preview and both exporters so the three cannot disagree. */
const findingsHead = (t: Messages): string[] => [
  t.report.findings.severity,
  t.report.findings.finding,
  t.report.findings.offset,
  t.report.findings.source,
  t.report.findings.proof,
];

/** Column shares for that table, in the same order. Shared with `toHtml` for the same reason the headers are. */
const FINDINGS_COLS = ['11%', '39%', '9%', '16%', '25%'];

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
  const t = useMessages();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [sbom, setSbom] = useState<SbomResult | null>(null);
  const [order, setOrder] = useState<string[]>([...ALL_SECTIONS]);
  const [enabled, setEnabled] = useState<Record<string, boolean>>(
    Object.fromEntries(ALL_SECTIONS.map((s) => [s, true])),
  );
  // Seeded once. A later language switch must not overwrite a cover the operator has already typed into.
  const [title, setTitle] = useState(() => t.report.defaultTitle(image.filename));
  const [preparedBy, setPreparedBy] = useState('');
  const [classification, setClassification] = useState(() => t.report.classificationDefault);

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

  // The ledger route serves measured rows and operator assertions in ONE array, separated only by the
  // `operator_assertion` sentinel on `proofState`. Sorting that array into the findings table put a person's claim
  // in the measured population under a "Proof state" column — printing the sentinel itself, since the proof-state
  // gloss is written for measurements — which is the exact interleaving the server-side renderer was built to make
  // impossible. The two populations are split here, once, and every count below is taken from `measured`.
  const measured = findings.filter((f) => f.proofState !== 'operator_assertion');
  const asserted = findings.filter((f) => f.proofState === 'operator_assertion');
  const sevCount = (s: string): number => measured.filter((f) => f.severity === s).length;

  const sections = useMemo<Section[]>(() => {
    const idn = image.identity;
    const ent = analysis?.entropy;
    const unknown = t.common.unknown;
    const sevNote =
      sevCount('critical') || sevCount('high')
        ? t.report.summary.severityNote(sevCount('critical'), sevCount('high'))
        : '';
    const build: Record<string, Section> = {
      summary: {
        id: 'summary',
        title: t.report.section.summary,
        blocks: [
          {
            kind: 'p',
            // Sentences joined rather than concatenated so each language builds its own and each stays readable.
            text: [
              t.report.summary.scope(
                image.filename,
                fmtBytes(image.size),
                idn?.firmwareClass ?? unknown,
                idn?.arch ?? unknown,
                idn?.endianness ?? unknown,
              ),
              t.report.summary.recorded(measured.length, sevNote),
              t.report.summary.proofDiscipline,
              ...(asserted.length ? [t.report.summary.assertionsExcluded(asserted.length)] : []),
            ].join(' '),
          },
        ],
      },
      identity: {
        id: 'identity',
        title: t.report.section.identity,
        blocks: [
          {
            kind: 'kv',
            rows: [
              [t.report.identity.firmwareClass, idn?.firmwareClass ?? unknown],
              [t.report.identity.arch, `${idn?.arch ?? unknown} / ${idn?.endianness ?? unknown}`],
              [t.report.identity.filesystems, idn?.filesystems.join(', ') || '—'],
              [t.report.identity.bootloader, idn?.bootloader ?? '—'],
              [t.report.identity.vendorModel, [idn?.vendor, idn?.model].filter(Boolean).join(' / ') || '—'],
            ],
          },
          ...(idn?.classRationale ? [{ kind: 'p' as const, text: idn.classRationale }] : []),
        ],
      },
      entropy: {
        id: 'entropy',
        title: t.sections.entropy,
        blocks: ent
          ? [
              {
                kind: 'kv',
                rows: [
                  [t.report.entropy.mean, t.report.entropy.bitsPerByte(ent.mean.toFixed(2))],
                  [t.report.entropy.max, t.report.entropy.bitsPerByte(ent.max.toFixed(2))],
                  [t.report.entropy.likelyEncrypted, ent.likelyEncrypted ? t.common.yes : t.common.no],
                  [t.report.entropy.likelyCompressed, ent.likelyCompressed ? t.common.yes : t.common.no],
                  [t.report.entropy.highEntropyRegions, String(ent.highEntropyRegions.length)],
                ],
              },
            ]
          : [{ kind: 'p', text: t.report.entropy.none }],
      },
      structure: {
        id: 'structure',
        title: t.sections.structure,
        blocks: analysis?.structure?.length
          ? [
              {
                kind: 'table',
                head: [t.report.structure.range, t.report.structure.category, t.report.structure.label],
                rows: analysis.structure
                  .slice(0, 24)
                  .map((s) => [`${hex(s.start)}–${hex(s.end)}`, s.category, s.label || '—']),
              },
            ]
          : [{ kind: 'p', text: t.report.structure.none }],
      },
      coverage: {
        id: 'coverage',
        title: t.report.section.coverage,
        blocks: [
          {
            kind: 'ul',
            items: [
              `${image.status === 'ready' ? '✓' : '×'} ${t.report.coverage.staticAnalysis}`,
              `${ranKind('extract') ? '✓' : '○'} ${t.report.coverage.extraction}`,
              `${ranKind('sbom') ? '✓' : '○'} ${t.sections.sbom}`,
              `${ranKind('gitleaks') ? '✓' : '○'} ${t.report.coverage.secrets}`,
              `${ranKind('decompile') ? '✓' : '○'} ${t.report.coverage.binaries}`,
              `${jobs.some((j) => j.kind.startsWith('emulate') && j.status === 'done') ? '✓' : '○'} ${t.report.coverage.emulation}`,
            ],
          },
        ],
      },
      findings: {
        id: 'findings',
        title: t.report.findings.heading(t.report.section.findings, measured.length),
        blocks: [
          ...(measured.length
            ? ([
                {
                  kind: 'findings',
                  rows: [...measured]
                    .sort(
                      (a, b) =>
                        ['critical', 'high', 'medium', 'low', 'info'].indexOf(a.severity) -
                        ['critical', 'high', 'medium', 'low', 'info'].indexOf(b.severity),
                    )
                    .map((f) => {
                      const off = (f.evidence as Record<string, unknown> | undefined)?.offset;
                      return {
                        sev: f.severity,
                        // A row obtained against an altered subject says so IN THE TITLE, not in a column a
                        // reader can skim past. This document leaves the workbench and nobody reading the PDF
                        // can check it against the panel it came from, so the qualification has to travel with
                        // the claim itself.
                        title: f.interventions?.length
                          ? `${f.title} ${t.report.findings.interventionSuffix(f.interventions.join('; '))}`
                          : f.title,
                        offset: typeof off === 'number' ? hex(off) : '—',
                        source: f.source,
                        proof: t.proofState.label[f.proofState],
                      };
                    }),
                },
              ] as Block[])
            : ([{ kind: 'p', text: t.report.findings.none }] as Block[])),
          // Assertions follow the measured table, never inside it, and carry no proof-state column — there is no
          // proof state to print. The heading says what they are before the reader reaches a single row.
          ...(asserted.length
            ? ([
                {
                  kind: 'p',
                  text: [
                    t.report.assertions.heading(asserted.length),
                    t.report.assertions.provenance,
                    t.report.assertions.excluded,
                  ].join(' '),
                },
                {
                  kind: 'table',
                  head: [
                    t.report.assertions.claim,
                    t.report.assertions.statement,
                    t.report.assertions.assertedBy,
                    t.report.assertions.recorded,
                  ],
                  rows: asserted.map((f) => [
                    f.assertion?.claim ?? 'asserted_unverified',
                    f.title,
                    f.assertion?.assertedBy
                      ? `${f.assertion.assertedBy}${f.assertion.authorKind === 'agent' ? t.report.assertions.agentSuffix : ''}`
                      : t.report.assertions.unrecorded,
                    new Date(f.createdAt).toISOString().slice(0, 10),
                  ]),
                },
              ] as Block[])
            : []),
        ],
      },
      sbom: {
        id: 'sbom',
        title: t.sections.sbom,
        blocks:
          sbom?.available && sbom.packages?.length
            ? [
                {
                  kind: 'p',
                  text: t.report.sbom.inventory(sbom.packages.length, sbom.vulnerabilities?.length ?? 0),
                },
                ...(sbom.vulnerabilities?.length
                  ? [
                      {
                        kind: 'table' as const,
                        // `CVE` is the identifier's own name, not a word to translate.
                        head: ['CVE', t.report.sbom.severity, t.report.sbom.component, t.report.sbom.fixedIn],
                        rows: sbom.vulnerabilities
                          .slice(0, 40)
                          .map((v) => [v.id, v.severity, `${v.packageName} ${v.packageVersion}`, v.fixedIn ?? '—']),
                      },
                    ]
                  : []),
              ]
            : [{ kind: 'p', text: t.report.sbom.none }],
      },
      appendix: {
        id: 'appendix',
        title: t.report.section.appendix,
        blocks: [
          {
            kind: 'kv',
            rows: [
              // The digest names its own algorithm; only the two labels beside it are prose.
              ['SHA-256', image.sha256],
              [t.report.appendix.size, t.report.appendix.sizeWithBytes(fmtBytes(image.size), image.size)],
              [t.report.appendix.imageId, image.id],
            ],
          },
        ],
      },
    };
    return order
      .filter((id) => enabled[id])
      .map((id) => build[id])
      .filter((s): s is Section => s !== undefined);
  }, [order, enabled, image, analysis, findings, jobs, sbom, ranKind, sevCount, t]);

  // Counted from `measured`, like every other total in the document: a cover reading "3 findings" over an executive
  // summary reading "1 finding was recorded" is the same interleaving the table below refuses, moved to the top.
  const coverMeta = [
    classification,
    preparedBy && t.report.coverPreparedBy(preparedBy),
    t.report.coverFindings(measured.length),
  ]
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
          <div className="panel-title">{t.report.panelTitle}</div>
          <div style={{ display: 'grid', gap: 8, marginTop: 10 }}>
            <label className="eyebrow" htmlFor="rb-title">
              {t.report.fieldTitle}
            </label>
            <input id="rb-title" className="input" value={title} onChange={(e) => setTitle(e.target.value)} />
            <label className="eyebrow" htmlFor="rb-by">
              {t.report.fieldPreparedBy}
            </label>
            <input
              id="rb-by"
              className="input"
              placeholder={t.report.preparedByPlaceholder}
              value={preparedBy}
              onChange={(e) => setPreparedBy(e.target.value)}
            />
            <label className="eyebrow" htmlFor="rb-cls">
              {t.report.fieldClassification}
            </label>
            <input
              id="rb-cls"
              className="input"
              value={classification}
              onChange={(e) => setClassification(e.target.value)}
            />
          </div>

          <div className="eyebrow" style={{ marginTop: 16, marginBottom: 4 }}>
            {t.report.sectionsHeading}
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
                {labelOf(id, t)}
              </label>
              <button
                type="button"
                className="report-move"
                disabled={i === 0}
                aria-label={t.report.moveUp}
                onClick={() => move(id, -1)}
              >
                ↑
              </button>
              <button
                type="button"
                className="report-move"
                disabled={i === order.length - 1}
                aria-label={t.report.moveDown}
                onClick={() => move(id, 1)}
              >
                ↓
              </button>
            </div>
          ))}

          <div style={{ display: 'grid', gap: 8, marginTop: 16 }}>
            <button type="button" className="btn btn-primary btn-sm" onClick={() => window.print()}>
              {t.report.print}
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
  const t = useMessages();
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
          {/* Four of the five columns hold a fixed vocabulary — a severity, an offset, a source, a proof state —
              and only the title is open-ended. Left to `table-layout: auto` the title takes the width in
              proportion to its length and squeezes the rest until `Severity` wraps to "Severi/ty". The share is
              stated instead, here and in the HTML export, so the preview and the file agree. */}
          <colgroup>
            {FINDINGS_COLS.map((w) => (
              <col key={w} style={{ width: w }} />
            ))}
          </colgroup>
          <thead>
            <tr>
              {findingsHead(t).map((h) => (
                <th key={h}>{h}</th>
              ))}
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
//
// These run from a click handler rather than a render, so they read the catalogue through `messages()` instead of
// the hook. Same store, same locale: the export a reader downloads is in the language they were reading.

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
      return `<table><colgroup>${FINDINGS_COLS.map((w) => `<col style="width:${w}">`).join('')}</colgroup><thead><tr>${findingsHead(
        messages(),
      )
        .map((h) => `<th>${esc(h)}</th>`)
        .join('')}</tr></thead><tbody>${b.rows
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
    /* Same rule as the preview: a proof state and a SHA-256 are unbreakable words, and a printed page cannot scroll. */
    th,td,.kv dd{overflow-wrap:anywhere}
    .kv{display:grid;grid-template-columns:minmax(0,190px) minmax(0,1fr);gap:4px 16px}.kv dt{color:#5b616b}.kv dd{margin:0;font-weight:500}
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
    case 'findings': {
      const head = findingsHead(messages());
      return `| ${head.join(' | ')} |\n| ${head.map(() => '---').join(' | ')} |\n${b.rows
        .map((r) => `| ${r.sev} | ${r.title} | ${r.offset} | ${r.source} | ${r.proof} |`)
        .join('\n')}\n`;
    }
  }
}

function toMarkdown(title: string, meta: string, sections: Section[]): string {
  return `# ${title}\n\n_${meta}_\n\n${sections.map((s) => `## ${s.title}\n\n${s.blocks.map(blockToMd).join('\n')}`).join('\n')}`;
}
