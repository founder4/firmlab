/**
 * Findings report generator. Assembles a single self-contained HTML document for one image — identity, the findings
 * ledger, entropy signal, structure summary, raw secrets, and whatever tool-backed results exist (SBOM/CVEs,
 * gitleaks, binary triage) — so an analyst can archive or share a run without the live workbench. Pure string
 * building: no tool invocation, no external assets (inline CSS), safe to open offline.
 *
 * The ledger is rendered by `report-assertions.ts`, which is store-free and unit-tested. Two populations share that
 * table and this document is read without any of the workbench's live context, so the separation between what code
 * measured and what a person asserted has to be visible in the HTML itself: the two arrive here as two finished
 * strings, placed in two different parts of the page, and this module never gets the pieces to interleave.
 *
 * **Language.** The locale is a parameter, defaulting to English, and every sentence comes from `../i18n` — this
 * module holds no prose of its own. `<html lang>` and the generated-at date follow it, so a screen reader and the
 * reader's own eye agree with the text. What does NOT follow it: the image's own data. Filenames, hashes,
 * architectures, filesystem names, package names, CVE ids, severities and every finding title print exactly as
 * recorded, and the ISO timestamp stays in `<time datetime>` beside the localised date so the document remains
 * checkable against a log.
 */
import type { ImageIdentity, StaticAnalysis } from '@firmlab/core';
import { rowToFinding } from '../findings.js';
import { type Locale, formatTimestamp, htmlLang, messages } from '../i18n/index.js';
import { getImage, listFindings, listJobs } from '../store.js';
import type { DecompileResult } from './decompile.js';
import type { GitleaksResult } from './gitleaks.js';
import { LEDGER_CSS, escapeHtml as esc, renderLedgerSections } from './report-assertions.js';
import type { SbomResult } from './sbom.js';

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(2)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

/** Latest successful result of a job kind, parsed, or null. */
function latestResult<T>(imageId: string, kind: string): T | null {
  const done = listJobs(imageId).find((j) => j.kind === kind && j.status === 'done' && j.resultJson);
  if (!done?.resultJson) return null;
  try {
    return JSON.parse(done.resultJson) as T;
  } catch {
    return null;
  }
}

function table(headers: string[], rows: string[][], empty: string): string {
  if (rows.length === 0) return `<p class="muted">${empty}</p>`;
  const head = headers.map((h) => `<th>${esc(h)}</th>`).join('');
  const body = rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join('')}</tr>`).join('');
  return `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}

function section(title: string, inner: string): string {
  return `<section><h2>${esc(title)}</h2>${inner}</section>`;
}

/**
 * Build the full self-contained HTML report for an image; returns null if the image is unknown.
 *
 * `locale` defaults to English — the language every caller got before the parameter existed, and the one an
 * unrecognised `?lang` resolves to.
 */
export function generateReport(imageId: string, locale: Locale = 'en'): string | null {
  const row = getImage(imageId);
  if (!row) return null;

  const t = messages(locale);
  const identity: ImageIdentity | null = row.identityJson ? JSON.parse(row.identityJson) : null;
  const analysis: StaticAnalysis | null = row.analysisJson ? JSON.parse(row.analysisJson) : null;
  const sbom = latestResult<SbomResult>(imageId, 'sbom');
  const gitleaks = latestResult<GitleaksResult>(imageId, 'gitleaks');
  const triage = latestResult<DecompileResult>(imageId, 'decompile');
  const ledger = renderLedgerSections(listFindings(imageId).map(rowToFinding), locale);
  const generatedAt = new Date().toISOString();
  // The reader gets the date written the way their locale writes it; the machine-readable ISO stamp stays in the
  // `datetime` attribute, so an archived report is still checkable against a log line.
  const generatedHtml = `<time datetime="${esc(generatedAt)}">${esc(formatTimestamp(generatedAt, locale))}</time>`;

  const identityRows: string[][] = identity
    ? [
        [t.report.identityRows.firmwareClass, esc(identity.firmwareClass)],
        [t.report.identityRows.arch, `${esc(identity.arch)} / ${esc(identity.endianness)}`],
        [t.report.identityRows.filesystems, esc(identity.filesystems.join(', ') || '—')],
        [t.report.identityRows.bootloader, esc(identity.bootloader ?? '—')],
      ]
    : [];

  const identitySection = section(
    t.report.identityHeading,
    table([t.report.identityColumns.field, t.report.identityColumns.value], identityRows, t.report.none) +
      (analysis
        ? `<p class="muted">${t.report.entropy({
            mean: analysis.entropy.mean.toFixed(2),
            signal: analysis.entropy.likelyEncrypted
              ? 'encrypted'
              : analysis.entropy.likelyCompressed
                ? 'compressed'
                : 'none',
            signatures: analysis.signatures.length,
            segments: analysis.structure.length,
          })}</p>`
        : ''),
  );

  const secretsSection = analysis
    ? section(
        t.report.secretsHeading(analysis.secrets.length),
        table(
          [
            t.report.secretsColumns.severity,
            t.report.secretsColumns.kind,
            t.report.secretsColumns.offset,
            t.report.secretsColumns.value,
          ],
          analysis.secrets
            .slice(0, 200)
            .map((s) => [
              esc(s.severity),
              esc(s.secretKind),
              `0x${s.offset.toString(16)}`,
              `<code>${esc(s.value)}</code>`,
            ]),
          t.report.none,
        ),
      )
    : '';

  const sbomSection = sbom?.available
    ? section(
        t.report.sbomHeading,
        `<p>${t.report.sbomSummary({
          packages: sbom.packageCount,
          cves: sbom.vulnerabilities.length,
          critical: sbom.counts.Critical,
          high: sbom.counts.High,
          medium: sbom.counts.Medium,
        })}</p>${table(
          [
            t.report.sbomColumns.severity,
            t.report.sbomColumns.cve,
            t.report.sbomColumns.pkg,
            t.report.sbomColumns.version,
            t.report.sbomColumns.fixedIn,
          ],
          sbom.vulnerabilities
            .slice(0, 300)
            .map((v) => [
              esc(v.severity),
              `<code>${esc(v.id)}</code>`,
              esc(v.packageName),
              esc(v.packageVersion),
              esc(v.fixedIn ?? '—'),
            ]),
          t.report.none,
        )}`,
      )
    : '';

  const gitleaksSection = gitleaks?.available
    ? section(
        t.report.gitleaksHeading(gitleaks.findingCount),
        table(
          [
            t.report.gitleaksColumns.rule,
            t.report.gitleaksColumns.file,
            t.report.gitleaksColumns.line,
            t.report.gitleaksColumns.match,
          ],
          gitleaks.findings
            .slice(0, 300)
            .map((f) => [esc(f.rule), `<code>${esc(f.file)}</code>`, String(f.line), `<code>${esc(f.match)}</code>`]),
          t.report.none,
        ),
      )
    : '';

  const triageSection = triage?.available
    ? section(
        t.report.triageHeading(triage.binary),
        `<p>${t.report.triageSummary({
          arch: `${esc(triage.info.arch ?? '?')}${triage.info.bits ? `/${triage.info.bits}` : ''}`,
          nx: triage.info.nx === true,
          canary: triage.info.canary === true,
          functions: triage.functionCount,
          imports: triage.imports.length,
          strings: triage.strings.length,
        })}</p>${table(
          [t.report.triageColumns.import, t.report.triageColumns.library],
          triage.imports.slice(0, 200).map((i) => [`<code>${esc(i.name)}</code>`, esc(i.libname ?? '—')]),
          t.report.none,
        )}`,
      )
    : '';

  return `<!doctype html>
<html lang="${htmlLang(locale)}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(t.report.title(row.filename))}</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 14px/1.5 -apple-system, system-ui, sans-serif; max-width: 960px; margin: 0 auto; padding: 32px 20px; color: #1b1f27; background: #fff; }
  @media (prefers-color-scheme: dark) { body { background: #0b0e14; color: #d6dbe5; } th { background: #161b25 !important; } td, th { border-color: #232a38 !important; } code { background: #161b25 !important; } }
  h1 { font-size: 22px; margin: 0 0 4px; }
  h2 { font-size: 15px; margin: 28px 0 10px; border-bottom: 1px solid #d9dee8; padding-bottom: 6px; }
  .meta { color: #6b7488; font-size: 12px; font-family: ui-monospace, monospace; }
  table { border-collapse: collapse; width: 100%; font-size: 12.5px; margin: 6px 0; }
  th, td { border: 1px solid #e3e7ef; padding: 5px 8px; text-align: left; vertical-align: top; word-break: break-word; }
  th { background: #f4f6fa; font-size: 11px; text-transform: uppercase; letter-spacing: .4px; }
  code { font-family: ui-monospace, monospace; background: #f4f6fa; padding: 1px 4px; border-radius: 3px; font-size: 12px; }
  .muted { color: #6b7488; }
  .mono { font-family: ui-monospace, monospace; }
  footer { margin-top: 32px; color: #6b7488; font-size: 11px; }
${LEDGER_CSS}
</style></head><body>
<h1>${esc(t.report.title(row.filename))}</h1>
<div class="meta">${esc(row.sha256)} · ${fmtBytes(row.size)} · ${t.report.generated(generatedHtml)}</div>
${identitySection}
${ledger.measured}
${secretsSection}
${sbomSection}
${gitleaksSection}
${triageSection}
${ledger.operator}
<footer>${t.report.footer}</footer>
</body></html>`;
}
