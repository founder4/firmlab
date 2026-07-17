/**
 * Findings report generator. Assembles a single self-contained HTML document for one image — identity, entropy
 * signal, structure summary, raw secrets, and whatever tool-backed results exist (SBOM/CVEs, gitleaks, binary
 * triage) — so an analyst can archive or share a run without the live workbench. Pure string building: no tool
 * invocation, no external assets (inline CSS), safe to open offline.
 */
import type { ImageIdentity, StaticAnalysis } from '@firmlab/core';
import { getImage, listJobs } from '../store.js';
import type { DecompileResult } from './decompile.js';
import type { GitleaksResult } from './gitleaks.js';
import type { SbomResult } from './sbom.js';

function esc(s: unknown): string {
  return String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c] ?? c);
}

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

function table(headers: string[], rows: string[][]): string {
  if (rows.length === 0) return '<p class="muted">None.</p>';
  const head = headers.map((h) => `<th>${esc(h)}</th>`).join('');
  const body = rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join('')}</tr>`).join('');
  return `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}

function section(title: string, inner: string): string {
  return `<section><h2>${esc(title)}</h2>${inner}</section>`;
}

/** Build the full self-contained HTML report for an image; returns null if the image is unknown. */
export function generateReport(imageId: string): string | null {
  const row = getImage(imageId);
  if (!row) return null;

  const identity: ImageIdentity | null = row.identityJson ? JSON.parse(row.identityJson) : null;
  const analysis: StaticAnalysis | null = row.analysisJson ? JSON.parse(row.analysisJson) : null;
  const sbom = latestResult<SbomResult>(imageId, 'sbom');
  const gitleaks = latestResult<GitleaksResult>(imageId, 'gitleaks');
  const triage = latestResult<DecompileResult>(imageId, 'decompile');
  const generatedAt = new Date().toISOString();

  const identityRows: string[][] = identity
    ? [
        ['Class', esc(identity.firmwareClass)],
        ['Architecture', `${esc(identity.arch)} / ${esc(identity.endianness)}`],
        ['Filesystems', esc(identity.filesystems.join(', ') || '—')],
        ['Bootloader', esc(identity.bootloader ?? '—')],
      ]
    : [];

  const identitySection = section(
    'Identity',
    table(['Field', 'Value'], identityRows) +
      (analysis
        ? `<p class="muted">Mean entropy ${analysis.entropy.mean.toFixed(2)} · ${
            analysis.entropy.likelyEncrypted
              ? 'likely encrypted'
              : analysis.entropy.likelyCompressed
                ? 'likely compressed'
                : 'no high-entropy signal'
          } · ${analysis.signatures.length} signatures · ${analysis.structure.length} structure segments</p>`
        : ''),
  );

  const secretsSection = analysis
    ? section(
        `Raw secrets (${analysis.secrets.length})`,
        table(
          ['Severity', 'Kind', 'Offset', 'Value'],
          analysis.secrets
            .slice(0, 200)
            .map((s) => [
              esc(s.severity),
              esc(s.secretKind),
              `0x${s.offset.toString(16)}`,
              `<code>${esc(s.value)}</code>`,
            ]),
        ),
      )
    : '';

  const sbomSection = sbom?.available
    ? section(
        'SBOM & CVEs',
        `<p>${sbom.packageCount} packages · ${sbom.vulnerabilities.length} CVEs (Critical ${sbom.counts.Critical}, High ${sbom.counts.High}, Medium ${sbom.counts.Medium})</p>${table(
          ['Severity', 'CVE', 'Package', 'Version', 'Fixed in'],
          sbom.vulnerabilities
            .slice(0, 300)
            .map((v) => [
              esc(v.severity),
              `<code>${esc(v.id)}</code>`,
              esc(v.packageName),
              esc(v.packageVersion),
              esc(v.fixedIn ?? '—'),
            ]),
        )}`,
      )
    : '';

  const gitleaksSection = gitleaks?.available
    ? section(
        `Deep secret scan (${gitleaks.findingCount})`,
        table(
          ['Rule', 'File', 'Line', 'Match'],
          gitleaks.findings
            .slice(0, 300)
            .map((f) => [esc(f.rule), `<code>${esc(f.file)}</code>`, String(f.line), `<code>${esc(f.match)}</code>`]),
        ),
      )
    : '';

  const triageSection = triage?.available
    ? section(
        `Binary triage — ${esc(triage.binary)}`,
        `<p>${esc(triage.info.arch ?? '?')}${triage.info.bits ? `/${triage.info.bits}` : ''} · NX ${triage.info.nx ? 'on' : 'off'} · canary ${triage.info.canary ? 'on' : 'off'} · ${triage.functionCount} functions · ${triage.imports.length} imports · ${triage.strings.length} strings</p>${table(
          ['Import', 'Library'],
          triage.imports.slice(0, 200).map((i) => [`<code>${esc(i.name)}</code>`, esc(i.libname ?? '—')]),
        )}`,
      )
    : '';

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>FirmLab report — ${esc(row.filename)}</title>
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
  footer { margin-top: 32px; color: #6b7488; font-size: 11px; }
</style></head><body>
<h1>FirmLab report — ${esc(row.filename)}</h1>
<div class="meta">${esc(row.sha256)} · ${fmtBytes(row.size)} · generated ${esc(generatedAt)}</div>
${identitySection}
${secretsSection}
${sbomSection}
${gitleaksSection}
${triageSection}
<footer>Generated by FirmLab — local-only firmware analysis workbench. Analyze only firmware you are authorized to assess.</footer>
</body></html>`;
}
