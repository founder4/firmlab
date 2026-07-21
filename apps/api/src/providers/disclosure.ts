/**
 * Responsible-disclosure report generator (Phase 5.3, debt) — turns the confirmed findings for an image into a
 * downloadable coordinated-disclosure draft the operator reviews and sends. It closes the 5.3 loop: the research
 * track already discovers the vendor security contact (security.txt) and the intel brief drafts prose; this
 * produces a structured, self-contained Markdown report a human can attach to that email.
 *
 * Discipline (inherited): DEFENSIVE only — a DRAFT, never auto-sent, no exploitation. Proof-state honesty is
 * preserved: confirmed findings (present in the bytes / reproduced in the sandbox) lead; leads that still need
 * runtime reproduction are listed separately and explicitly marked "reachability unverified". Published-advisory
 * correlations (OSV/NVD/KEV) are included as context, never as confirmed vulnerabilities of this image. The
 * builder is PURE (takes a context, returns a string) so it is unit-testable without the store or the network.
 */
import type { Finding, ImageIdentity, ProofState } from '@firmlab/core';

export interface DisclosureContext {
  image: { filename: string; sha256: string };
  identity: ImageIdentity | null;
  findings: Finding[];
  /** Provenance hints from the research track (vendor/product), if a research run exists. */
  provenance?: { vendors: string[]; models: string[]; versions: string[] };
  /** Discovered vendor disclosure contacts (security.txt), if a research run exists. */
  securityContacts?: { domain: string; checked: boolean; found: boolean; contact: string[] }[];
  /** Known-exploited CVEs (CISA KEV) that correlate to present components — priority context, not confirmation. */
  kevMatches?: { cveID: string; product: string }[];
  /** ISO timestamp — passed in so the builder stays pure/deterministic. */
  generatedAt: string;
}

/** Proof states that represent a genuinely confirmed issue worth disclosing (vs. an unproven lead). */
const CONFIRMED: ReadonlySet<ProofState> = new Set<ProofState>([
  'static_confirmed',
  'confirmed_in_emulation',
  'confirmed_full_system',
]);

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function sortBySeverity(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9));
}

/** One-line evidence hint from a finding's structured evidence, kept short and free of secret values. */
function evidenceHint(f: Finding): string {
  const e = f.evidence ?? {};
  const parts: string[] = [];
  const pick = (k: string): void => {
    const v = (e as Record<string, unknown>)[k];
    if (typeof v === 'string' || typeof v === 'number') parts.push(`${k}: ${String(v).slice(0, 80)}`);
  };
  for (const k of ['binary', 'file', 'path', 'sink', 'guid', 'name', 'cve', 'offset']) pick(k);
  return parts.join(' · ');
}

function findingBlock(f: Finding): string {
  const lines = [`#### ${f.title}`, '', `- **Severity:** ${f.severity}`, `- **Proof state:** \`${f.proofState}\``];
  const hint = evidenceHint(f);
  if (hint) lines.push(`- **Evidence:** ${hint}`);
  if (f.rationale) lines.push(`- **Rationale:** ${f.rationale}`);
  lines.push('');
  return lines.join('\n');
}

/**
 * Pure: build the coordinated-disclosure Markdown draft. Structure: coordinated-disclosure preamble → device
 * identity/provenance → who to contact → confirmed issues (severity-ordered) → unverified leads (clearly
 * separated) → known-exploited context (KEV) → a DRAFT email body. Returns the full document.
 */
export function buildDisclosureReport(ctx: DisclosureContext): string {
  const confirmed = sortBySeverity(ctx.findings.filter((f) => CONFIRMED.has(f.proofState)));
  const leads = sortBySeverity(ctx.findings.filter((f) => f.proofState === 'needs_runtime_reproduction'));

  const vendor = ctx.provenance?.vendors[0];
  const product = ctx.provenance?.models[0];
  const contactLines: string[] = [];
  for (const c of ctx.securityContacts ?? []) {
    if (c.found && c.contact.length > 0) contactLines.push(`- **${c.domain}:** ${c.contact.join(', ')}`);
    else if (c.checked) contactLines.push(`- **${c.domain}:** no security.txt found — try a vendor PSIRT / CERT/CC.`);
    else
      contactLines.push(
        `- **${c.domain}:** not checked — add it to \`FIRMLAB_RESEARCH_ALLOWLIST\` to discover a contact.`,
      );
  }

  const out: string[] = [];
  out.push('# Coordinated vulnerability disclosure — draft');
  out.push('');
  out.push(
    '> **This is a DRAFT for you to review and send yourself.** FirmLab does not contact anyone. Disclose ' +
      'responsibly: give the vendor reasonable time to remediate before any public discussion, and only assess ' +
      'firmware you are authorized to test.',
  );
  out.push('');
  out.push(`**Image:** \`${ctx.image.filename}\``);
  out.push(`**SHA-256:** \`${ctx.image.sha256}\``);
  out.push(`**Prepared:** ${ctx.generatedAt}`);
  out.push('');

  out.push('## Device / firmware');
  out.push('');
  if (vendor || product)
    out.push(`- **Vendor / product (inferred):** ${[vendor, product].filter(Boolean).join(' / ')}`);
  if (ctx.provenance?.versions?.length)
    out.push(`- **Version hints:** ${ctx.provenance.versions.slice(0, 5).join(', ')}`);
  if (ctx.identity) {
    out.push(`- **Class / arch:** ${ctx.identity.firmwareClass} / ${ctx.identity.arch} (${ctx.identity.endianness})`);
    if (ctx.identity.filesystems.length) out.push(`- **Filesystems:** ${ctx.identity.filesystems.join(', ')}`);
  }
  out.push('');

  out.push('## Who to contact');
  out.push('');
  out.push(
    contactLines.length > 0
      ? contactLines.join('\n')
      : '- No contact discovered yet — run the research track (RFC 9116 security.txt), or use a national CERT/CC as a coordinator.',
  );
  out.push('');

  out.push(`## Confirmed issues (${confirmed.length})`);
  out.push('');
  if (confirmed.length === 0) {
    out.push(
      '_No confirmed issues. Nothing here is proven from the bytes or reproduced in the sandbox — do not report leads as confirmed._',
    );
    out.push('');
  } else {
    out.push(
      'These are present in the firmware bytes or were reproduced under isolation. Proof states are stated per finding; emulated reproduction proves the sandbox, not the deployed device.',
    );
    out.push('');
    for (const f of confirmed) out.push(findingBlock(f));
  }

  if (leads.length > 0) {
    out.push(`## Unverified leads (${leads.length}) — reachability unverified`);
    out.push('');
    out.push(
      `> These are **not confirmed**. They need runtime reproduction on the target before they belong in a report. Listed for the vendor's own triage; do not present them as vulnerabilities.`,
    );
    out.push('');
    for (const f of leads) out.push(findingBlock(f));
  }

  if (ctx.kevMatches && ctx.kevMatches.length > 0) {
    out.push('## Known-exploited context (CISA KEV)');
    out.push('');
    out.push(
      `Published CVEs for components present in this image that are on CISA's Known Exploited Vulnerabilities list. This raises priority; it does **not** confirm the CVE is reachable in this build.`,
    );
    out.push('');
    for (const m of ctx.kevMatches.slice(0, 20))
      out.push(`- \`${m.cveID}\` — ${m.product} (known-exploited; reachability unverified)`);
    out.push('');
  }

  out.push('## Draft email');
  out.push('');
  out.push('```text');
  out.push(`Subject: Security disclosure — ${[vendor, product].filter(Boolean).join(' ') || ctx.image.filename}`);
  out.push('');
  out.push('Hello,');
  out.push('');
  out.push(
    `I am reporting ${confirmed.length} security ${confirmed.length === 1 ? 'issue' : 'issues'} I found while ` +
      `analyzing the firmware image ${ctx.image.filename} (SHA-256 ${ctx.image.sha256.slice(0, 16)}…).`,
  );
  out.push('');
  for (const f of confirmed.slice(0, 10)) out.push(`- [${f.severity}] ${f.title}`);
  out.push('');
  out.push(
    'Full technical details are attached. I am disclosing this privately and will coordinate on a timeline before ' +
      `any public discussion. Please let me know the right contact if this isn't it.`,
  );
  out.push('');
  out.push('Thank you,');
  out.push('[your name]');
  out.push('```');
  out.push('');
  out.push('---');
  out.push(
    '_Generated by FirmLab. Draft only — review before sending. Assess only firmware you are authorized to test._',
  );

  return out.join('\n');
}
