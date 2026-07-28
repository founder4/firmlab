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
 *
 * The operator ledger reaches this document under the same discipline, and one addition it makes non-negotiable:
 * **a finding this draft asks a vendor to act on, which someone on the reporting side has contested, says so on
 * the finding.** Of every surface that renders the ledger this is the one where the omission costs most — it is
 * the document that leaves the building. So a contested finding carries the objection inline, with its proof
 * state printed unchanged beside it and the statement that the dispute moved nothing; the vendor weighs both,
 * which is the only honest thing to hand them. For the same reason an amended assertion shows what it replaced
 * (an author who quietly narrowed a strong claim after the vendor read the first draft would be untraceable
 * otherwise) and a withdrawn one is printed as withdrawn rather than dropped — a claim already communicated must
 * not vanish silently; its retraction is the update the vendor needs.
 *
 * Every one of those fields is read defensively: `supersedes` and a revision's `title` were added late, so an
 * assertion stored by an older build simply has no history, which is the correct thing to say about it.
 */
import type { Finding, ImageIdentity, ProofState } from '@firmlab/core';
import {
  type AssertionRevision,
  assertionDay,
  describeAssertion,
  indexDisputes,
  partitionByProvenance,
  revisionsOf,
} from '../operator-findings.js';

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

/**
 * Proof states that represent a genuinely confirmed issue worth disclosing (vs. an unproven lead). Typed over
 * `string` rather than `ProofState` because a finding's provenance field can also hold the operator-assertion
 * sentinel, which belongs to neither bucket and gets a section of its own below.
 */
const CONFIRMED: ReadonlySet<string> = new Set<ProofState>([
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

/**
 * The contest as it appears on the finding it contests: who, when, on what basis — and, in the same block, that
 * the proof state above it is unchanged. The two sentences travel together on purpose. A vendor reading only
 * "DISPUTED" is being invited to discount the measurement, which is precisely the override an assertion may not
 * perform; a vendor reading only the proof state is being shown a claim the reporting side does not fully stand
 * behind, presented as though it did.
 */
function disputeBlock(target: Finding, disputes: readonly Finding[]): string {
  return disputes
    .map((d) => {
      const a = d.assertion;
      const who = a ? (a.authorKind === 'agent' ? `${a.assertedBy} (agent)` : a.assertedBy) : 'an unrecorded author';
      const when = a ? assertionDay(a.assertedAt) : 'an unrecorded date';
      const basis = d.rationale ? ` Stated basis: ${d.rationale}` : '';
      return [
        `> **CONTESTED BY AN OPERATOR** — ${who} asserts on ${when} that this finding is wrong: “${d.title}”.${basis}`,
        '>',
        `> This is testimony about a measurement, not a measurement: the proof state above is still \`${target.proofState}\`, decided by code from the evidence, and the dispute neither changes it, downgrades it nor removes the finding. Both stand — the assertion is listed in full under "Operator assertions" below.`,
        '',
      ].join('\n');
    })
    .join('\n');
}

function findingBlock(f: Finding, disputes: readonly Finding[] = []): string {
  const lines = [`#### ${f.title}`, '', `- **Severity:** ${f.severity}`, `- **Proof state:** \`${f.proofState}\``];
  const hint = evidenceHint(f);
  if (hint) lines.push(`- **Evidence:** ${hint}`);
  if (f.rationale) lines.push(`- **Rationale:** ${f.rationale}`);
  lines.push('');
  if (disputes.length > 0) lines.push(disputeBlock(f, disputes));
  return lines.join('\n');
}

/** One superseded claim, printed with the window it stood in — "they said X, then narrowed it to Y" needs both. */
function revisionLine(r: AssertionRevision, n: number): string {
  const title = r.title ? ` — “${r.title}”` : '';
  const target = r.disputesFindingId ? ` (contested \`${r.disputesFindingId}\`)` : '';
  return `  ${n}. \`${r.claim}\`, stood from ${assertionDay(r.from)} to ${assertionDay(
    r.supersededAt,
  )}${title}${target}. Basis given at the time: ${r.rationale}`;
}

/**
 * What this claim replaced, or an honest statement that the predecessor was not kept.
 *
 * An amendment that showed only its result would let an author restate a strong claim as a weak one with no
 * trace — the same erasure a delete performs, in the document where the earlier version may already have been
 * sent. Returns nothing at all for a claim that was never amended, which is every assertion stored before the
 * history existed.
 */
function historyLines(f: Finding): string[] {
  const a = f.assertion;
  if (!a) return [];
  const revisions = revisionsOf(a);
  if (a.amendedAt === undefined && revisions.length === 0) return [];
  const when = assertionDay(a.amendedAt ?? a.assertedAt);
  if (revisions.length === 0) {
    return [
      `- **Amended ${when}:** the claim it replaced was not preserved — this row was amended by a build that overwrote its predecessor. What stands above is the current claim only; it is not necessarily the original one.`,
    ];
  }
  const plural = revisions.length === 1 ? 'claim' : 'claims';
  return [
    `- **Amended ${when}, superseding ${revisions.length} earlier ${plural}.** An amendment appends; it never overwrites. What the author previously stated, and on what basis — superseded, and quoted here only as history:`,
    ...revisions.map((r, i) => revisionLine(r, i + 1)),
  ];
}

/**
 * The finding an assertion contests, named back so a vendor can find it, or said to be gone if it is.
 *
 * A retracted contest gets its own sentence rather than the live one. Rendering the draft showed the defect: the
 * live wording promises the target "is annotated where it appears above", and for a withdrawn dispute it is not —
 * the annotation was deliberately withheld, and the document would have been sending the vendor to look for a
 * block that is not there.
 */
function contestedTargetLine(f: Finding, ledger: readonly Finding[]): string | null {
  const targetId = f.assertion?.disputesFindingId;
  if (!targetId) return null;
  const retracted = f.assertion?.status === 'withdrawn';
  const target = ledger.find((r) => r.id === targetId);
  if (!target) {
    return `- **Contested:** finding \`${targetId}\`, which is no longer in this image's ledger. Re-running an analysis replaces its rows with new ids, so a dispute can outlive the row it was recorded against: the claim is kept, and what it pointed at cannot be shown here.`;
  }
  if (retracted) {
    return `- **Contested until withdrawn:** “${target.title}” (\`${target.proofState}\`). The objection has been retracted, so that finding carries no contest annotation above; it stands as code decided it, and always did.`;
  }
  return `- **Contests:** “${target.title}” (\`${target.proofState}\`), annotated where it appears above. That row stands exactly as code decided it; this assertion is recorded beside it, not over it.`;
}

/** One asserted row, in the shape an assertion earns: an author, a basis, and no proof state anywhere. */
function assertionBlock(f: Finding, ledger: readonly Finding[], severityLabel: string): string {
  const lines = [`#### ${f.title}`, '', `- **${severityLabel}:** ${f.severity}`];
  if (f.assertion) lines.push(`- **Attribution:** ${describeAssertion(f.assertion)}`);
  const hint = evidenceHint(f);
  if (hint) lines.push(`- **Referenced:** ${hint}`);
  if (f.rationale) lines.push(`- **Stated basis:** ${f.rationale}`);
  const contested = contestedTargetLine(f, ledger);
  if (contested) lines.push(contested);
  lines.push(...historyLines(f));
  lines.push('');
  return lines.join('\n');
}

/**
 * Pure: build the coordinated-disclosure Markdown draft. Structure: coordinated-disclosure preamble → device
 * identity/provenance → who to contact → confirmed issues (severity-ordered) → unverified leads (clearly
 * separated) → known-exploited context (KEV) → a DRAFT email body. Returns the full document.
 */
export function buildDisclosureReport(ctx: DisclosureContext): string {
  // Assertions are separated first. They match neither bucket's filter, so without this they would simply vanish
  // from the draft — and an operator's observation on the physical device is often the strongest thing in the
  // ledger. Silent omission and silent promotion are both failures; a section that names the author is neither.
  const { measured, asserted, withdrawn } = partitionByProvenance(ctx.findings);
  const confirmed = sortBySeverity(measured.filter((f) => CONFIRMED.has(f.proofState)));
  const leads = sortBySeverity(measured.filter((f) => f.proofState === 'needs_runtime_reproduction'));
  // Built from the whole ledger, and read by both the finding blocks and the draft email: a contested issue must
  // not be listed in the email as though nobody on this side objected to it.
  const disputesByTarget = indexDisputes(ctx.findings);
  const disputesFor = (f: Finding): Finding[] => disputesByTarget.get(f.id) ?? [];

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
    for (const f of confirmed) out.push(findingBlock(f, disputesFor(f)));
  }

  if (leads.length > 0) {
    out.push(`## Unverified leads (${leads.length}) — reachability unverified`);
    out.push('');
    out.push(
      `> These are **not confirmed**. They need runtime reproduction on the target before they belong in a report. Listed for the vendor's own triage; do not present them as vulnerabilities.`,
    );
    out.push('');
    for (const f of leads) out.push(findingBlock(f, disputesFor(f)));
  }

  if (asserted.length > 0) {
    out.push(`## Operator assertions (${asserted.length}) — asserted by a person, not measured here`);
    out.push('');
    out.push(
      '> FirmLab did not measure any of these. Each is a claim by the named author, on the stated basis, and it ' +
        'carries no proof state. They are included because an observation made on the physical device is ' +
        'knowledge this workbench structurally cannot produce — but a vendor reading this must be able to see, ' +
        'without asking, which lines are measurements and which are testimony.',
    );
    out.push('');
    for (const f of sortBySeverity(asserted)) out.push(assertionBlock(f, ctx.findings, 'Severity (asserted)'));
  }

  // A retraction is an update the recipient needs more than the original claim: if an earlier draft cited it, the
  // vendor is still working from it. Kept apart from the standing assertions, counted nowhere, contesting nothing.
  if (withdrawn.length > 0) {
    out.push(`## Withdrawn assertions (${withdrawn.length}) — retracted, and kept`);
    out.push('');
    out.push(
      '> Each of these was asserted and then withdrawn by a named author, with the reason recorded. None of them ' +
        'is a claim any longer and none contests anything; they are printed rather than deleted so that a claim ' +
        'which may already have been communicated is not silently dropped. "This was wrong, and here is why" is ' +
        'the most useful line a ledger holds.',
    );
    out.push('');
    for (const f of sortBySeverity(withdrawn)) out.push(assertionBlock(f, ctx.findings, 'Severity (as asserted)'));
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
  // The email is the part that gets read; a contested issue that is flagged only in the attachment is flagged in
  // the document the vendor may never open.
  for (const f of confirmed.slice(0, 10)) {
    const contested = disputesFor(f).length > 0 ? ' — CONTESTED on my side, see the attached details' : '';
    out.push(`- [${f.severity}] ${f.title}${contested}`);
  }
  const contestedInEmail = confirmed.slice(0, 10).filter((f) => disputesFor(f).length > 0).length;
  if (contestedInEmail > 0) {
    out.push('');
    out.push(
      `${contestedInEmail === 1 ? 'One issue above is' : `${contestedInEmail} issues above are`} marked CONTESTED: someone on my side has recorded that the finding is wrong, and their objection is in the attached details alongside the measurement. I have not removed or downgraded the finding — you have both, and I would value your reading of it.`,
    );
  }
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
