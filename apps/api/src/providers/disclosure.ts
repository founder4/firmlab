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
 *
 * **Language.** The draft composes in English or Spanish; the locale is a parameter with an English default, and
 * every sentence comes from `../i18n`. What is NOT translated is everything the vendor may need to match against
 * something else: proof states, assertion claims, finding ids, CVE ids, severities, package and file names, and
 * the findings' own titles and rationales — a vendor grepping the draft for `needs_runtime_reproduction` or
 * `CVE-2021-44228` must find the same token in either language. Only the document's scaffolding and the draft
 * email are localised.
 */
import type { Finding, ImageIdentity, ProofState } from '@firmlab/core';
import { type Locale, type Messages, formatTimestamp, messages } from '../i18n/index.js';
import {
  type AssertionRevision,
  assertionDay,
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
function disputeBlock(target: Finding, disputes: readonly Finding[], t: Messages): string {
  return disputes
    .map((d) => {
      const a = d.assertion;
      const who = a
        ? a.authorKind === 'agent'
          ? t.ledger.agentAuthor(a.assertedBy)
          : a.assertedBy
        : t.ledger.unrecordedAuthor;
      const when = a ? assertionDay(a.assertedAt) : t.ledger.unrecordedDate;
      return t.disclosure.dispute({
        who,
        when,
        title: d.title,
        rationale: d.rationale,
        proofState: target.proofState,
      });
    })
    .join('\n');
}

function findingBlock(f: Finding, disputes: readonly Finding[], t: Messages): string {
  const lines = [
    `#### ${f.title}`,
    '',
    `- **${t.disclosure.findingLabels.severity}:** ${f.severity}`,
    `- **${t.disclosure.findingLabels.proofState}:** \`${f.proofState}\``,
  ];
  const hint = evidenceHint(f);
  if (hint) lines.push(`- **${t.disclosure.findingLabels.evidence}:** ${hint}`);
  if (f.rationale) lines.push(`- **${t.disclosure.findingLabels.rationale}:** ${f.rationale}`);
  lines.push('');
  if (disputes.length > 0) lines.push(disputeBlock(f, disputes, t));
  return lines.join('\n');
}

/** One superseded claim, printed with the window it stood in — "they said X, then narrowed it to Y" needs both. */
function revisionLine(r: AssertionRevision, n: number, t: Messages): string {
  return t.disclosure.revision({
    n,
    revision: {
      claim: r.claim,
      from: assertionDay(r.from),
      to: assertionDay(r.supersededAt),
      rationale: r.rationale,
      title: r.title,
      disputesFindingId: r.disputesFindingId,
    },
  });
}

/**
 * What this claim replaced, or an honest statement that the predecessor was not kept.
 *
 * An amendment that showed only its result would let an author restate a strong claim as a weak one with no
 * trace — the same erasure a delete performs, in the document where the earlier version may already have been
 * sent. Returns nothing at all for a claim that was never amended, which is every assertion stored before the
 * history existed.
 */
function historyLines(f: Finding, t: Messages): string[] {
  const a = f.assertion;
  if (!a) return [];
  const revisions = revisionsOf(a);
  if (a.amendedAt === undefined && revisions.length === 0) return [];
  const when = assertionDay(a.amendedAt ?? a.assertedAt);
  if (revisions.length === 0) return [t.disclosure.amendedLost(when)];
  return [
    t.disclosure.amendedSuperseding({ when, count: revisions.length }),
    ...revisions.map((r, i) => revisionLine(r, i + 1, t)),
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
function contestedTargetLine(f: Finding, ledger: readonly Finding[], t: Messages): string | null {
  const targetId = f.assertion?.disputesFindingId;
  if (!targetId) return null;
  const retracted = f.assertion?.status === 'withdrawn';
  const target = ledger.find((r) => r.id === targetId);
  if (!target) return t.disclosure.contestedGone(targetId);
  if (retracted) {
    return t.disclosure.contestedUntilWithdrawn({ title: target.title, proofState: target.proofState });
  }
  return t.disclosure.contests({ title: target.title, proofState: target.proofState });
}

/** One asserted row, in the shape an assertion earns: an author, a basis, and no proof state anywhere. */
function assertionBlock(f: Finding, ledger: readonly Finding[], severityLabel: string, t: Messages): string {
  const lines = [`#### ${f.title}`, '', `- **${severityLabel}:** ${f.severity}`];
  if (f.assertion) {
    lines.push(`- **${t.disclosure.assertionLabels.attribution}:** ${t.ledger.describeAssertion(f.assertion)}`);
  }
  const hint = evidenceHint(f);
  if (hint) lines.push(`- **${t.disclosure.assertionLabels.referenced}:** ${hint}`);
  if (f.rationale) lines.push(`- **${t.disclosure.assertionLabels.statedBasis}:** ${f.rationale}`);
  const contested = contestedTargetLine(f, ledger, t);
  if (contested) lines.push(contested);
  lines.push(...historyLines(f, t));
  lines.push('');
  return lines.join('\n');
}

/**
 * Pure: build the coordinated-disclosure Markdown draft. Structure: coordinated-disclosure preamble → device
 * identity/provenance → who to contact → confirmed issues (severity-ordered) → unverified leads (clearly
 * separated) → known-exploited context (KEV) → a DRAFT email body. Returns the full document.
 *
 * `locale` defaults to English — what every caller got before the parameter existed, and what an unrecognised
 * `?lang` resolves to. It is a parameter and not a global: two requests in two languages can be in flight at once.
 */
export function buildDisclosureReport(ctx: DisclosureContext, locale: Locale = 'en'): string {
  const t = messages(locale);
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
    else if (c.checked) contactLines.push(`- **${c.domain}:** ${t.disclosure.contactNoSecurityTxt}`);
    else contactLines.push(`- **${c.domain}:** ${t.disclosure.contactNotChecked}`);
  }

  const out: string[] = [];
  out.push(`# ${t.disclosure.title}`);
  out.push('');
  out.push(`> ${t.disclosure.draftNotice}`);
  out.push('');
  out.push(`**${t.disclosure.imageLabel}:** \`${ctx.image.filename}\``);
  out.push(`**${t.disclosure.shaLabel}:** \`${ctx.image.sha256}\``);
  // The localised date is what a reader parses at a glance; the ISO stamp stays beside it because a disclosure is
  // correlated against logs and other reports, and a date written one way in one language is not a key.
  out.push(`**${t.disclosure.preparedLabel}:** ${formatTimestamp(ctx.generatedAt, locale)} (${ctx.generatedAt})`);
  out.push('');

  out.push(`## ${t.disclosure.deviceHeading}`);
  out.push('');
  if (vendor || product)
    out.push(`- **${t.disclosure.vendorProduct}:** ${[vendor, product].filter(Boolean).join(' / ')}`);
  if (ctx.provenance?.versions?.length)
    out.push(`- **${t.disclosure.versionHints}:** ${ctx.provenance.versions.slice(0, 5).join(', ')}`);
  if (ctx.identity) {
    out.push(
      `- **${t.disclosure.classArch}:** ${ctx.identity.firmwareClass} / ${ctx.identity.arch} (${ctx.identity.endianness})`,
    );
    if (ctx.identity.filesystems.length)
      out.push(`- **${t.disclosure.filesystems}:** ${ctx.identity.filesystems.join(', ')}`);
  }
  out.push('');

  out.push(`## ${t.disclosure.contactHeading}`);
  out.push('');
  out.push(contactLines.length > 0 ? contactLines.join('\n') : `- ${t.disclosure.contactNone}`);
  out.push('');

  out.push(`## ${t.disclosure.confirmedHeading(confirmed.length)}`);
  out.push('');
  if (confirmed.length === 0) {
    out.push(`_${t.disclosure.confirmedEmpty}_`);
    out.push('');
  } else {
    out.push(t.disclosure.confirmedIntro);
    out.push('');
    for (const f of confirmed) out.push(findingBlock(f, disputesFor(f), t));
  }

  if (leads.length > 0) {
    out.push(`## ${t.disclosure.leadsHeading(leads.length)}`);
    out.push('');
    out.push(`> ${t.disclosure.leadsNotice}`);
    out.push('');
    for (const f of leads) out.push(findingBlock(f, disputesFor(f), t));
  }

  if (asserted.length > 0) {
    out.push(`## ${t.disclosure.assertionsHeading(asserted.length)}`);
    out.push('');
    out.push(`> ${t.disclosure.assertionsNotice}`);
    out.push('');
    for (const f of sortBySeverity(asserted))
      out.push(assertionBlock(f, ctx.findings, t.disclosure.assertionLabels.severityAsserted, t));
  }

  // A retraction is an update the recipient needs more than the original claim: if an earlier draft cited it, the
  // vendor is still working from it. Kept apart from the standing assertions, counted nowhere, contesting nothing.
  if (withdrawn.length > 0) {
    out.push(`## ${t.disclosure.withdrawnHeading(withdrawn.length)}`);
    out.push('');
    out.push(`> ${t.disclosure.withdrawnNotice}`);
    out.push('');
    for (const f of sortBySeverity(withdrawn))
      out.push(assertionBlock(f, ctx.findings, t.disclosure.assertionLabels.severityAsAsserted, t));
  }

  if (ctx.kevMatches && ctx.kevMatches.length > 0) {
    out.push(`## ${t.disclosure.kevHeading}`);
    out.push('');
    out.push(t.disclosure.kevIntro);
    out.push('');
    for (const m of ctx.kevMatches.slice(0, 20))
      out.push(`- ${t.disclosure.kevItem({ cve: m.cveID, product: m.product })}`);
    out.push('');
  }

  out.push(`## ${t.disclosure.emailHeading}`);
  out.push('');
  out.push('```text');
  out.push(t.disclosure.emailSubject([vendor, product].filter(Boolean).join(' ') || ctx.image.filename));
  out.push('');
  out.push(t.disclosure.emailGreeting);
  out.push('');
  out.push(
    t.disclosure.emailIntro({
      count: confirmed.length,
      filename: ctx.image.filename,
      shaPrefix: ctx.image.sha256.slice(0, 16),
    }),
  );
  out.push('');
  // The email is the part that gets read; a contested issue that is flagged only in the attachment is flagged in
  // the document the vendor may never open.
  for (const f of confirmed.slice(0, 10)) {
    const contested = disputesFor(f).length > 0 ? t.disclosure.emailContestedSuffix : '';
    out.push(`- [${f.severity}] ${f.title}${contested}`);
  }
  const contestedInEmail = confirmed.slice(0, 10).filter((f) => disputesFor(f).length > 0).length;
  if (contestedInEmail > 0) {
    out.push('');
    out.push(t.disclosure.emailContestedNote(contestedInEmail));
  }
  out.push('');
  out.push(t.disclosure.emailClosing);
  out.push('');
  out.push(t.disclosure.emailThanks);
  out.push(t.disclosure.emailSignature);
  out.push('```');
  out.push('');
  out.push('---');
  out.push(`_${t.disclosure.footer}_`);

  return out.join('\n');
}
