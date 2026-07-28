/**
 * The English catalogue — the source of truth for every sentence the GENERATED DOCUMENTS say.
 *
 * The workbench shell has its own catalogue in `apps/web/src/locales`. This one is deliberately separate and lives
 * on the API side, because the HTML report and the disclosure draft are composed by the server, leave the building
 * as files, and are read months later by someone who never opened the UI. They are also where this project's
 * prose is least decorative: the sentence that says a blocked stage is NOT a negative, that an empty ledger is not
 * a clean image, that an emulated reproduction proves the sandbox and never the device, and that an operator
 * assertion counts towards no analysis stage — those sentences *are* the product. A document that half-translates
 * them still looks finished.
 *
 * **Why the catalogue is typed rather than keyed by string.** `Messages` is derived from this object and `es.ts`
 * declares itself as `Messages`, so a key added here is a COMPILE error there until it is translated. There is no
 * runtime lookup, no fallback to English and no fallback to the key: the failure mode of a conventional
 * `t('some.key')` catalogue is a build that ships looking complete and degrades silently in exactly the places
 * that matter most.
 *
 * **Why entries are functions when they interpolate.** Spanish agrees in gender and number where English does not,
 * and placeholder substitution forces both languages through English's grammar. A function per message lets each
 * language build its own sentence.
 *
 * **What is NOT translated, ever.** Proof states (`static_confirmed`, `blocked_by_platform`), finding kinds,
 * operator claims (`asserted_from_device`), source strings and severities are IDENTIFIERS: they cross the API,
 * land in SQLite, and a vendor grepping the draft for `needs_runtime_reproduction` must find it. They render
 * verbatim in both languages and only their human gloss is localised. Finding titles and rationales are not
 * translated either — a provider wrote them and they are stored with the image as evidence, so they render as
 * recorded. What is localised is the document's own scaffolding: headings, column names, caveats, the assertion
 * prose and the draft email.
 *
 * Pure: no store import, no I/O, so every sentence here is reachable from a unit test.
 */
import { CLAIM_MEANING, NOT_A_MEASUREMENT, describeAssertion } from '../operator-findings.js';
import { escapeHtml as esc } from './escape.js';

/** A superseded claim, flattened to strings by the caller so the catalogue holds no date logic. */
export interface RevisionText {
  claim: string;
  from: string;
  to: string;
  rationale: string;
  title?: string | undefined;
  disputesFindingId?: string | undefined;
}

export const en = {
  /**
   * The human gloss for each proof state. The CODE is printed verbatim beside it — never replaced by this text,
   * in either language. `blocked_by_*` says the question was asked and could not be answered; a rendering that
   * reads like "no problems found" inverts the workbench's central claim.
   */
  proofState: {
    meaning: {
      confirmed_full_system: 'Reproduced under full-system emulation.',
      confirmed_in_emulation: 'Reproduced against a booted image. This proves the sandbox, never the physical device.',
      static_confirmed: 'The property is literally present in the bytes. It states the fact, not its exploitability.',
      needs_runtime_reproduction:
        'A lead. A precondition was observed and nothing was proven — never report it as a bug.',
      blocked_by_platform:
        'The question was asked and this deployment could not answer it. This is NOT a negative result.',
      blocked_by_security: 'A control — encryption, secure boot — stopped the analysis. This is NOT a negative result.',
      false_positive: 'Checked and dismissed.',
      operator_assertion:
        'A person or an agent asserted this; FirmLab did not measure it. It carries no proof state and counts towards no analysis stage.',
    },
    /** A code written by a build this one does not know. Printed, never guessed at. */
    unknown:
      'A proof state this build does not recognise. It was recorded by another version of FirmLab and is printed exactly as stored.',
  },

  /**
   * The HTML analysis report's own scaffolding. Unlike `ledger`, these entries are plain text — they land inside a
   * heading or a `<p>` that the caller escapes — so anything interpolated into them (`filename`, `arch`) arrives
   * already escaped or is a number. The one entry that takes markup says so on its own line.
   */
  report: {
    title: (filename: string) => `FirmLab report — ${filename}`,
    /** `when` is a ready-made `<time>` element, so the caller keeps the ISO stamp beside the localised date. */
    generated: (when: string) => `generated ${when}`,
    none: 'None.',
    identityHeading: 'Identity',
    identityColumns: { field: 'Field', value: 'Value' },
    identityRows: {
      firmwareClass: 'Class',
      arch: 'Architecture',
      filesystems: 'Filesystems',
      bootloader: 'Bootloader',
    },
    entropy: (p: { mean: string; signal: 'encrypted' | 'compressed' | 'none'; signatures: number; segments: number }) =>
      `Mean entropy ${p.mean} · ${
        p.signal === 'encrypted'
          ? 'likely encrypted'
          : p.signal === 'compressed'
            ? 'likely compressed'
            : 'no high-entropy signal'
      } · ${p.signatures} signatures · ${p.segments} structure segments`,
    secretsHeading: (n: number) => `Raw secrets (${n})`,
    secretsColumns: { severity: 'Severity', kind: 'Kind', offset: 'Offset', value: 'Value' },
    sbomHeading: 'SBOM & CVEs',
    sbomSummary: (p: { packages: number; cves: number; critical: number; high: number; medium: number }) =>
      `${p.packages} packages · ${p.cves} CVEs (Critical ${p.critical}, High ${p.high}, Medium ${p.medium})`,
    sbomColumns: { severity: 'Severity', cve: 'CVE', pkg: 'Package', version: 'Version', fixedIn: 'Fixed in' },
    gitleaksHeading: (n: number) => `Deep secret scan (${n})`,
    gitleaksColumns: { rule: 'Rule', file: 'File', line: 'Line', match: 'Match' },
    triageHeading: (binary: string) => `Binary triage — ${binary}`,
    triageSummary: (p: {
      arch: string;
      nx: boolean;
      canary: boolean;
      functions: number;
      imports: number;
      strings: number;
    }) =>
      `${p.arch} · NX ${p.nx ? 'on' : 'off'} · canary ${p.canary ? 'on' : 'off'} · ${p.functions} functions · ${
        p.imports
      } imports · ${p.strings} strings`,
    triageColumns: { import: 'Import', library: 'Library' },
    footer:
      'Generated by FirmLab — local-only firmware analysis workbench. Analyze only firmware you are authorized to assess.',
  },

  /**
   * The findings ledger as the HTML report renders it. Entries that build markup escape what they interpolate:
   * an assertion is a sentence a human typed and this document is opened in a browser.
   */
  ledger: {
    measuredHeading: (n: number) => `Findings — measured (${n})`,
    measuredEmpty:
      'No measured findings are recorded for this image. That is a count of rows in the ledger, not a verdict: a stage that never ran contributes nothing to it, and an empty list here is not evidence that the image is clean. Check which analyses were executed before reading this as a negative.',
    measuredIntro:
      'Every row below was decided by code, and its proof state says what was actually established. This count excludes operator assertions entirely — those are recorded further down and are not measurements.',
    cutRule: (p: { shown: number; total: number; omitted: number }) =>
      `Showing ${p.shown} of ${p.total}. Rows are ordered by severity (highest first, then proof state and title) and the ${p.omitted} lowest-ranked are omitted — the cut is by that rule, never by the order the rows were written. Every contested row is shown regardless of the cap.`,
    columns: { severity: 'Severity', proofState: 'Proof state', source: 'Source', finding: 'Finding' },
    glossHeading: 'What the proof states above claim',
    glossNote:
      'The codes are printed exactly as recorded — they are identifiers, and only their explanation is written out here.',
    unrecordedAuthor: 'an unrecorded author',
    unrecordedDate: 'an unrecorded date',
    agentAuthor: (who: string) => `${who} (agent)`,
    dispute: (p: {
      who: string;
      when: string;
      title: string;
      rationale?: string | undefined;
      assertionId: string;
      proofState: string;
    }) =>
      `<div class="dispute"><strong>CONTESTED BY AN OPERATOR</strong> — ${esc(p.who)} asserts on ${esc(
        p.when,
      )} that this finding is wrong: “${esc(p.title)}”.${
        p.rationale ? ` ${esc(p.rationale)}` : ''
      }<div class="muted">Recorded as operator assertion <code>${esc(
        p.assertionId,
      )}</code>, and listed in full in the operator section. This is testimony about a measurement, not a measurement: the proof state of this row is still <code>${esc(
        p.proofState,
      )}</code>, decided by code from the evidence, and the dispute neither changes it, downgrades it nor removes the row. Both stand; a reader weighs them.</div></div>`,
    cited: 'Cited:',
    revision: (r: RevisionText) =>
      `<li><code>${esc(r.claim)}</code>, stood from ${esc(r.from)} to ${esc(r.to)}${
        r.title ? ` — “${esc(r.title)}”` : ''
      }${
        r.disputesFindingId ? ` (contested <code>${esc(r.disputesFindingId)}</code>)` : ''
      }<div class="muted">${esc(r.rationale)}</div></li>`,
    historyLost: (when: string) =>
      `<div class="history"><strong>Amended ${esc(
        when,
      )}.</strong> The claim it replaced was not preserved — this row was amended by a build that overwrote its predecessor. What stands here is the current claim only.</div>`,
    history: (p: { when: string; items: string[] }) =>
      `<div class="history"><strong>Amended ${esc(p.when)}, superseding ${p.items.length} earlier ${
        p.items.length === 1 ? 'claim' : 'claims'
      }.</strong> An amendment appends; it never overwrites. What the author previously stated, and on what basis:<ol>${p.items.join(
        '',
      )}</ol></div>`,
    disputeTargetGone: (targetId: string) =>
      `<div class="basis">Contests finding <code>${esc(
        targetId,
      )}</code>, which is no longer in this image's ledger. Re-running a provider replaces its rows with new ids, so a dispute can outlive the row it was recorded against: the claim is kept, and what it pointed at cannot be shown here.</div>`,
    disputeTarget: (p: { targetId: string; title: string; proofState: string; source: string }) =>
      `<div class="basis">Contests finding <code>${esc(p.targetId)}</code> — “${esc(p.title)}” (<code>${esc(
        p.proofState,
      )}</code>, source <code>${esc(
        p.source,
      )}</code>). That row stands exactly as code decided it; this assertion is recorded beside it, not over it.</div>`,
    badgeAsserted: 'asserted · not measured',
    badgeWithdrawn: 'withdrawn · not measured',
    unrecognisedClaim: 'Unrecognised claim — read it as an unverified assertion.',
    noAuthorRecord: `This row carries the operator-assertion provenance but no author record. Treat it as an unattributed claim; ${NOT_A_MEASUREMENT}`,
    assertedSeverity: (severity: string) => `severity asserted: ${esc(severity)}`,
    statedBasis: 'Stated basis:',
    claim: 'Claim:',
    noAssertionStands:
      'No assertion currently stands on this image; the retracted ones below are kept as part of the record.',
    withdrawnHeading: (n: number) => `Withdrawn assertions (${n}) — retracted, and kept`,
    withdrawnIntro:
      'A retraction is part of the record, so it is shown rather than deleted: "this was wrong, and here is why" is often the most useful row a ledger holds. A withdrawn claim is counted nowhere and contests nothing.',
    operatorHeading: (n: number) => `Operator assertions (${n}) — asserted by a named author, not measured`,
    notAMeasurement: NOT_A_MEASUREMENT,
    operatorIntro:
      'Nothing in this section was produced by an analysis. Each block is a claim recorded by the named author on the basis they state, and it is kept apart from the findings above for that reason: none of it carries a proof state, none of it counts towards any analysis stage, and none of it is included in the measured count. Where an author disputes a computed finding, that finding is annotated where it appears above and its proof state is left exactly as code decided it.',
    /** The one-line attribution. English delegates to the shared constant so the two cannot drift. */
    describeAssertion,
    claimMeaning: CLAIM_MEANING,
  },

  /** The coordinated-disclosure draft. Markdown, so nothing here is escaped. */
  disclosure: {
    title: 'Coordinated vulnerability disclosure — draft',
    draftNotice:
      '**This is a DRAFT for you to review and send yourself.** FirmLab does not contact anyone. Disclose ' +
      'responsibly: give the vendor reasonable time to remediate before any public discussion, and only assess ' +
      'firmware you are authorized to test.',
    imageLabel: 'Image',
    shaLabel: 'SHA-256',
    preparedLabel: 'Prepared',
    deviceHeading: 'Device / firmware',
    vendorProduct: 'Vendor / product (inferred)',
    versionHints: 'Version hints',
    classArch: 'Class / arch',
    filesystems: 'Filesystems',
    contactHeading: 'Who to contact',
    contactNoSecurityTxt: 'no security.txt found — try a vendor PSIRT / CERT/CC.',
    contactNotChecked: 'not checked — add it to `FIRMLAB_RESEARCH_ALLOWLIST` to discover a contact.',
    contactNone:
      'No contact discovered yet — run the research track (RFC 9116 security.txt), or use a national CERT/CC as a coordinator.',
    confirmedHeading: (n: number) => `Confirmed issues (${n})`,
    confirmedEmpty:
      'No confirmed issues. Nothing here is proven from the bytes or reproduced in the sandbox — do not report leads as confirmed.',
    confirmedIntro:
      'These are present in the firmware bytes or were reproduced under isolation. Proof states are stated per finding; emulated reproduction proves the sandbox, not the deployed device.',
    leadsHeading: (n: number) => `Unverified leads (${n}) — reachability unverified`,
    leadsNotice:
      'These are **not confirmed**. They need runtime reproduction on the target before they belong in a report. ' +
      "Listed for the vendor's own triage; do not present them as vulnerabilities.",
    assertionsHeading: (n: number) => `Operator assertions (${n}) — asserted by a person, not measured here`,
    assertionsNotice:
      'FirmLab did not measure any of these. Each is a claim by the named author, on the stated basis, and it ' +
      'carries no proof state. They are included because an observation made on the physical device is ' +
      'knowledge this workbench structurally cannot produce — but a vendor reading this must be able to see, ' +
      'without asking, which lines are measurements and which are testimony.',
    withdrawnHeading: (n: number) => `Withdrawn assertions (${n}) — retracted, and kept`,
    withdrawnNotice:
      'Each of these was asserted and then withdrawn by a named author, with the reason recorded. None of them ' +
      'is a claim any longer and none contests anything; they are printed rather than deleted so that a claim ' +
      'which may already have been communicated is not silently dropped. "This was wrong, and here is why" is ' +
      'the most useful line a ledger holds.',
    kevHeading: 'Known-exploited context (CISA KEV)',
    kevIntro:
      "Published CVEs for components present in this image that are on CISA's Known Exploited Vulnerabilities list. This raises priority; it does **not** confirm the CVE is reachable in this build.",
    kevItem: (p: { cve: string; product: string }) =>
      `\`${p.cve}\` — ${p.product} (known-exploited; reachability unverified)`,
    findingLabels: {
      severity: 'Severity',
      proofState: 'Proof state',
      evidence: 'Evidence',
      rationale: 'Rationale',
    },
    assertionLabels: {
      severityAsserted: 'Severity (asserted)',
      severityAsAsserted: 'Severity (as asserted)',
      attribution: 'Attribution',
      referenced: 'Referenced',
      statedBasis: 'Stated basis',
    },
    dispute: (p: { who: string; when: string; title: string; rationale?: string | undefined; proofState: string }) =>
      [
        `> **CONTESTED BY AN OPERATOR** — ${p.who} asserts on ${p.when} that this finding is wrong: “${p.title}”.${
          p.rationale ? ` Stated basis: ${p.rationale}` : ''
        }`,
        '>',
        `> This is testimony about a measurement, not a measurement: the proof state above is still \`${p.proofState}\`, decided by code from the evidence, and the dispute neither changes it, downgrades it nor removes the finding. Both stand — the assertion is listed in full under "Operator assertions" below.`,
        '',
      ].join('\n'),
    contestedGone: (targetId: string) =>
      `- **Contested:** finding \`${targetId}\`, which is no longer in this image's ledger. Re-running an analysis replaces its rows with new ids, so a dispute can outlive the row it was recorded against: the claim is kept, and what it pointed at cannot be shown here.`,
    contestedUntilWithdrawn: (p: { title: string; proofState: string }) =>
      `- **Contested until withdrawn:** “${p.title}” (\`${p.proofState}\`). The objection has been retracted, so that finding carries no contest annotation above; it stands as code decided it, and always did.`,
    contests: (p: { title: string; proofState: string }) =>
      `- **Contests:** “${p.title}” (\`${p.proofState}\`), annotated where it appears above. That row stands exactly as code decided it; this assertion is recorded beside it, not over it.`,
    amendedLost: (when: string) =>
      `- **Amended ${when}:** the claim it replaced was not preserved — this row was amended by a build that overwrote its predecessor. What stands above is the current claim only; it is not necessarily the original one.`,
    amendedSuperseding: (p: { when: string; count: number }) =>
      `- **Amended ${p.when}, superseding ${p.count} earlier ${
        p.count === 1 ? 'claim' : 'claims'
      }.** An amendment appends; it never overwrites. What the author previously stated, and on what basis — superseded, and quoted here only as history:`,
    revision: (p: { n: number; revision: RevisionText }) =>
      `  ${p.n}. \`${p.revision.claim}\`, stood from ${p.revision.from} to ${p.revision.to}${
        p.revision.title ? ` — “${p.revision.title}”` : ''
      }${
        p.revision.disputesFindingId ? ` (contested \`${p.revision.disputesFindingId}\`)` : ''
      }. Basis given at the time: ${p.revision.rationale}`,
    emailHeading: 'Draft email',
    emailSubject: (target: string) => `Subject: Security disclosure — ${target}`,
    emailGreeting: 'Hello,',
    emailIntro: (p: { count: number; filename: string; shaPrefix: string }) =>
      `I am reporting ${p.count} security ${p.count === 1 ? 'issue' : 'issues'} I found while ` +
      `analyzing the firmware image ${p.filename} (SHA-256 ${p.shaPrefix}…).`,
    emailContestedSuffix: ' — CONTESTED on my side, see the attached details',
    emailContestedNote: (n: number) =>
      `${
        n === 1 ? 'One issue above is' : `${n} issues above are`
      } marked CONTESTED: someone on my side has recorded that the finding is wrong, and their objection is in the attached details alongside the measurement. I have not removed or downgraded the finding — you have both, and I would value your reading of it.`,
    emailClosing:
      'Full technical details are attached. I am disclosing this privately and will coordinate on a timeline before ' +
      `any public discussion. Please let me know the right contact if this isn't it.`,
    emailThanks: 'Thank you,',
    emailSignature: '[your name]',
    footer:
      'Generated by FirmLab. Draft only — review before sending. Assess only firmware you are authorized to test.',
  },
};

export type Messages = typeof en;
