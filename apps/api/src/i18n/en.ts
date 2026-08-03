/**
 * The English catalogue — the source of truth for every sentence the SERVER composes and the client prints verbatim.
 *
 * The workbench shell has its own catalogue in `apps/web/src/locales`. This one is deliberately separate and lives
 * on the API side, because the HTML report and the disclosure draft are composed by the server, leave the building
 * as files, and are read months later by someone who never opened the UI. They are also where this project's
 * prose is least decorative: the sentence that says a blocked stage is NOT a negative, that an empty ledger is not
 * a clean image, that an emulated reproduction proves the sandbox and never the device, and that an operator
 * assertion counts towards no analysis stage — those sentences *are* the product. A document that half-translates
 * them still looks finished.
 *
 * **The rule that decides what belongs here.** Stored with the image or the job → FROZEN, in the language that
 * produced it; recomputed on every read → localised. A finding's title and rationale were written at measurement
 * time and are stored as evidence about the firmware, so re-translating one would be rewriting a record. The
 * coverage verdict, the class plan's stage reasons, the tool table, the capture backends and the lane flags are the
 * opposite: they are recomputed from live state on every request and they describe THIS DEPLOYMENT and THIS
 * ANALYSIS RUN, not the firmware. They are interface copy that merely happens to be built server-side — which is
 * why `coverage`, `plan`, `tools`, `captureBackends` and `flags` below sit in the same catalogue as the report's
 * own scaffolding, and why every endpoint serving them takes the locale as a parameter.
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
import type { CaptureBackendId } from '../capture/backends.js';
import type { LaneFlagName } from '../flags.js';
import type { PlanReasonId } from '../opacidad-plan.js';
import { CLAIM_MEANING, NOT_A_MEASUREMENT, describeAssertion } from '../operator-findings.js';
import type { ToolId } from '../tools.js';
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

  /**
   * The analysis-coverage verdict — the workbench's central honesty sentence, and the reason an empty findings list
   * is never allowed to read as "clean".
   *
   * It is composed here rather than in the browser because `providers/coverage.ts` reads the same class plan the
   * autonomous scan executes, so the banner and the scan cannot disagree. That makes it server-side prose, not a
   * stored record: nothing about it is written at measurement time, it is recomputed from the stage table on every
   * request, and it describes THE ANALYSIS RUN rather than the firmware. So it is localised, while the finding
   * titles it counts are not.
   *
   * Worker names (`W3 · Credentials`, `Cross-check · Kernel command line`) arrive as data and are interpolated
   * verbatim in both languages — they are the ids the plan, the scan and the stage table all use, and a reader
   * comparing the verdict against the table underneath it must find the same strings in both.
   *
   * The branches are deliberately distinct in both languages. "Nothing has run" and "everything ran and found
   * nothing" are opposite conclusions that produce the identical empty list, so no two of them may collapse into
   * the same sentence in translation.
   */
  coverage: {
    verdict: {
      /** Nothing executed and nothing found. The strongest claim available is that nobody has looked. */
      unexamined: (applicable: number) =>
        `Nothing has analyzed this image yet — ${applicable} applicable stage(s) are unexecuted. An empty findings list here means UNEXAMINED, not clean.`,
      /** Nothing executed under the scan, yet rows exist: they came from individually-run stages. */
      unknownWithFindings: (p: { applicable: number; findingCount: number }) =>
        `No autonomous scan has run, so coverage of the ${p.applicable} applicable stage(s) is UNKNOWN. The ${p.findingCount} finding(s) here come from individually-run stages — real results, but no basis for reading the rest as clean.`,
      partialEmpty: (p: { executed: number; applicable: number; missing: number }) =>
        `${p.executed} of ${p.applicable} stages ran and recorded nothing; ${p.missing} never ran. Zero findings covers only the stages that ran — it is not a clean bill for this firmware.`,
      allRanEmpty: (applicable: number) =>
        `All ${applicable} applicable stages ran and recorded nothing. That is a real negative for what this deployment can check statically — it is not proof the firmware is secure.`,
      partialWithFindings: (p: { findingCount: number; executed: number; applicable: number; missing: number }) =>
        `${p.findingCount} finding(s) from ${p.executed} of ${p.applicable} stages; ${p.missing} never ran, so the picture is incomplete.`,
      complete: (p: { findingCount: number; applicable: number }) =>
        `${p.findingCount} finding(s) across all ${p.applicable} applicable stages.`,
    },
    /** The stages the count does NOT cover, named. `workers` are ids and are printed as given. */
    notCovered: (p: { workers: string[]; more: number }) =>
      `Not covered: ${p.workers.join(', ')}${p.more > 0 ? `, +${p.more} more` : ''}.`,
    /**
     * A degraded stage RAN, so it counts as executed — and saying "all applicable stages" while one of them only
     * half-worked lets the headline absorb the caveat its own table is showing.
     */
    degraded: (p: { count: number; workers: string[]; more: number }) =>
      `${p.count} stage(s) ran DEGRADED and cover less than their name suggests: ${p.workers.join(', ')}${
        p.more > 0 ? `, +${p.more} more` : ''
      }.`,
    /** Appended to EVERY branch, so a reader never learns that the clause only appears in some of them. */
    assertions: (n: number) =>
      [
        `Separately, ${n} operator assertion(s) are recorded on this image — statements by a named author,`,
        'not measurements. They are excluded from the count above and cover no stage.',
      ].join(' '),
    /** The reason column for a worker W9 scheduled from a lead rather than from the static class plan. */
    scheduledFromLead: 'scheduled dynamically from a lead',
  },

  /**
   * The class plan's "why this stage" column — what each worker in `opacidad-plan.ts` could even tell you.
   *
   * It sits directly underneath the coverage verdict in the same table, which is the reason it is here at all: for
   * as long as the verdict was localised and this column was not, a Spanish reader got an honest Spanish sentence
   * with an English stage-reason column beside it, and the seam was in the one panel whose whole job is to be read
   * carefully. Nothing in this column is written at measurement time — it is recomposed from `specsForClass` on
   * every request and describes THE PLAN, never a firmware image.
   *
   * Keyed by `PlanReasonId`, so a stage added to the routing is a compile error here (and in `es.ts`) until its
   * sentence exists. The worker ids beside it (`W3 · Credentials & secrets`, `Cross-check · Kernel command line`)
   * are NOT here: they are identifiers the plan, the scan and the stage table all key on, and they are printed
   * verbatim in both languages. Neither are the paths, the flags and the library names inside these sentences —
   * `init=/bin/sh`, `/dev/kmem`, `/chosen bootargs`, `os.execute/io.popen` are what you would grep for.
   */
  plan: {
    reason: {
      extract: 'recover the rootfs (recursive FIT→UBI→SquashFS carve when the container needs it)',
      credentials: 'weak/empty creds, root shells, key material',
      auxSecrets: 'embedded private keys in sibling (non-rootfs) partitions the rootfs audit never sees',
      sbom: 'components → known CVEs (the n-day surface)',
      componentFingerprint: 'bundled binaries (pppd, openssl) → CVEs a manifest-only SBOM misses',
      kernelPosture:
        'the kernel under the userland: version age, /dev/kmem, module signing, KASLR/RWX (three-state, honest)',
      serviceEnumeration: 'boot-time network daemons = attack surface',
      certificates: 'embedded X.509 posture',
      certificatesRaw: 'embedded X.509 posture (reads the raw image — no rootfs needed)',
      componentMap: 'rootfs ELF → dependency graph',
      ubootEnv: 'boot posture (init=/bin/sh, interruptible autoboot, console)',
      ubootEnvRaw: 'boot posture (init=/bin/sh, interruptible autoboot, net-boot, console)',
      deviceTree: 'board/SoC identity, declared flash map, /chosen bootargs, enabled debug UART',
      bootCmdlineCrosscheck:
        'the tree and the U-Boot env each declare one — do they agree, and which line does the board pass?',
      fccId: 'FCC IDs → public filings',
      nvram: 'flash key-value store in the raw image — credentials and wifi keys no rootfs scan can reach',
      webTaint: 'web-param → uci → os.execute/io.popen sinks (the GL.iNet Tor root-RCE class)',
      binaryVulnSweep: 'rootfs ELFs → unbounded-copy + no-canary stack-overflow candidates (DVRF pwnables)',
      updatePath: 'is the image signed, does the updater verify anything, is a downgrade bounded',
      chipsec: 'offline firmware-volume decode + Secure Boot / NVRAM posture',
      fwhunt: 'upstream FwHunt code-pattern rules → known implant / vulnerable-module families',
      rtos: 'vector table + memory map + RTOS/decode-routine detection',
      esp: 'partition table + NVS key store (signing keys!) + Flash-Enc/Secure-Boot posture',
      encrypted: 'identify cipher/mode/IV and name the key-recovery path (honest verdict, never a silent empty)',
    } satisfies Record<PlanReasonId, string>,
  },

  /**
   * The Capabilities table — what each external tool unlocks, and the placeholder version for a tool detected by
   * presence alone.
   *
   * Probed from the binaries actually on this box at request time, so this is interface copy about THIS DEPLOYMENT
   * and it is localised. The tool ids and the binary names beside it (`binwalk`, `qemu-system-mips`,
   * `analyzeHeadless`) are what you would type at a shell: they are identifiers, they key this record, and they
   * render verbatim in every language.
   *
   * The claim the page exists to make is that an absent tool is an absent ANSWER, not an absent problem. That
   * sentence lives in the web catalogue beside the count; what is here is only the per-tool "what this would let
   * you ask", and none of these may be phrased as a property of the firmware.
   */
  tools: {
    /** Keyed by `ToolId`, so a new `ToolSpec` is a compile error in `es.ts` until it is translated. */
    unlocks: {
      binwalk: 'Format-aware signature carving',
      unsquashfs: 'SquashFS extraction',
      sasquatch: 'Vendor SquashFS extraction',
      jefferson: 'JFFS2 extraction',
      lzop: 'lzop payload decompression',
      ubireader_extract_files: 'UBIFS extraction',
      cpio: 'CPIO/initramfs extraction',
      radare2: 'Binary triage + disassembly',
      analyzeHeadless: 'Ghidra headless decompilation',
      syft: 'SBOM generation',
      grype: 'CVE matching (N-day)',
      gitleaks: 'Deep secret scan',
      'qemu-mipsel-static': 'MIPSel user-mode emulation',
      'qemu-mips-static': 'Big-endian MIPS user-mode emulation',
      'qemu-arm-static': 'ARM user-mode emulation',
      'qemu-aarch64-static': 'ARM64 user-mode emulation',
      'qemu-system-mips': 'Full-system big-endian MIPS boot',
      'qemu-system-mipsel': 'Full-system MIPS boot',
      'qemu-system-arm': 'Full-system ARM boot',
      'qemu-system-aarch64': 'Full-system ARM64 boot',
      'mkfs.ext2': 'Assembling the raw disk image a full-system boot needs',
      renode: 'RTOS / Cortex-M emulation',
      chipsec: 'UEFI/BIOS firmware analysis (offline decode + IOC scan)',
      angr: 'Symbolic reachability (is a dangerous sink on a live path?)',
      'gdb-multiarch': 'Dynamic reproduction of a memory-safety candidate (does it actually crash?)',
      fwhunt: 'UEFI implant detection with real FwHunt code-pattern rules',
      // The engine, never the rules: FirmLab ships no signatures, so this line promises a scan and names whose
      // corpus it would run. A gloss that said "detects implants" would claim what only somebody's rules can.
      yara: 'Rule-based rootfs scan for known implants, webshells and backdoors, with a corpus you supply',
    } satisfies Record<ToolId, string>,
    /**
     * Shown in the version column for a tool detected by PATH existence, because executing its probe costs more
     * than the answer is worth (Ghidra spins a JVM). It states that the binary is there and that its version was
     * not asked for — it is not a version string, and it must not be mistaken for one.
     */
    installed: 'installed',
  },

  /**
   * The Capture backends table — what each backend would let an operator ACQUIRE, once it is available.
   *
   * Same category as the tool table and the same reasoning: probed from the hardware, the privileges and the
   * operator declaration present at request time, so it is interface copy about THIS DEPLOYMENT and it is
   * localised. The backend ids (`on-path-spoof`, `network-proxy`), the transports and the environment variable
   * beside them are identifiers and render verbatim in every language.
   *
   * These sentences are the ones where a milder translation costs something outside the browser: two of them
   * describe touching somebody else's network, and one describes decrypting traffic. Where the English says what
   * is done to a device, the Spanish says it too — a backend's line is read BEFORE the operator arms it.
   */
  captureBackends: {
    /** Keyed by `CaptureBackendId`, so a new backend is a compile error in `es.ts` until it is glossed. */
    unlocks: {
      'network-proxy': 'Intercept an HTTP OTA (or HTTPS when the device does not pin/validate) and carve the blob',
      'on-path-spoof': 'Get on-path for one target without router config, via ARP/DNS spoof',
      'on-path-gateway':
        'Cleanest capture: the target routes through FirmLab (default route / SPAN mirror), no spoofing',
      ble: 'Sniff a BLE OTA/DFU (Nordic DFU & friends) and reassemble the firmware',
      zigbee: 'Capture the standard Zigbee OTA Upgrade cluster (0x0019)',
      'usb-serial': 'On-device dump over UART/serial when there is no OTA to intercept',
    } satisfies Record<CaptureBackendId, string>,
  },

  /**
   * The lane flags — what each switch turns on, and what leaves this machine when it is on.
   *
   * Resolved against the environment and the stored overrides at read time, so this is interface copy about the
   * deployment rather than a record of anything. It is also the copy where understating a translation understates a
   * real consequence: the egress line is what an operator reads BEFORE flipping a switch that sends data to a third
   * party, so each one names the destination and the kind of data, and none of them softens it.
   *
   * The flag names (`FIRMLAB_RESEARCH`, `FIRMLAB_CAPTURE_GATEWAY`) key this record and render verbatim — they are
   * environment variables, and an operator grepping a compose file for one must find it.
   */
  flags: {
    FIRMLAB_AGENT: {
      label: 'AI copilot & agent',
      effect:
        'Lets the copilot and the agent skeleton run. The mechanics stay deterministic — the model only makes the judgment calls, inside a governor that halts on steps, tokens, USD or wall-clock.',
      egress:
        'Prompts built from findings and identity go to the configured LLM provider. Needs an API key; with no key the layer stays off however this is set.',
    },
    FIRMLAB_RESEARCH: {
      label: 'External intelligence',
      effect:
        'Correlates the SBOM and the components fingerprinted out of bundled binaries against published advisories, and looks up vendor disclosure contacts.',
      egress:
        'Component names and versions go to api.osv.dev and services.nvd.nist.gov; the CISA KEV catalogue is downloaded and cross-referenced locally. Never firmware bytes, secrets or keys. The egress ledger declares a ceiling before each run and reconciles it afterwards.',
    },
    FIRMLAB_HASH_LOOKUP: {
      label: 'Online password-hash lookup',
      effect:
        'Sends UNSALTED password digests recovered from the firmware to public reverse-lookup services. Salted crypt hashes are counted out and never sent; a recovered plaintext stays local and masked.',
      egress:
        'Password hashes from YOUR firmware reach a third party. This is a bigger step than a component name and it has its own switch for that reason — if an image is client or engagement material, treat this as a disclosure.',
    },
    FIRMLAB_CAPTURE: {
      label: 'Capture lane',
      effect:
        'Unlocks LAN discovery and the interception backends used to acquire firmware from a live device. Nothing touches the wire until a specific action is armed on a single, time-boxed target.',
      egress: 'Discovery sweeps the local subnet (nmap / arp-scan / mDNS). Nothing about your firmware leaves.',
    },
    FIRMLAB_CAPTURE_GATEWAY: {
      label: 'Declare on-path positioning',
      effect:
        'Your assertion that FirmLab is ALREADY on the target’s path — its default route, or fed by a port mirror. It spawns nothing; it is what makes an ARP spoof unnecessary, so a capture session positions as `gateway` instead. Declare it falsely and a session will report the target on-path and capture nothing.',
      egress: 'Nothing by itself. It changes how a capture session positions, not what it sends.',
    },
    FIRMLAB_EMU_ISOLATE: {
      label: 'Cut the emulated firmware off the internet',
      effect:
        'Adds `restrict=on` to the emulated guest’s network, so a firmware booted under full-system emulation can no longer reach anything beyond the emulator. Host→guest forwards keep working, so the rung still reaches its own services. The guest keeps seeing a gateway that answers, so it gets timeouts rather than “network unreachable” — a firmware behaves closer to normal under this than under a dead link.',
      egress:
        'ON BY DEFAULT — this is the one switch here you turn OFF to let something out, and turning it off lets A FIRMWARE YOU ARE ANALYSING REACH THE INTERNET FROM THIS MACHINE. Measured on this corpus: a booted TP-Link WDR3600 reached three public NTP servers back when off was the default. The default was flipped after measuring the cost: the same image booted open and isolated recorded the same 15 external attempts and the same verdict, so no analysis rung depends on outbound. Either way, what the firmware TRIED to reach is recorded and shown — blocking the traffic does not hide the attempt.',
    },
    FIRMLAB_EMU_REPAIR: {
      label: 'Repair the guest at boot so services can answer',
      effect:
        'Appends ONE line to the firmware’s own init script in the booted disk image, which waits ~20 s and then runs the vendor’s own `/etc/rc.d/iptables-stop` — a teardown script shipped byte-identical in all three corpus routers that nothing in the vendor boot path ever calls. It reads the live ruleset with `iptables-save` first, so a run can report that the firewall was empty and the repair changed nothing. Nothing else is written into the guest: no binary, no script, no busybox of ours.',
      egress:
        'Nothing leaves this machine. What it changes is the ARTEFACT: a service that answers on a repaired boot may be answering only because its packet filtering was torn down, which is a different claim from answering as shipped. Every finding from such a boot carries that sentence in `interventions`, and the init script is restored to its original bytes as soon as the image is built.',
    },
  } satisfies Record<LaneFlagName, { label: string; effect: string; egress: string }>,
};

export type Messages = typeof en;
