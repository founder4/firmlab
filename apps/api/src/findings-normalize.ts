/**
 * Pure finding normalizers — turn each provider's structured output into `Finding` drafts with an explicit,
 * honest initial proof state. No persistence, no side effects (kept separate from findings.ts so they are
 * unit-testable without loading the SQLite store).
 *
 * Initial proof-state policy (deliberately conservative):
 *   - secrets             → `static_confirmed`  (the secret is literally present in the firmware bytes)
 *   - gitleaks            → depends on the RULE: a format that identifies itself is `static_confirmed`, an
 *                            entropy heuristic is `needs_runtime_reproduction` (see the essay below)
 *   - binary hardening    → `static_confirmed`  (an NX/canary/PIC flag is a fact about the binary)
 *   - SBOM CVEs           → `needs_runtime_reproduction`  (a vulnerable component is present, but reachability
 *                            and on-device exploitability are unproven — never overstated)
 */
import type { EvidenceChannel, Finding, FindingSeverity, ProofState, StringHit } from '@firmlab/core';
import type { DecompileResult } from './providers/decompile.js';
import type { GitleaksFinding, GitleaksResult } from './providers/gitleaks.js';
import type { SbomResult, Severity } from './providers/sbom.js';

/** A finding as produced by a normalizer, before it is stamped with id/imageId/source/createdAt. */
export type FindingDraft = Omit<Finding, 'id' | 'imageId' | 'source' | 'createdAt'>;

/** Hardcoded credentials / keys / tokens found by the static string classifier over the raw image. */
export function normalizeSecrets(secrets: StringHit[]): FindingDraft[] {
  return secrets
    .filter((s) => s.secretKind)
    .map((s) => ({
      kind: s.secretKind ?? 'secret',
      title: `${s.secretKind ?? 'secret'} at 0x${s.offset.toString(16)}`,
      severity: (s.severity ?? 'medium') as FindingSeverity,
      proofState: 'static_confirmed' as ProofState,
      // The classifier read this out of the image itself; nothing was executed and nobody was asked.
      evidenceChannel: 'static_bytes' as EvidenceChannel,
      evidence: { offset: s.offset, value: s.value },
    }));
}

const SBOM_SEVERITY: Record<Severity, FindingSeverity> = {
  Critical: 'critical',
  High: 'high',
  Medium: 'medium',
  Low: 'low',
  Negligible: 'info',
  Unknown: 'info',
};

/** CVEs matched against the rootfs SBOM (syft + grype). Present ≠ reachable, hence needs_runtime_reproduction. */
export function normalizeSbom(result: SbomResult): FindingDraft[] {
  if (!result.available) return [];
  return result.vulnerabilities.map((v) => ({
    kind: 'cve',
    title: `${v.id} — ${v.packageName} ${v.packageVersion}`,
    severity: SBOM_SEVERITY[v.severity] ?? 'info',
    proofState: 'needs_runtime_reproduction' as ProofState,
    // A published database says this version is affected. Nothing here was measured on THIS image beyond the
    // package's presence — which is exactly the distinction the channel exists to make visible.
    evidenceChannel: 'external_advisory' as EvidenceChannel,
    rationale: 'Vulnerable component present in the rootfs; reachability and exploitability not yet proven.',
    evidence: { id: v.id, packageName: v.packageName, packageVersion: v.packageVersion, fixedIn: v.fixedIn },
  }));
}

/**
 * ─── gitleaks: what the rule matched decides the rung, not the fact that something matched ───
 *
 * A gitleaks hit used to be `static_confirmed` / `high` unconditionally, on the reasoning that the secret is
 * literally present in the firmware bytes. That reasoning holds for exactly one half of gitleaks' rule set.
 *
 * gitleaks has two kinds of rule. One matches an artifact that **identifies itself**: a `-----BEGIN … PRIVATE
 * KEY-----` block, an `AKIA`-prefixed AWS id, a `ghp_` token — the format IS the claim, and "an AWS access key
 * id is present in this file" is a property literally in the bytes. The other kind, `generic-api-key` and its
 * relatives, matches *an assignment to a key-ish identifier whose value scores above an entropy floor*. What is
 * literally in the bytes there is **a high-entropy string**, and nothing more. Calling that `static_confirmed`
 * promotes a heuristic to the bench's strongest rung — the exact failure the ladder exists to prevent.
 *
 * Measured on the GL.iNet BE3600 (2026-08-03): all 12 gitleaks rows were `generic-api-key`, all 12 were
 * `static_confirmed` / `high`, and all 12 were false. Seven were the *published* dnscrypt-proxy minisign
 * verification key (`RWQf6LRC…`), four of those on commented-out lines; two were the same key inside the
 * resolver directory that dnscrypt ships as documentation; one was a Lua local named `key_xord_with_0x5c`; one
 * was an MD5 of the word "password" in a commented-out usage example.
 *
 * So the demotion is rule-aware, and the discounting reads context rather than a denylist of known-public
 * values. A denylist would have had to be told about `RWQf6LRC…`; the signals below did not, because the file
 * says what the value is: the identifier that names it (`minisign_key`), the `#` in front of the line, the `.md`
 * extension. Every signal is derived from what the provider actually measured, and all of it is optional — a
 * result stored by an older build has no context at all and still normalizes, just with fewer discounts.
 *
 * Three refusals, each of which is the failure mode of the fix rather than of the bug:
 *
 *  1. **Nothing is suppressed.** A demoted hit is still a row with the same `kind` and the same evidence. The
 *     claim changes; the count does not. An empty findings list never means clean, and a shrinking one obtained
 *     by deleting rows would be the same lie in a new place.
 *  2. **Self-identifying rules are never discounted.** A PEM private key in a file called `README.md` on a
 *     commented-out line is still a private key in the shipped bytes. Applying the discounts there would be the
 *     mirror failure — this lane losing a real key to a heuristic about where keys are allowed to live — and
 *     that is worse than the bug being fixed. The discounts apply to heuristic rules only.
 *  3. **The rationale states what was observed, not what is feared.** "a high-entropy string matched rule X"
 *     rather than "a credential", plus what would settle it.
 */

/** Severity ladder, low to high. A heuristic hit is capped below `critical`: entropy cannot earn that. */
const SEVERITY_LADDER: FindingSeverity[] = ['info', 'low', 'medium', 'high', 'critical'];
const HEURISTIC_BASE = 2; // 'medium' — a lead worth ranking above noise and below a proven secret
const HEURISTIC_CEILING = 3; // 'high'

/**
 * A rule is heuristic when it matched *shape and entropy* rather than a format that names itself. gitleaks'
 * stock entropy rule is `generic-api-key`; custom rule sets name theirs similarly, and both the id and the
 * description are checked so a renamed rule with gitleaks' own wording is still caught. Everything else is
 * assumed self-identifying, which is the conservative direction: it keeps real key formats at their rung.
 */
const HEURISTIC_RULE_ID = /generic|entropy/i;
const HEURISTIC_DESCRIPTION = /\bgeneric\b/i;

export function isHeuristicGitleaksRule(rule: string, description?: string): boolean {
  return HEURISTIC_RULE_ID.test(rule) || HEURISTIC_DESCRIPTION.test(description ?? '');
}

/**
 * A line whose first non-space character opens a comment in some language the rootfs plausibly contains.
 *
 * `--` and `*` require a following space (or end of line): a bare `--` prefix is also how a command line writes
 * a long option, and `--api-key=…` in a shipped launcher is the opposite of a commented-out example.
 */
const COMMENT_MARKER = /^(#|\/\/|\/\*|<!--|;|\*(\s|$)|--(\s|$|\[\[)|dnl\s|rem\s)/i;
/** Paths whose content is prose or a shipped example rather than configuration the device reads as truth. */
const DOC_PATH =
  /(\.(md|markdown|rst|adoc|asciidoc)$)|((^|\/)(readme|changelog|changes|news|notice|authors|todo)(\.[a-z0-9]+)?$)|((^|\/)(docs?|examples?|samples?)\/)|(^usr\/share\/(doc|man)\/)/i;
/** The value is named as the PUBLIC half of a keypair, or is written in a public-key wire format. */
const PUBLIC_KEY_NAME =
  /(public[_-]?key|pubkey|minisign[_-]?key|verify[_-]?key|verification[_-]?key|signing[_-]?pubkey|authorized_keys|BEGIN PUBLIC KEY|ssh-(rsa|ed25519|dss)|ecdsa-sha2-)/i;
/** The value is named as something that must stay secret. Overrides the public-name discount when both appear. */
const SECRET_NAME =
  /(private[_-]?key|secret[_-]?key|client[_-]?secret|api[_-]?secret|passwo?rd|passwd|auth[_-]?token|access[_-]?token|bearer)/i;
/** The surrounding text calls itself an example. Weak on its own; one step, never a suppression. */
const EXAMPLE_MARKER =
  /(\bexamples?\b|\bsamples?\b|placeholder|change[_-]?me|\bdummy\b|\bfake\b|test[_-]?key|your[_-]?(key|token|secret|password)|x{5,})/i;
/** snake_case, no character outside an identifier alphabet: a variable name, not opaque key material. */
const SOURCE_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;
const IDENTIFIER_ENTROPY_CEILING = 4.5;

/** One observation about a hit, and how many rungs of severity it is worth. Negative discounts, positive raises. */
export interface GitleaksSignal {
  code: string;
  note: string;
  weight: number;
}

export interface GitleaksVerdict {
  /** `heuristic` when the rule matched entropy/shape; `self-identifying` when it matched a format. */
  ruleClass: 'heuristic' | 'self-identifying';
  proofState: ProofState;
  severity: FindingSeverity;
  title: string;
  rationale: string;
  signals: GitleaksSignal[];
}

/**
 * Decide a single gitleaks hit's rung, severity and wording. Pure and exported so the unit test reaches it with
 * the real strings from a real report — the whole point of keeping this module free of the store.
 */
export function classifyGitleaksHit(f: GitleaksFinding): GitleaksVerdict {
  const heuristic = isHeuristicGitleaksRule(f.rule, f.description);
  const where = `${f.file}:${f.line}`;

  if (!heuristic) {
    return {
      ruleClass: 'self-identifying',
      proofState: 'static_confirmed',
      severity: 'high',
      title: `${f.description || f.rule} in ${where}`,
      rationale: [
        `Rule \`${f.rule}\` matches a self-identifying artifact — the format is the claim, not the entropy —`,
        'so the property really is literally present in the extracted bytes. Not discounted by comments, file',
        'type or naming: a real key does not stop being one for sitting in documentation.',
      ].join(' '),
      signals: [],
    };
  }

  // Everything below runs on a heuristic hit only. `context` is the gitleaks match with the secret scrubbed;
  // `lineText` is the source line. Both are optional forever — absent means not measured, never measured-clean.
  const context = f.context ?? '';
  const lineText = f.lineText ?? '';
  const named = `${context} ${lineText}`;
  const signals: GitleaksSignal[] = [];

  if (lineText && COMMENT_MARKER.test(lineText)) {
    signals.push({
      code: 'commented-out',
      note: `the match sits on a commented-out line (\`${lineText.slice(0, 60)}\`), not in live configuration`,
      weight: -1,
    });
  }
  if (DOC_PATH.test(f.file)) {
    signals.push({
      code: 'documentation-file',
      note: `\`${f.file}\` is prose or a shipped example, not config`,
      weight: -1,
    });
  }

  const secretName = SECRET_NAME.exec(named);
  const publicName = PUBLIC_KEY_NAME.exec(named);
  if (secretName) {
    // A line that names a private key is not discounted for also naming the public one; the escalation wins.
    signals.push({
      code: 'secret-identifier',
      note: `the identifier naming the value (\`${secretName[0]}\`) says it is meant to stay secret`,
      weight: +1,
    });
  } else if (publicName) {
    signals.push({
      code: 'public-key-identifier',
      note: `the identifier naming the value (\`${publicName[0]}\`) says it is public/verification key material`,
      weight: -1,
    });
  }

  // This one is NOT gated on `secretName`, unlike the public-name discount above. Those two are rival readings
  // of the same identifier and only one can be right; "named private_key" and "written inside something that
  // calls itself an example" are both true at once, and on the BE3600 they are both true of the same line. The
  // signals net out to medium and the reader sees both codes, which is more honest than picking one.
  if (EXAMPLE_MARKER.test(named)) {
    signals.push({ code: 'example-marker', note: 'the surrounding text labels itself an example', weight: -1 });
  }
  if (
    SOURCE_IDENTIFIER.test(f.match) &&
    f.match.includes('_') &&
    (f.entropy === undefined || f.entropy < IDENTIFIER_ENTROPY_CEILING)
  ) {
    signals.push({
      code: 'source-identifier',
      note: `the matched value (\`${f.match}\`) is a snake_case source identifier, not opaque key material`,
      weight: -2,
    });
  }

  const shift = signals.reduce((n, s) => n + s.weight, 0);
  const index = Math.min(HEURISTIC_CEILING, Math.max(0, HEURISTIC_BASE + shift));

  const entropyPhrase = f.entropy === undefined ? '' : ` (Shannon entropy ${f.entropy.toFixed(2)})`;
  const observed = signals.length > 0 ? ` Observed: ${signals.map((s) => s.note).join('; ')}.` : '';
  return {
    ruleClass: 'heuristic',
    proofState: 'needs_runtime_reproduction',
    severity: SEVERITY_LADDER[index] ?? 'medium',
    title: `High-entropy string matched ${f.rule} in ${where}`,
    rationale: [
      `Rule \`${f.rule}\` is a heuristic: what is literally in the bytes is a high-entropy string${entropyPhrase}`,
      'assigned to a key-ish identifier — not a credential shown to authenticate anywhere. Held as a lead',
      `rather than confirmed.${observed} Settled by showing the value opens something (a service accepts it, or`,
      'it decrypts/signs material on the device), or by finding it published upstream, in which case it is a',
      'false positive.',
    ].join(' '),
    signals,
  };
}

/**
 * Deep secret scan of the extracted rootfs files (gitleaks). The rung is per-rule — see the essay above.
 * `findings` is defended because this result is re-read from a job row written by an older build.
 */
export function normalizeGitleaks(result: GitleaksResult): FindingDraft[] {
  if (!result.available) return [];
  return (result.findings ?? []).map((f) => {
    const verdict = classifyGitleaksHit(f);
    return {
      kind: f.rule,
      title: verdict.title,
      severity: verdict.severity,
      proofState: verdict.proofState,
      // Read out of a real file of the extracted rootfs, as shipped. The channel says how it was known; the
      // proof state says how far it was proven, and a heuristic match is read statically without being proven.
      evidenceChannel: 'static_bytes' as EvidenceChannel,
      rationale: verdict.rationale,
      evidence: {
        file: f.file,
        line: f.line,
        match: f.match,
        rule: f.rule,
        ruleClass: verdict.ruleClass,
        signals: verdict.signals.map((s) => s.code),
        ...(f.entropy === undefined ? {} : { entropy: f.entropy }),
        ...(f.context ? { context: f.context } : {}),
        ...(f.lineText ? { lineText: f.lineText } : {}),
      },
    };
  });
}

/** Missing exploit-mitigations on a triaged binary (radare2). A hardening flag is a fact → static_confirmed. */
export function normalizeBinaryHardening(result: DecompileResult): FindingDraft[] {
  if (!result.available) return [];
  const { info, binary } = result;
  const drafts: FindingDraft[] = [];
  const weak = (kind: string, label: string, severity: FindingSeverity): void => {
    drafts.push({
      kind,
      title: `${label}: ${binary}`,
      severity,
      proofState: 'static_confirmed',
      // A hardening flag is a field in the ELF header; radare2 read it.
      evidenceChannel: 'static_bytes',
      evidence: { binary, info },
    });
  };
  if (info.nx === false) weak('no-nx', 'Non-executable stack disabled (NX off)', 'low');
  if (info.canary === false) weak('no-canary', 'No stack canary', 'low');
  if (info.pic === false) weak('no-pic', 'No position-independent code (PIC off)', 'info');
  return drafts;
}
