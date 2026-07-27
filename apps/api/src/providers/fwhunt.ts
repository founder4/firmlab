/**
 * fwhunt-scan provider — the honest route to UEFI implant detection.
 *
 * The UEFI track already parses firmware volumes and enumerates modules (providers/chipsec.ts), and it carries a
 * `FIRMLAB_UEFI_IOC` hook for operator-supplied indicators. What it deliberately does NOT carry is a curated feed
 * of "known implant" GUIDs, and the reason is recorded in docs/BACKLOG.md: the advanced implants people actually
 * care about — LoJax, MoonBounce, CosmicStrand, BlackLotus — are not reliably GUID-detectable, and there are no
 * stable public file-GUIDs for those families. A hand-assembled GUID list would have looked like threat
 * intelligence and been fabrication. That is precisely why Binarly's FwHunt rules match on CODE PATTERNS (esil
 * expressions, hex strings, NVRAM variable usage) rather than identity.
 *
 * So FirmLab ships the SCANNER and the upstream RULES as data, and authors neither. This provider runs
 * `fwhunt_scan_analyzer.py scan-firmware` over a UEFI image with the rule corpus and turns its verdicts into
 * findings.
 *
 * The honesty contract:
 *
 *  - A rule match is `static_confirmed` and the claim is *this rule matched these bytes*, attributed to the rule's
 *    own name and category. FirmLab is not the author of the detection and does not restate it as its own verdict.
 *  - NO match is NOT "no implant". The corpus covers the families someone wrote a rule for; everything else is
 *    unexamined by construction. The result therefore always carries how many rules ran, and a clean scan emits an
 *    explicit `info` finding saying what was and was not covered, rather than an empty result that reads as clean.
 *  - fwhunt-scan / rizin absent ⇒ `blocked_by_platform` with the reason, never a silent skip.
 *  - Rules scoped to volume GUIDs this image does not have are SKIPPED by the scanner. That is a real coverage
 *    hole, so the run counts them and says so instead of letting them inflate the "rules ran" number.
 *
 * The output parser and the finding builder are PURE and unit-tested; the runner only shells out under a timeout.
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import type { FindingDraft } from '../findings-normalize.js';
import { fwhuntPython, fwhuntRulesDir, isToolAvailable } from '../tools.js';
import type { JobHandle } from './jobs.js';

const execFileAsync = promisify(execFile);

/** Scanning a full image against the whole corpus is minutes of rizin analysis, not seconds. */
export const DEFAULT_TIMEOUT_MS = 15 * 60 * 1000;

/** One rule variant's verdict, as the analyzer reports it. */
export interface RuleVerdict {
  rule: string;
  /** Rules ship variants (`default`, `variant1`…); each is scanned and reported separately. */
  variant?: string;
  matched: boolean;
  /** The EFI module the rule was evaluated against, when the scanner names one. */
  module?: string;
}

export interface FwHuntResult {
  available: boolean;
  reason: string;
  /** Distinct rules that actually ran against this image. */
  rulesRun: number;
  /** Rules present in the corpus that never ran here (no matching firmware volume / module). */
  rulesNotApplicable: number;
  rulesInCorpus: number;
  matches: RuleVerdict[];
  findings: FindingDraft[];
}

/** Severity by rule category — a live threat rule is not the same claim as a mitigation-hygiene rule. */
const CATEGORY_SEVERITY: Record<string, FindingDraft['severity']> = {
  Threats: 'critical',
  SupplyChain: 'high',
  Vulnerabilities: 'high',
  MitigationFailures: 'medium',
};

/** Strip the ANSI colour click emits when it thinks it has a terminal. */
function stripAnsi(s: string): string {
  // biome-ignore lint/suspicious/noControlCharactersInRegex: matching the ESC of an ANSI SGR sequence is the point.
  return s.replace(/\[[0-9;]*m/g, '');
}

/**
 * Pure: normalize the analyzer's stdout into per-rule-variant verdicts.
 *
 * The real shape, from `fwhunt_scan_analyzer.py`:
 *
 *   Scanner result <RuleName> (variant: <label>) No threat detected
 *   Scanner result <RuleName> (variant: <label>) No threat detected (<ModuleName>)
 *   Scanner result <RuleName> (variant: <label>) FwHunt rule has been triggered and threat detected!
 *
 * A line that carries the `Scanner result` prefix but cannot be read is COUNTED rather than dropped silently: a
 * verdict we could not parse is an unknown, and an unknown must not be quietly folded into "nothing matched".
 */
export function parseFwHuntOutput(stdout: string): { verdicts: RuleVerdict[]; unreadableLines: number } {
  const verdicts: RuleVerdict[] = [];
  let unreadableLines = 0;

  for (const raw of stdout.split('\n')) {
    const line = stripAnsi(raw).trim();
    if (!line.startsWith('Scanner result')) continue;
    const m = /^Scanner result\s+(\S+)\s+\(variant:\s*([^)]*)\)\s+(.*)$/.exec(line);
    if (!m) {
      unreadableLines++;
      continue;
    }
    const tail = (m[3] as string).trim();
    const matched = /threat detected!/i.test(tail);
    const clean = /^no threat detected/i.test(tail);
    if (!matched && !clean) {
      // An unrecognised verdict is not a negative one.
      unreadableLines++;
      continue;
    }
    const mod = /\(([^)]+)\)\s*$/.exec(tail);
    const variant = (m[2] as string).trim();
    verdicts.push({
      rule: m[1] as string,
      matched,
      ...(variant ? { variant } : {}),
      ...(mod ? { module: mod[1] as string } : {}),
    });
  }

  return { verdicts, unreadableLines };
}

/**
 * Pure: the corpus category a rule belongs to, from its path (`.../Threats/BlackLotusBootkit.yml` → `Threats`).
 * The scanner reports only the rule NAME, so the caller resolves the path from the corpus listing.
 */
export function ruleCategory(rulePath: string): string | undefined {
  const parts = rulePath.split('/').filter(Boolean);
  const known = Object.keys(CATEGORY_SEVERITY);
  return parts.find((p) => known.includes(p));
}

/**
 * Pure: turn the verdicts into findings.
 *
 * A match is the only outcome that makes a positive claim, and it is phrased as the RULE's claim — FirmLab did not
 * author the detection and says so. Every run, matched or not, also emits one coverage note: without it a scan
 * that matched nothing would be an empty result, and an empty result reads as "no implant" when what it actually
 * means is "no rule for whatever might be in here fired". Skipped rules are named in that note because they are
 * coverage the operator did not get.
 */
export function buildFwHuntFindings(input: {
  verdicts: RuleVerdict[];
  unreadableLines?: number;
  /** Rule name → its path in the corpus, so a match can be attributed to a category. */
  rulePaths?: Record<string, string>;
  /** Total rules present in the corpus — the denominator the run's coverage is measured against. */
  rulesInCorpus?: number;
  rulesDir?: string;
}): FindingDraft[] {
  const { verdicts, unreadableLines = 0, rulePaths = {}, rulesInCorpus = 0, rulesDir = fwhuntRulesDir() } = input;
  const drafts: FindingDraft[] = [];
  const matched = verdicts.filter((v) => v.matched);
  const distinctRun = new Set(verdicts.map((v) => v.rule));

  for (const v of matched) {
    const category = ruleCategory(rulePaths[v.rule] ?? v.rule);
    drafts.push({
      kind: 'uefi-fwhunt-match',
      title: `FwHunt rule ${v.rule} matched this firmware${category ? ` (${category})` : ''}`,
      severity: (category && CATEGORY_SEVERITY[category]) || 'high',
      proofState: 'static_confirmed',
      evidence: {
        rule: v.rule,
        ...(v.variant ? { variant: v.variant } : {}),
        ...(v.module ? { module: v.module } : {}),
        ...(category ? { category } : {}),
      },
      rationale: [
        `The FwHunt rule '${v.rule}' matched the code patterns it looks for in this image. FwHunt rules match on`,
        'code (esil expressions, hex strings, NVRAM usage) rather than on file GUIDs, which is what makes them',
        "usable against implants that have no stable identity. The claim here is the RULE's, not FirmLab's:",
        'FirmLab runs the upstream corpus and does not author detections. Read the rule to see exactly what it',
        'asserts before acting on it — a match on a Vulnerabilities or MitigationFailures rule describes a',
        'weakness, not an active implant.',
      ].join(' '),
    });
  }

  // The denominator matters more than the numerator. A rule only runs when the image contains the firmware volume
  // or module it is scoped to, so most of the corpus never applies to any given image — on real OVMF, 27 of 108.
  // Reporting "no matches" without that ratio would present a 25%-coverage scan as a clean bill of health.
  const notApplicable = Math.max(0, rulesInCorpus - distinctRun.size);
  const scopeNote =
    rulesInCorpus > 0
      ? ` ${distinctRun.size} of the ${rulesInCorpus} rule(s) in the corpus ran; the other ${notApplicable} never applied to this image (they are scoped to firmware volumes or modules it does not contain), so they examined nothing.`
      : '';
  const unreadableNote = unreadableLines
    ? ` ${unreadableLines} verdict line(s) could not be parsed, so those results are unknown rather than negative.`
    : '';

  drafts.push({
    kind: 'uefi-fwhunt-coverage',
    title: matched.length
      ? `FwHunt: ${matched.length} rule match(es) across ${distinctRun.size} rule(s) run`
      : `FwHunt: no rule matched — ${distinctRun.size} rule(s) ran, which is not "no implant"`,
    severity: 'info',
    proofState: 'static_confirmed',
    evidence: {
      rulesRun: distinctRun.size,
      rulesInCorpus,
      rulesNotApplicable: notApplicable,
      variantsEvaluated: verdicts.length,
      rulesMatched: matched.length,
      unreadableLines,
      rulesDir,
    },
    rationale: [
      `${distinctRun.size} FwHunt rule(s) ran against this image and ${matched.length} matched.${scopeNote}${unreadableNote}`,
      'Beyond that, a rule corpus only covers what someone wrote a rule for, so a scan with no matches means the',
      'KNOWN families were not found — never that the firmware carries no implant. Everything the corpus has no',
      'rule for is unexamined by construction, and no amount of scanning changes that.',
    ].join(' '),
  });

  return drafts;
}

/** Every rule in the corpus, as `name → path`. The scanner prints only names, so matches are attributed via this. */
export function indexRuleCorpus(rulesDir: string): Record<string, string> {
  const index: Record<string, string> = {};
  const walk = (dir: string): void => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const abs = path.join(dir, e.name);
      if (e.isDirectory()) walk(abs);
      else if (e.isFile() && /\.ya?ml$/i.test(e.name)) {
        index[e.name.replace(/\.ya?ml$/i, '')] = path.relative(rulesDir, abs);
      }
    }
  };
  walk(rulesDir);
  return index;
}

function unavailable(reason: string): FwHuntResult {
  return {
    available: false,
    reason,
    rulesRun: 0,
    rulesNotApplicable: 0,
    rulesInCorpus: 0,
    matches: [],
    findings: [
      {
        kind: 'uefi-fwhunt-blocked',
        title: 'UEFI implant scan (FwHunt) could not run',
        severity: 'info',
        proofState: 'blocked_by_platform',
        evidence: { reason },
        rationale:
          'The implant-rule scan was requested but this deployment could not perform it. Recorded so the absence ' +
          'of implant findings is visible as a missing capability rather than mistaken for a clean firmware.',
      },
    ],
  };
}

/**
 * Scan a UEFI image with the FwHunt rule corpus. Degrades honestly at every step: scanner absent, rules missing,
 * or a crashing analyzer each produce a `blocked` finding naming the reason instead of an empty result.
 */
export async function runFwHunt(
  imagePath: string,
  handle: JobHandle,
  timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<FwHuntResult> {
  if (!(await isToolAvailable('fwhunt'))) {
    handle.log('fwhunt-scan not available — rebuild the tools base with the optional fwhunt layer.');
    return unavailable('fwhunt-scan (or its rizin backend) is not installed in this deployment');
  }

  const rulesDir = fwhuntRulesDir();
  if (!fs.existsSync(rulesDir)) {
    return unavailable(`FwHunt rule corpus not found at ${rulesDir} — set FIRMLAB_FWHUNT_RULES`);
  }

  // The analyzer is a console script inside the same venv as the library, next to its interpreter.
  const analyzer = path.join(path.dirname(fwhuntPython()), 'fwhunt_scan_analyzer.py');
  // `--force` lets rules that declare no volume GUID run instead of being silently skipped — strictly more
  // coverage, and the residual gap is reported rather than hidden.
  const scanArgs = ['scan-firmware', imagePath, '-d', rulesDir, '--force'];
  const args = fs.existsSync(analyzer)
    ? [analyzer, ...scanArgs]
    : ['-m', 'fwhunt_scan.fwhunt_scan_analyzer', ...scanArgs];

  handle.log(`fwhunt: scanning ${path.basename(imagePath)} against the rule corpus at ${rulesDir}.`);
  let stdout = '';
  try {
    const r = await execFileAsync(fwhuntPython(), args, { timeout: timeoutMs, maxBuffer: 32 * 1024 * 1024 });
    stdout = r.stdout;
  } catch (err) {
    // The analyzer exits non-zero on a match in some versions, so partial stdout is a normal success path — only
    // a run that produced nothing readable is a real failure.
    const e = err as { stdout?: string; message?: string };
    stdout = e.stdout ?? '';
    if (!stdout.trim()) {
      const message = e.message ?? String(err);
      handle.log(`fwhunt failed: ${message}`);
      return unavailable(`fwhunt-scan failed: ${message}`);
    }
  }

  const { verdicts, unreadableLines } = parseFwHuntOutput(stdout);
  if (verdicts.length === 0) {
    return unavailable('fwhunt-scan produced no readable rule verdicts — treat the scan as not performed');
  }

  const rulePaths = indexRuleCorpus(rulesDir);
  const rulesInCorpus = Object.keys(rulePaths).length;
  const distinctRun = new Set(verdicts.map((v) => v.rule)).size;
  const matched = verdicts.filter((v) => v.matched);
  const reason =
    `FwHunt: ${matched.length} match(es) across ${distinctRun}/${rulesInCorpus} rule(s) that applied to this image. ` +
    'No match means the known families were not found, never that the firmware is implant-free.';
  handle.log(reason);

  return {
    available: true,
    reason,
    rulesRun: distinctRun,
    rulesNotApplicable: Math.max(0, rulesInCorpus - distinctRun),
    rulesInCorpus,
    matches: matched,
    findings: buildFwHuntFindings({ verdicts, unreadableLines, rulePaths, rulesInCorpus, rulesDir }),
  };
}
