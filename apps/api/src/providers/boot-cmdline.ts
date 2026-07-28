/**
 * The kernel command line audit, shared by every provider that can find one.
 *
 * "The kernel boots to a root shell" and "a serial console is on the kernel command line" are facts about a
 * *command line*, not about U-Boot. They were first implemented in `uboot.ts` because the U-Boot environment was
 * the first place this workbench could read one; the flattened device tree's `/chosen` node carries the same
 * string, and a second set of finding codes for the same fact would split the ledger into two dialects — a
 * consumer filtering for "does this image drop to a root shell" would have to know every provider that can answer.
 *
 * So the codes stay exactly as `uboot.ts` minted them (`uboot-root-shell`, `uboot-serial-console`) and only the
 * PROVENANCE varies: `origin` says where the string was read from, in the finding's rationale and its evidence.
 * The ledger's own `source` column already separates the providers; `kind` is the class of fact, and the class is
 * the same one. Renaming the codes to be provider-neutral would be tidier and is deliberately not done — it would
 * silently reclassify every finding already stored under the old codes.
 *
 * Proof states are unchanged and deliberately split: a root-shell command line is a LEAD
 * (`needs_runtime_reproduction`) because only a real boot proves the device honours it, while an exposed console
 * directive is `static_confirmed` because the directive is literally in the bytes.
 *
 * ---
 *
 * **The cross-check.** Once two providers answer the same question, the interesting case is the one where they
 * answer it *differently*. The tree's `/chosen` line is what the BUILD expects; the environment's `bootargs` is
 * what the BOARD would pass. When an image carries both and they diverge, that divergence is itself the finding —
 * and it is the only thing here that no single provider can see, because each one only ever holds its own half.
 *
 * A disagreement has to survive normalisation, or the workbench would mint findings out of formatting. Normalised
 * away, with the reason each is cosmetic:
 *
 *  - **Whitespace.** Runs of spaces/tabs/newlines collapse and the line is trimmed. A device-tree property is a
 *    NUL-terminated string that routinely carries stray padding, and `bootargs-append` is joined on with a space.
 *  - **The order of independent parameters.** The kernel parses parameters one at a time and each stands alone, so
 *    `root=/dev/mtdblock2 console=ttyS0` and `console=ttyS0 root=/dev/mtdblock2` configure the same boot.
 *  - **Repeated parameters the kernel resolves last-wins.** A `__setup`/module-param handler is called once per
 *    occurrence and simply overwrites, so `rw ... rw` and `root=a root=b` reduce to the last one — which is what
 *    the kernel would end up with.
 *
 * Deliberately NOT normalised, because each of these changes what the board boots:
 *
 *  - **Repetition and order of `console=` (and `earlycon`, `earlyprintk`, `initcall_blacklist`).** These do not
 *    overwrite — every occurrence registers, and for `console=` the LAST one becomes `/dev/console`. Sorting them
 *    or collapsing them to one would erase a real difference in where the kernel talks.
 *  - **Everything after a standalone `--`.** Those are init's argv, not kernel parameters; their order is theirs.
 *  - **Case, and the values themselves.** `root=/dev/mtdblock2` and `root=31:02` may name the same device, and
 *    deciding that needs the flash layout. Equating them would be the workbench asserting a board fact it has not
 *    read, so they are reported as the difference they literally are and the finding quotes both strings.
 *
 * The bias of that list is one-directional and on purpose: a key wrongly treated as last-wins can only HIDE a
 * difference, never invent one. Fabricating a disagreement is the worse failure, so where the semantics are
 * unclear the check stays quiet.
 *
 * **U-Boot variable references, which the corpus forced.** The one image in this corpus carrying both sources
 * (the Tenda camera) stores `bootargs=console=${console} root=${mtd_root} rootfstype=${rootfstype} init=${init}`
 * — a TEMPLATE, not a command line. Compared literally it "differs" from the tree on `console=`, which it does
 * not: the env's own `console` variable holds exactly the tree's value. So a source may carry its variable store
 * with it, and `${x}` / `$(x)` / `$x` are resolved from it before anything is compared; the finding then quotes
 * the stored literal, the expanded line and every substitution, so the reader can redo it by hand. Expansion is a
 * property of the SOURCE, not of the string: a device-tree property is a literal, so a `$` in one stays a `$`.
 * A reference that does not resolve stops the comparison outright (`unresolved-variables`) rather than letting an
 * unexpanded `${x}` masquerade as a differing value — the check refuses to answer instead of answering wrongly.
 *
 * **The line a boot script assembles, which the same image forced again.** `bootargs` is a stored variable and a
 * `bootcmd` is free to overwrite it before it boots — which the Tenda's does: `bootcmd=run boot_normal`, and
 * `boot_normal` performs `env set bootargs … ${mtdparts}${mtdparts1} ${mem} ${memsize}`, a line carrying the very
 * `mem`/`memsize` parameters whose absence from the stored variable this check was reporting as a disagreement. So
 * the U-Boot side may hand over what a script BUILDS as well as what the environment stores, and the assembled line
 * is what gets compared when one exists — it is closer to what the board passes. Every finding then names which of
 * the two it compared, because a reader who cannot tell which string was used cannot check the claim.
 *
 * What the assembled line is NOT is an execution. `uboot.ts` reads script text: a conditional makes more than one
 * assignment reachable, so all of them are compared and reported rather than one being chosen; a `run` the walk
 * could not follow is named. And when a script assembles a line that cannot be resolved, the comparison is REFUSED
 * rather than quietly falling back to the stored variable — the script overwrites that variable, so it is known
 * *not* to be the operative line, and comparing it is precisely the defect this paragraph exists to fix.
 *
 * That is also why a source may declare its variable store COMPLETE. `${mtdparts1}` is not in the Tenda's
 * environment at all, and U-Boot expands an unset variable to nothing; the blanket refusal above exists because a
 * name missing from a store we may have CAPPED could be a variable the board really has. When the provider can say
 * it dropped nothing and decoded everything, an absent name is the board's own answer — recorded as `unset` rather
 * than as unresolved, and the comparison proceeds.
 *
 * Two refusals bound the result. **Both sources present is a precondition, not an assumption**: only one, or
 * neither, is neither disagreement nor agreement, and `verdict` keeps every case apart so no reader can
 * collapse "we could not ask" into "they match". And the finding's `static_confirmed` claims exactly one thing —
 * that two parsed structures in these bytes carry different strings. Not that the board is misconfigured, not
 * that either line is exploitable, and *not* which line the kernel receives: U-Boot normally writes `$bootargs`
 * into `/chosen/bootargs` before handing the tree over, so the environment usually wins — but nothing in these
 * bytes proves this board takes that path.
 */
import type { FindingDraft } from '../findings-normalize.js';

/** Where a command line was read from, so the finding can say so without inventing a new finding code. */
export interface CmdlineOrigin {
  /** Human phrase completing "…is present in {where}", e.g. 'the stored U-Boot environment'. */
  where: string;
  /** Provenance fields merged into every finding's evidence (the variable name, the device-tree path, …). */
  evidence: Record<string, unknown>;
}

/** Truncate a value for evidence so a huge command line cannot bloat the finding. */
export function truncate(s: string, n = 200): string {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

/**
 * Pure: audit one kernel command line. Returns the root-shell finding (when the line hands PID 1 or an
 * interactive shell to whoever powers the board on) and the serial-console finding (when it names a console).
 * Every finding quotes the offending string and asserts only what the string actually contains.
 */
export function auditKernelCommandLine(cmdline: string, origin: CmdlineOrigin): FindingDraft[] {
  const drafts: FindingDraft[] = [];
  if (!cmdline) return drafts;

  const markers: string[] = [];
  if (/\binit=\/bin\/sh\b/.test(cmdline)) markers.push('init=/bin/sh');
  if (/\brdinit=/.test(cmdline)) markers.push('rdinit=');
  if (/(?:^|\s)single(?:\s|$)/.test(cmdline)) markers.push('single');
  if (markers.length > 0) {
    drafts.push({
      kind: 'uboot-root-shell',
      title: 'Kernel command line drops to an unauthenticated root shell',
      severity: 'high',
      proofState: 'needs_runtime_reproduction',
      evidence: { ...origin.evidence, value: truncate(cmdline), markers },
      rationale: [
        `The kernel command line in ${origin.where} hands PID 1 / an interactive shell to whoever powers the`,
        'device on (no authentication). Confirmed by a real boot — hence needs_runtime_reproduction, not',
        'asserted device compromise.',
      ].join(' '),
    });
  }

  const cm = /\bconsole=(\S+)/.exec(cmdline);
  if (cm) {
    drafts.push({
      kind: 'uboot-serial-console',
      title: `Kernel serial console exposed (console=${truncate(cm[1] ?? '', 32)})`,
      severity: 'info',
      proofState: 'static_confirmed',
      evidence: { ...origin.evidence, value: truncate(cmdline), console: cm[1] },
      rationale: [
        'A serial console on the kernel command line means physical UART access yields boot logs and, combined',
        `with a command-line shell, an interactive session. The console= directive is present in ${origin.where}.`,
      ].join(' '),
    });
  }

  return drafts;
}

// === Cross-check: the same question, answered twice ======================================================

/**
 * One command line as a provider read it, with the provenance the finding will quote. `value` is the ASSEMBLED
 * line — for the device tree that means `bootargs` already concatenated with the OpenWrt/U-Boot `bootargs-append`
 * extension, because the concatenation is what a board would boot with and comparing only the first half would
 * manufacture a difference out of a property split.
 */
export interface CmdlineSource {
  value: string;
  origin: CmdlineOrigin;
  /**
   * The source's own variable store, when it HAS one. Present for a U-Boot environment (whose `bootargs` is
   * routinely a template of `${x}` references) and absent for a device-tree property (a literal string, where a
   * `$` is just a `$`). Supplying it is what licenses expansion — see the module header. The map may be capped by
   * the provider that produced it, in which case a dropped variable surfaces as an unresolved reference and the
   * comparison is refused rather than guessed.
   */
  variables?: Record<string, string>;
  /**
   * True when `variables` is the WHOLE store the source has — nothing dropped by a cap, nothing that failed to
   * decode. Only then may a reference to a name the store lacks be read as U-Boot's own rule (an unset variable
   * expands to nothing) rather than as our own blind spot. Absent means "cannot claim completeness", which keeps
   * every existing caller on the refusal path it had before this field existed.
   */
  variablesComplete?: boolean;
}

/**
 * A command line a `bootcmd`/`preboot` script ASSEMBLES, as the cross-check needs to see it. Same shape as any
 * other source plus the one thing a comparison must not lose: whether a static read could say this variant runs.
 */
export interface AssembledCmdlineSource extends CmdlineSource {
  /** True when the assignment sits under an `if`/`while`/`for` — reachable, but not established as the one. */
  conditional?: boolean;
}

/** The U-Boot side's second answer: what a boot script builds, and what reading it could not decide. */
export interface UbootScriptCmdlines {
  /** One per DISTINCT `setenv bootargs` the script reaches. Empty means the script sets no command line. */
  assembled: AssembledCmdlineSource[];
  /** True when the read cannot say which variant runs (several, a conditional, or an unfollowable `run`). */
  ambiguous?: boolean;
  /** The reader's own sentence, quoted verbatim so the claim travels with the limits its author put on it. */
  note?: string;
}

/** The three spellings U-Boot's own `setenv` accepts for a variable reference. */
const VAR_REF_RE = /\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|\(([A-Za-z_][A-Za-z0-9_]*)\)|([A-Za-z_][A-Za-z0-9_]*))/g;

/** A variable may expand to something that itself references a variable; four passes, then it is a loop. */
const MAX_EXPANSION_PASSES = 4;

/** A command line with its variable references resolved — or the record of why they could not be. */
export interface ExpandedCmdline {
  /** The line actually compared: fully expanded, or the input verbatim when the source has no variable store. */
  value: string;
  /** Every substitution made, so the finding can show its working. */
  substitutions: Record<string, string>;
  /** References that did not resolve. Non-empty means the line is still a template and must not be compared. */
  unresolved: string[];
  /**
   * References the store PROVES are unset, expanded to nothing exactly as U-Boot's own `setenv` does. Only ever
   * non-empty when the source declared its store complete; without that declaration an absent name is
   * `unresolved`, because it may be a variable our own cap dropped rather than one the board does not have.
   */
  unset: string[];
}

/**
 * Pure: resolve `${x}` / `$(x)` / `$x` in a command line from the source's own variable store. With no store the
 * line is returned verbatim and nothing is ever reported unresolved — a literal `$` in a device-tree string is a
 * `$`, not a reference. Bounded at `MAX_EXPANSION_PASSES`; anything still referencing after that (a self- or
 * mutually-recursive variable) is reported unresolved rather than expanded further.
 *
 * `options.complete` says the store is everything the source has, which changes what an ABSENT name means: not
 * "we may have dropped it" but "the board does not carry it", which U-Boot expands to nothing. Those names are
 * recorded in `unset` rather than `unresolved`, so the substitution is still visible and auditable.
 */
export function expandCmdlineVariables(
  line: string,
  variables?: Record<string, string>,
  options?: { complete?: boolean },
): ExpandedCmdline {
  if (!variables) return { value: line, substitutions: {}, unresolved: [], unset: [] };

  const complete = options?.complete === true;
  const substitutions: Record<string, string> = {};
  const unresolved = new Set<string>();
  const unset = new Set<string>();
  let value = line;
  for (let pass = 0; pass < MAX_EXPANSION_PASSES; pass++) {
    let changed = false;
    value = value.replace(VAR_REF_RE, (match, braced?: string, parens?: string, bare?: string) => {
      const name = braced ?? parens ?? bare;
      if (name === undefined) return match;
      const resolved = variables[name];
      if (resolved === undefined) {
        if (!complete) {
          unresolved.add(name);
          return match;
        }
        unset.add(name);
        changed = true;
        return '';
      }
      substitutions[name] = resolved;
      changed = true;
      return resolved;
    });
    if (!changed) break;
  }
  for (const m of value.matchAll(VAR_REF_RE)) {
    const name = m[1] ?? m[2] ?? m[3];
    if (name !== undefined) unresolved.add(name);
  }
  return { value, substitutions, unresolved: [...unresolved].sort(), unset: [...unset].sort() };
}

/**
 * Parameters whose repetition and relative ORDER the kernel honours instead of overwriting. `console=` is the one
 * that matters in practice: every occurrence registers a console and the last becomes `/dev/console`, so
 * `console=ttyS0 console=tty1` and `console=tty1 console=ttyS0` are two different boots. The list is deliberately
 * short — a key wrongly left OUT of it can only make the check quieter, never louder.
 */
const ORDER_SENSITIVE_KEYS = new Set(['console', 'earlycon', 'earlyprintk', 'initcall_blacklist']);

/** How many differing parameters a finding lists before it starts saying how many it dropped. */
const DIFF_CAP = 16;

/** A command line reduced to the form the kernel would actually end up applying. */
export interface NormalizedCmdline {
  /** The canonical string; two lines are the same boot configuration iff these are equal. */
  canonical: string;
  /**
   * Per parameter key, the token(s) that survive normalisation, in the order the kernel applies them. Exactly one
   * entry for a last-wins key; every occurrence, in order, for an order-sensitive one.
   */
  byKey: Map<string, string[]>;
  /** Everything after a standalone `--`: init's argv, kept verbatim and in order. */
  initArgs: string[];
}

/**
 * Split a command line into tokens on whitespace, honouring the kernel's own double-quote rule so a
 * `param="a b"` value stays one token. The quote characters are kept in the token text — both sides are split by
 * the same code, so keeping them cannot make two identical lines compare unequal.
 */
function splitTokens(line: string): string[] {
  const out: string[] = [];
  let current = '';
  let quoted = false;
  for (const ch of line) {
    if (ch === '"') {
      quoted = !quoted;
      current += ch;
    } else if (!quoted && /\s/.test(ch)) {
      if (current !== '') out.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  if (current !== '') out.push(current);
  return out;
}

/** The parameter name of a token — everything before the first `=`, or the whole token for a bare flag. */
function tokenKey(token: string): string {
  const eq = token.indexOf('=');
  return eq < 0 ? token : token.slice(0, eq);
}

/**
 * Pure: reduce a kernel command line to what the kernel would end up applying. See the module header for exactly
 * what this normalises and what it deliberately refuses to.
 */
export function normalizeCommandLine(line: string): NormalizedCmdline {
  const tokens = splitTokens(line);
  const sep = tokens.indexOf('--');
  const kernelTokens = sep < 0 ? tokens : tokens.slice(0, sep);
  const initArgs = sep < 0 ? [] : tokens.slice(sep + 1);

  const byKey = new Map<string, string[]>();
  for (const token of kernelTokens) {
    const key = tokenKey(token);
    if (ORDER_SENSITIVE_KEYS.has(key)) {
      const seen = byKey.get(key);
      if (seen) seen.push(token);
      else byKey.set(key, [token]);
    } else {
      // Last occurrence wins, exactly as a __setup / module-param handler does: it is called once per occurrence
      // and simply overwrites what the previous call stored.
      byKey.set(key, [token]);
    }
  }

  const ordered = [...byKey.keys()].sort().flatMap((k) => byKey.get(k) as string[]);
  const canonical = [...ordered, ...(initArgs.length > 0 ? ['--', ...initArgs] : [])].join(' ');
  return { canonical, byKey, initArgs };
}

/** One parameter the two sources do not answer the same way. `null` means the source does not carry the key at all. */
export interface CmdlineDifference {
  key: string;
  deviceTree: string[] | null;
  ubootEnv: string[] | null;
}

/**
 * Pure: the parameter-level differences between two normalised lines, keyed and sorted by parameter name — so a
 * later cap drops by name, never by where a token happened to sit in the line. An empty array means the two lines
 * are the same boot configuration.
 */
export function diffCommandLines(deviceTree: NormalizedCmdline, ubootEnv: NormalizedCmdline): CmdlineDifference[] {
  const out: CmdlineDifference[] = [];
  const keys = [...new Set([...deviceTree.byKey.keys(), ...ubootEnv.byKey.keys()])].sort();
  for (const key of keys) {
    const dt = deviceTree.byKey.get(key) ?? null;
    const env = ubootEnv.byKey.get(key) ?? null;
    if (dt && env && dt.join(' ') === env.join(' ')) continue;
    out.push({ key, deviceTree: dt, ubootEnv: env });
  }
  if (deviceTree.initArgs.join(' ') !== ubootEnv.initArgs.join(' ')) {
    out.push({
      key: '-- (arguments passed to init)',
      deviceTree: deviceTree.initArgs,
      ubootEnv: ubootEnv.initArgs,
    });
  }
  return out;
}

/** The outcome of comparing ONE device tree's command line against ONE of the environment's. */
export interface CmdlineComparison {
  /** Where the tree's line came from, in the same words the finding uses. */
  deviceTreeWhere: string;
  /** Where the U-Boot line came from — the stored variable, or the script chain that assembles it. */
  ubootWhere: string;
  /** Which of the U-Boot side's two possible lines this comparison used. Never inferred by a reader. */
  ubootLine: 'stored' | 'assembled';
  agrees: boolean;
  /** Capped at `DIFF_CAP`, sorted by parameter name. Empty when the two agree. */
  differences: CmdlineDifference[];
  /** How many differing parameters the cap dropped. They exist; they are simply not listed. */
  differencesDropped: number;
  /** True when the two lines answer this module's OWN audit questions differently (root shell / serial console). */
  securityRelevant: boolean;
}

/**
 * Five cases, kept apart on purpose. `agree`/`disagree` are answers; `device-tree-only`, `uboot-env-only`,
 * `neither` and `unresolved-variables` are the question going unasked, and no reader may round any of them to
 * agreement.
 */
export type CmdlineCrossCheckVerdict =
  | 'disagree'
  | 'agree'
  | 'device-tree-only'
  | 'uboot-env-only'
  | 'neither'
  | 'unresolved-variables';

/** Outcome of cross-checking the device tree's command line(s) against the U-Boot side's. */
export interface CmdlineCrossCheck {
  verdict: CmdlineCrossCheckVerdict;
  /** True only when BOTH sources yielded a comparable line. The precondition, stated rather than assumed. */
  comparable: boolean;
  /** One entry per (distinct device-tree line × distinct U-Boot line). Empty whenever `comparable` is false. */
  comparisons: CmdlineComparison[];
  findings: FindingDraft[];
  /** What was compared and what was normalised away — or, when nothing was compared, why not. */
  reason: string;
  /**
   * Which U-Boot line the comparison used: the one a boot script assembles (preferred — it is closer to what the
   * board passes), the one stored in `bootargs`, or neither because nothing was comparable. Stated, never implied.
   */
  comparedUbootLine: 'stored' | 'assembled' | 'none';
  /**
   * True when the environment stores a `bootargs` AND a script assembles a different boot configuration from it.
   * Worth stating on its own: it means quoting the stored variable anywhere else on this image answers a different
   * question from the one this check answered.
   */
  storedAndAssembledDiffer: boolean;
}

/** The audit questions a line answers, as a stable set — used only to decide whether a difference is material. */
function auditKinds(cmdline: string): string[] {
  const kinds = auditKernelCommandLine(cmdline, { where: 'the line under comparison', evidence: {} }).map(
    (d) => d.kind,
  );
  return [...new Set(kinds)].sort();
}

/** Truncate every token of a difference so one absurd parameter value cannot bloat the finding. */
function truncateSide(tokens: string[] | null): string[] | null {
  return tokens === null ? null : tokens.map((t) => truncate(t, 120));
}

const NORMALIZED_NOTE =
  'whitespace, the order of independent parameters, and repeated parameters the kernel resolves last-wins';

/** One side of the comparison: the source as read, and the line that expansion actually produced from it. */
interface ResolvedSide {
  source: CmdlineSource;
  expanded: ExpandedCmdline;
  /** The audit kinds the EXPANDED line answers — `init=${init}` only says "root shell" once `init` is known. */
  kinds: string[];
}

/** Expand a source and audit the EXPANDED line, since that is the line the comparison actually works on. */
function resolveSide(source: CmdlineSource): ResolvedSide {
  const expanded = expandCmdlineVariables(source.value, source.variables, {
    complete: source.variablesComplete === true,
  });
  return { source, expanded, kinds: auditKinds(expanded.value) };
}

/** One U-Boot line the comparison may use, carrying the label every finding has to quote. */
interface EnvCandidate {
  side: ResolvedSide;
  line: 'stored' | 'assembled';
  /** True when the assembled assignment sits under a conditional — reachable, not established. */
  conditional: boolean;
}

/** The `expanded`/`substitutions` half of the evidence, present only when the source really was a template. */
function expansionEvidence(side: ResolvedSide, prefix: 'deviceTree' | 'ubootEnv'): Record<string, unknown> {
  const subs = Object.keys(side.expanded.substitutions);
  if (subs.length === 0) return {};
  return {
    [`${prefix}Expanded`]: truncate(side.expanded.value),
    [`${prefix}Substitutions`]: side.expanded.substitutions,
  };
}

/** The stored `bootargs` as context for a comparison that used the ASSEMBLED line instead. */
interface StoredContext {
  cmdline: string;
  /** True when the stored variable and the compared assembled line are different boot configurations. */
  differs: boolean;
}

function disagreementFinding(input: {
  tree: ResolvedSide;
  env: EnvCandidate;
  comparison: CmdlineComparison;
  treeKinds: string[];
  envKinds: string[];
  stored: StoredContext | null;
  scriptNote?: string;
  scriptAmbiguous?: boolean;
}): FindingDraft {
  const { tree, env, comparison, treeKinds, envKinds, stored } = input;
  const envSource = env.side.source;
  const total = comparison.differences.length + comparison.differencesDropped;
  const material = comparison.securityRelevant;
  const assembled = env.line === 'assembled';
  const materialNote = material
    ? [
        'The difference is material to this audit: the two lines do not answer the root-shell / serial-console',
        `questions the same way (device tree: ${treeKinds.join(', ') || 'neither'};`,
        `U-Boot environment: ${envKinds.join(', ') || 'neither'}), so which source wins changes the answer.`,
      ].join(' ')
    : [
        'None of the differing parameters changes the root-shell / serial-console answer, so the disagreement is',
        'reported as a provenance fact rather than a security one.',
      ].join(' ');
  // Which line was compared leads the rationale, because a reader who cannot tell which of the U-Boot side's two
  // strings produced the diff below cannot check a single row of it.
  const comparedNote = assembled
    ? [
        `Compared against ${envSource.origin.where} — the line a \`bootcmd\`/\`preboot\` script ASSEMBLES, not the`,
        'value stored in the `bootargs` variable. That is a static read of the script text: it shows the assignment',
        'is on the path U-Boot would run, not that this board ran it.',
        env.conditional
          ? 'This assignment sits inside a conditional, so it is one reachable variant and not established as the one.'
          : '',
      ]
        .filter((s) => s !== '')
        .join(' ')
    : `Compared against ${envSource.origin.where} — the line stored in the \`bootargs\` variable.`;
  const storedNote = stored
    ? stored.differs
      ? [
          'The stored `bootargs` and the assembled line are themselves different boot configurations (stored:',
          `\`${truncate(stored.cmdline, 120)}\`), so quoting the stored variable would answer a different question`,
          'from the one answered here.',
        ].join(' ')
      : 'The stored `bootargs` normalises to the same boot configuration as the assembled line, so which one is quoted does not change this result.'
    : '';
  const rationale = [
    comparedNote,
    'The device tree and the U-Boot environment both declare a kernel command line, and after normalising',
    `${NORMALIZED_NOTE} they are not the same line: ${total} parameter(s) differ. static_confirmed claims exactly`,
    'that — two parsed structures in these bytes carry different strings. It does NOT claim the board is',
    'misconfigured, that either line is exploitable, or which line the kernel actually receives: U-Boot normally',
    'writes $bootargs into /chosen/bootargs before handing the tree to the kernel, so the environment is usually',
    'the operative line and the tree records what the build expected — but nothing in these bytes proves this',
    'board takes that path. Read it as: every other command-line finding on this image is conditional on which',
    'source wins, and each one names the origin it was read from.',
    storedNote,
    input.scriptAmbiguous && input.scriptNote ? input.scriptNote : '',
    materialNote,
  ]
    .filter((s) => s !== '')
    .join(' ');

  return {
    kind: 'boot-cmdline-disagreement',
    title: `Device tree and U-Boot environment disagree on the kernel command line (${total} parameter(s))`,
    severity: material ? 'medium' : 'info',
    proofState: 'static_confirmed',
    evidence: {
      deviceTreeCmdline: truncate(tree.source.value),
      ubootEnvCmdline: truncate(envSource.value),
      // The one field a reader needs before any of the rows below mean anything.
      ubootEnvLine: env.line,
      ubootEnvWhere: envSource.origin.where,
      ...(assembled && env.conditional ? { ubootEnvConditional: true } : {}),
      ...(stored
        ? { ubootStoredCmdline: truncate(stored.cmdline), ubootStoredDiffersFromAssembled: stored.differs }
        : {}),
      ...expansionEvidence(tree, 'deviceTree'),
      ...expansionEvidence(env.side, 'ubootEnv'),
      ...(env.side.expanded.unset.length > 0 ? { ubootEnvUnsetVariables: env.side.expanded.unset } : {}),
      deviceTreeSource: tree.source.origin.evidence,
      ubootEnvSource: envSource.origin.evidence,
      differences: comparison.differences.map((d) => ({
        key: d.key,
        deviceTree: truncateSide(d.deviceTree),
        ubootEnv: truncateSide(d.ubootEnv),
      })),
      ...(comparison.differencesDropped > 0
        ? {
            differencesDropped: comparison.differencesDropped,
            differencesRule: [
              `Listing ${DIFF_CAP} of ${total} differing parameter(s), chosen in alphabetical order by parameter`,
              'name — never by position in the command line, so the listed set is not an artefact of how either',
              'line is written. Both full command lines are quoted above.',
            ].join(' '),
          }
        : {}),
      normalized: NORMALIZED_NOTE,
      notNormalized:
        'case, parameter values, the repetition and order of console=/earlycon/earlyprintk/initcall_blacklist, ' +
        'and everything after a standalone `--` (init argv)',
      ...(material ? { securityRelevantDelta: { deviceTree: treeKinds, ubootEnv: envKinds } } : {}),
    },
    rationale,
  };
}

/** The refusal shape, so every "we could not ask" exit is built by the same code and none can drift. */
function refuse(verdict: CmdlineCrossCheckVerdict, reason: string): CmdlineCrossCheck {
  return {
    verdict,
    comparable: false,
    comparisons: [],
    findings: [],
    reason,
    comparedUbootLine: 'none',
    storedAndAssembledDiffer: false,
  };
}

/**
 * Pure: cross-check the kernel command line(s) a device tree declares against the one(s) the U-Boot side declares.
 * Produces a finding ONLY for a real disagreement — a line that survives normalisation unequal. Agreement produces
 * no finding, and neither does an image where only one source (or no source) carried a line: those are the question
 * going unasked, and `verdict` keeps them distinguishable from equality.
 *
 * The U-Boot side has TWO possible answers and they are not equal in standing. `ubootEnv` is the value stored in
 * `bootargs`; `ubootScript` is what a `bootcmd`/`preboot` script assembles, which OVERWRITES that value before the
 * board boots. So an assembled line is preferred whenever one is available, `comparedUbootLine` says which was
 * used, and every finding repeats it — the diff rows are unreadable without knowing which string produced them.
 * When a script assembles a line that cannot be resolved, the check REFUSES rather than falling back to the stored
 * variable: the script overwrites it, so it is known not to be the operative line.
 *
 * A FIT commonly ships one device tree per board variant, so the tree side is a LIST — and a conditional makes the
 * U-Boot side one too. Identical lines collapse on both axes (the same disagreement reported twice is noise), and
 * what remains is compared pairwise: each distinct board variant against each reachable command line. Nothing here
 * picks one variant and calls it the boot.
 *
 * Variable expansion runs FIRST, before presence is even decided: a `bootargs` that is nothing but `${x}`
 * references is a template, and whether it yields a line at all depends on what the store holds.
 */
export function crossCheckBootCmdlines(input: {
  deviceTree: CmdlineSource[];
  ubootEnv: CmdlineSource | null;
  ubootScript?: UbootScriptCmdlines;
}): CmdlineCrossCheck {
  const treeSides = input.deviceTree.map((s) => resolveSide(s));

  // An unresolved reference is not a differing value, and pretending otherwise is exactly how this check would
  // manufacture its first false finding. Stop, and name what could not be resolved.
  const treeUnresolved = [...new Set(treeSides.flatMap((t) => t.expanded.unresolved))].sort();
  if (treeUnresolved.length > 0) return refuse('unresolved-variables', unresolvedReason(treeUnresolved));

  const storedSide = input.ubootEnv ? resolveSide(input.ubootEnv) : null;
  const assembledSides = (input.ubootScript?.assembled ?? []).map((source) => ({
    side: resolveSide(source),
    conditional: source.conditional === true,
  }));

  const usableAssembled: EnvCandidate[] = assembledSides
    .filter((a) => a.side.expanded.unresolved.length === 0 && a.side.expanded.value.trim() !== '')
    .map((a) => ({ side: a.side, line: 'assembled' as const, conditional: a.conditional }));
  const usableStored: EnvCandidate | null =
    storedSide && storedSide.expanded.unresolved.length === 0 && storedSide.expanded.value.trim() !== ''
      ? { side: storedSide, line: 'stored', conditional: false }
      : null;

  // A script that sets `bootargs` and whose line we cannot resolve is the one case where falling back would be
  // actively wrong: the stored variable is overwritten by that very script, so comparing it answers a question
  // about a string the board never passes.
  if (usableAssembled.length === 0 && assembledSides.length > 0) {
    const names = [...new Set(assembledSides.flatMap((a) => a.side.expanded.unresolved))].sort();
    return refuse(
      'unresolved-variables',
      [
        `A \`bootcmd\`/\`preboot\` script assembles the kernel command line, and it could not be resolved${
          names.length ? ` (unresolved: ${names.join(', ')})` : ' (it expands to nothing)'
        }.`,
        'The stored `bootargs` was NOT compared in its place: the script overwrites that variable, so it is known',
        'not to be the line this board passes, and comparing it would answer a different question. That is not',
        'agreement and not a disagreement.',
      ].join(' '),
    );
  }

  const chosen: EnvCandidate[] = usableAssembled.length > 0 ? usableAssembled : usableStored ? [usableStored] : [];
  const comparedUbootLine: 'stored' | 'assembled' | 'none' =
    chosen.length === 0 ? 'none' : (chosen[0] as EnvCandidate).line;

  // Two reachable assignments that normalise to one boot configuration are one answer, not two.
  const envCandidates: { cand: EnvCandidate; norm: NormalizedCmdline }[] = [];
  const envSeen = new Set<string>();
  for (const cand of chosen) {
    const norm = normalizeCommandLine(cand.side.expanded.value);
    if (envSeen.has(norm.canonical)) continue;
    envSeen.add(norm.canonical);
    envCandidates.push({ cand, norm });
  }

  // The stored variable as CONTEXT, only when it was not itself the thing compared. Whether it differs from the
  // assembled line is a fact about this image worth stating even when the tree agrees with everything.
  const storedNorm = usableStored ? normalizeCommandLine(usableStored.side.expanded.value) : null;
  const storedContext: StoredContext | null =
    comparedUbootLine === 'assembled' && usableStored && storedNorm
      ? {
          cmdline: usableStored.side.source.value,
          differs: envCandidates.some((e) => e.norm.canonical !== storedNorm.canonical),
        }
      : null;
  const storedAndAssembledDiffer = storedContext?.differs === true;

  const trees = treeSides.filter((s) => s.expanded.value.trim() !== '');

  if (trees.length === 0 || envCandidates.length === 0) {
    // A stored line that is still a template is the one absence that is really a refusal, so it is checked before
    // the presence verdicts — "we could not expand it" must never be filed as "the environment carried none".
    const storedUnresolved = storedSide?.expanded.unresolved ?? [];
    if (envCandidates.length === 0 && storedUnresolved.length > 0) {
      return refuse('unresolved-variables', unresolvedReason([...storedUnresolved].sort()));
    }
    const verdict: CmdlineCrossCheckVerdict =
      trees.length === 0 && envCandidates.length === 0
        ? 'neither'
        : trees.length === 0
          ? 'uboot-env-only'
          : 'device-tree-only';
    const reason =
      verdict === 'neither'
        ? [
            'Neither the device tree nor the stored U-Boot environment declared a kernel command line, so there',
            'was nothing to cross-check. That is not agreement — the question could not be asked from these bytes.',
          ].join(' ')
        : verdict === 'device-tree-only'
          ? [
              'Only the device tree declared a kernel command line; the stored U-Boot environment carried none, so',
              'no cross-check was possible. That is not agreement — one source cannot corroborate itself, and the',
              'tree still only says what the build expected.',
            ].join(' ')
          : [
              'Only the stored U-Boot environment declared a kernel command line; no device tree in this image',
              'declared one, so no cross-check was possible. That is not agreement — the environment is',
              'uncorroborated, not confirmed.',
            ].join(' ');
    // `comparedUbootLine` stays `none`: nothing was compared, and naming the line that WOULD have been used would
    // read as though it had been. `storedAndAssembledDiffer` is still a fact about these bytes and survives.
    return { ...refuse(verdict, reason), storedAndAssembledDiffer };
  }

  const comparisons: CmdlineComparison[] = [];
  const findings: FindingDraft[] = [];
  const seen = new Set<string>();
  let duplicates = 0;

  for (const tree of trees) {
    const treeNorm = normalizeCommandLine(tree.expanded.value);
    if (seen.has(treeNorm.canonical)) {
      duplicates++;
      continue;
    }
    seen.add(treeNorm.canonical);

    for (const { cand, norm } of envCandidates) {
      const all = diffCommandLines(treeNorm, norm);
      const comparison: CmdlineComparison = {
        deviceTreeWhere: tree.source.origin.where,
        ubootWhere: cand.side.source.origin.where,
        ubootLine: cand.line,
        agrees: all.length === 0,
        differences: all.slice(0, DIFF_CAP),
        differencesDropped: Math.max(0, all.length - DIFF_CAP),
        securityRelevant: tree.kinds.join(' ') !== cand.side.kinds.join(' '),
      };
      comparisons.push(comparison);
      if (!comparison.agrees) {
        findings.push(
          disagreementFinding({
            tree,
            env: cand,
            comparison,
            treeKinds: tree.kinds,
            envKinds: cand.side.kinds,
            stored: storedContext,
            ...(input.ubootScript?.note ? { scriptNote: input.ubootScript.note } : {}),
            ...(input.ubootScript?.ambiguous ? { scriptAmbiguous: true } : {}),
          }),
        );
      }
    }
  }

  const disagreeing = comparisons.filter((c) => !c.agrees).length;
  const distinctNote =
    duplicates > 0
      ? [
          ` ${seen.size} distinct command line(s) across ${trees.length} device tree(s); the rest are`,
          'byte-for-byte repeats.',
        ].join(' ')
      : trees.length > 1
        ? ` All ${trees.length} device tree(s) in this image were compared.`
        : '';
  const lineNote = lineProvenanceNote(comparedUbootLine, envCandidates.length, input.ubootScript);
  const storedNote = storedContext
    ? storedContext.differs
      ? ' The stored `bootargs` is a different boot configuration from the assembled line, so it is not the string this result is about.'
      : ' The stored `bootargs` normalises to the same boot configuration as the assembled line.'
    : '';

  if (disagreeing === 0) {
    return {
      verdict: 'agree',
      comparable: true,
      comparisons,
      findings,
      comparedUbootLine,
      storedAndAssembledDiffer,
      reason: [
        'The device tree and the U-Boot environment declare the same kernel command line once',
        `${NORMALIZED_NOTE} are normalised.${distinctNote}${lineNote}${storedNote}`,
        'Both sources answer the boot question identically; nothing here says which one the board actually uses.',
      ].join(' '),
    };
  }

  return {
    verdict: 'disagree',
    comparable: true,
    comparisons,
    findings,
    comparedUbootLine,
    storedAndAssembledDiffer,
    reason: [
      `${disagreeing} of ${comparisons.length} comparison(s) differ after normalising`,
      `${NORMALIZED_NOTE}.${distinctNote}${lineNote}${storedNote}`,
      'The tree says what the build expects and the environment says what the board would pass; which one the',
      'kernel receives is not decidable from these bytes.',
    ].join(' '),
  };
}

/** The one sentence a refused expansion gets, so `reason` reads the same wherever the refusal came from. */
function unresolvedReason(names: string[]): string {
  return [
    `The command line still references ${names.length} variable(s) that could not be resolved from the source's`,
    `own store (${names.join(', ')}), so it is a template rather than a command line and was not compared. That is`,
    'not agreement and not a disagreement — comparing an unexpanded ${…} against a literal value would report a',
    'difference that is an artefact of not expanding it.',
  ].join(' ');
}

/** Say which of the U-Boot side's lines was used, and what reading it could not settle. Never omitted. */
function lineProvenanceNote(
  line: 'stored' | 'assembled' | 'none',
  candidates: number,
  script?: UbootScriptCmdlines,
): string {
  if (line === 'assembled') {
    const many =
      candidates > 1
        ? ` ${candidates} distinct assembled line(s) are statically reachable and each was compared; which one a powered board takes is not decidable from these bytes.`
        : '';
    return [
      ' The U-Boot side is the command line a `bootcmd`/`preboot` script ASSEMBLES, not the stored `bootargs`',
      `variable — a static read of the script text, not an execution.${many}${script?.note ? ` ${script.note}` : ''}`,
    ].join(' ');
  }
  if (line === 'stored') {
    return script?.note
      ? ` The U-Boot side is the line stored in \`bootargs\`. ${script.note}`
      : ' The U-Boot side is the line stored in `bootargs`; no boot script was read for this image, so nothing here rules out a `bootcmd` re-setting it.';
  }
  return '';
}
