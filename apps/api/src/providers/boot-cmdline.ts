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
}

/**
 * Pure: resolve `${x}` / `$(x)` / `$x` in a command line from the source's own variable store. With no store the
 * line is returned verbatim and nothing is ever reported unresolved — a literal `$` in a device-tree string is a
 * `$`, not a reference. Bounded at `MAX_EXPANSION_PASSES`; anything still referencing after that (a self- or
 * mutually-recursive variable) is reported unresolved rather than expanded further.
 */
export function expandCmdlineVariables(line: string, variables?: Record<string, string>): ExpandedCmdline {
  if (!variables) return { value: line, substitutions: {}, unresolved: [] };

  const substitutions: Record<string, string> = {};
  const unresolved = new Set<string>();
  let value = line;
  for (let pass = 0; pass < MAX_EXPANSION_PASSES; pass++) {
    let changed = false;
    value = value.replace(VAR_REF_RE, (match, braced?: string, parens?: string, bare?: string) => {
      const name = braced ?? parens ?? bare;
      if (name === undefined) return match;
      const resolved = variables[name];
      if (resolved === undefined) {
        unresolved.add(name);
        return match;
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
  return { value, substitutions, unresolved: [...unresolved].sort() };
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

/** The outcome of comparing ONE device tree's command line against the environment's. */
export interface CmdlineComparison {
  /** Where the tree's line came from, in the same words the finding uses. */
  deviceTreeWhere: string;
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

/** Outcome of cross-checking the device tree's command line(s) against the stored U-Boot environment's. */
export interface CmdlineCrossCheck {
  verdict: CmdlineCrossCheckVerdict;
  /** True only when BOTH sources yielded a comparable line. The precondition, stated rather than assumed. */
  comparable: boolean;
  /** One entry per DISTINCT device-tree command line. Empty whenever `comparable` is false. */
  comparisons: CmdlineComparison[];
  findings: FindingDraft[];
  /** What was compared and what was normalised away — or, when nothing was compared, why not. */
  reason: string;
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
  const expanded = expandCmdlineVariables(source.value, source.variables);
  return { source, expanded, kinds: auditKinds(expanded.value) };
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

function disagreementFinding(
  tree: ResolvedSide,
  env: ResolvedSide,
  comparison: CmdlineComparison,
  treeKinds: string[],
  envKinds: string[],
): FindingDraft {
  const total = comparison.differences.length + comparison.differencesDropped;
  const material = comparison.securityRelevant;
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
  const rationale = [
    'The device tree and the stored U-Boot environment both declare a kernel command line, and after normalising',
    `${NORMALIZED_NOTE} they are not the same line: ${total} parameter(s) differ. static_confirmed claims exactly`,
    'that — two parsed structures in these bytes carry different strings. It does NOT claim the board is',
    'misconfigured, that either line is exploitable, or which line the kernel actually receives: U-Boot normally',
    'writes $bootargs into /chosen/bootargs before handing the tree to the kernel, so the environment is usually',
    'the operative line and the tree records what the build expected — but nothing in these bytes proves this',
    'board takes that path, and nothing proves the stored value is even the line U-Boot passes: a `bootcmd` script',
    'is free to `setenv bootargs` again before it boots. Read it as: every other command-line finding on this',
    'image is conditional on which source wins, and each one names the origin it was read from.',
    materialNote,
  ].join(' ');

  return {
    kind: 'boot-cmdline-disagreement',
    title: `Device tree and U-Boot environment disagree on the kernel command line (${total} parameter(s))`,
    severity: material ? 'medium' : 'info',
    proofState: 'static_confirmed',
    evidence: {
      deviceTreeCmdline: truncate(tree.source.value),
      ubootEnvCmdline: truncate(env.source.value),
      ...expansionEvidence(tree, 'deviceTree'),
      ...expansionEvidence(env, 'ubootEnv'),
      deviceTreeSource: tree.source.origin.evidence,
      ubootEnvSource: env.source.origin.evidence,
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

/**
 * Pure: cross-check the kernel command line(s) a device tree declares against the one the stored U-Boot
 * environment declares. Produces a finding ONLY for a real disagreement — a line that survives normalisation
 * unequal. Agreement produces no finding, and neither does an image where only one source (or no source) carried
 * a line: those are the question going unasked, and `verdict` keeps them distinguishable from equality.
 *
 * A FIT commonly ships one device tree per board variant, so the tree side is a LIST. Identical lines collapse to
 * one comparison (the same disagreement reported twice is noise); genuinely different ones each get their own,
 * because each is a different board variant disagreeing with the same environment. The list is already bounded by
 * the device-tree provider's blob cap, so nothing is truncated here.
 *
 * Variable expansion runs FIRST, before presence is even decided: a `bootargs` that is nothing but `${x}`
 * references is a template, and whether it yields a line at all depends on what the store holds.
 */
export function crossCheckBootCmdlines(input: {
  deviceTree: CmdlineSource[];
  ubootEnv: CmdlineSource | null;
}): CmdlineCrossCheck {
  const treeSides = input.deviceTree.map((s) => resolveSide(s));
  const envSide = input.ubootEnv ? resolveSide(input.ubootEnv) : null;

  // An unresolved reference is not a differing value, and pretending otherwise is exactly how this check would
  // manufacture its first false finding. Stop, and name what could not be resolved.
  const unresolved = [
    ...new Set([...(envSide?.expanded.unresolved ?? []), ...treeSides.flatMap((t) => t.expanded.unresolved)]),
  ].sort();
  if (unresolved.length > 0) {
    return {
      verdict: 'unresolved-variables',
      comparable: false,
      comparisons: [],
      findings: [],
      reason: [
        `The command line still references ${unresolved.length} variable(s) that could not be resolved from the`,
        `source's own store (${unresolved.join(', ')}), so it is a template rather than a command line and was`,
        'not compared. That is not agreement and not a disagreement — comparing an unexpanded ${…} against a',
        'literal value would report a difference that is an artefact of not expanding it.',
      ].join(' '),
    };
  }

  const trees = treeSides.filter((s) => s.expanded.value.trim() !== '');
  const env = envSide && envSide.expanded.value.trim() !== '' ? envSide : null;

  if (trees.length === 0 || env === null) {
    const verdict: CmdlineCrossCheckVerdict =
      trees.length === 0 && env === null ? 'neither' : trees.length === 0 ? 'uboot-env-only' : 'device-tree-only';
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
    return { verdict, comparable: false, comparisons: [], findings: [], reason };
  }

  const envNorm = normalizeCommandLine(env.expanded.value);

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

    const all = diffCommandLines(treeNorm, envNorm);
    const comparison: CmdlineComparison = {
      deviceTreeWhere: tree.source.origin.where,
      agrees: all.length === 0,
      differences: all.slice(0, DIFF_CAP),
      differencesDropped: Math.max(0, all.length - DIFF_CAP),
      securityRelevant: tree.kinds.join(' ') !== env.kinds.join(' '),
    };
    comparisons.push(comparison);
    if (!comparison.agrees) findings.push(disagreementFinding(tree, env, comparison, tree.kinds, env.kinds));
  }

  const disagreeing = comparisons.filter((c) => !c.agrees).length;
  const distinctNote =
    duplicates > 0
      ? [
          ` ${comparisons.length} distinct command line(s) across ${trees.length} device tree(s); the rest are`,
          'byte-for-byte repeats.',
        ].join(' ')
      : trees.length > 1
        ? ` All ${trees.length} device tree(s) in this image were compared.`
        : '';

  if (disagreeing === 0) {
    return {
      verdict: 'agree',
      comparable: true,
      comparisons,
      findings,
      reason: [
        'The device tree and the stored U-Boot environment declare the same kernel command line once',
        `${NORMALIZED_NOTE} are normalised.${distinctNote}`,
        'Both sources answer the boot question identically; nothing here says which one the board actually uses.',
      ].join(' '),
    };
  }

  return {
    verdict: 'disagree',
    comparable: true,
    comparisons,
    findings,
    reason: [
      `${disagreeing} of ${comparisons.length} device-tree command line(s) differ from the stored U-Boot`,
      `environment's after normalising ${NORMALIZED_NOTE}.${distinctNote}`,
      'The tree says what the build expects and the environment says what the board would pass; which one the',
      'kernel receives is not decidable from these bytes.',
    ].join(' '),
  };
}
