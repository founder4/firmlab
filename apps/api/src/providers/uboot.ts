/**
 * U-Boot provider — the bootloader-analysis track. A `bootloader` image (a raw flash dump, a `u-boot.bin`, or a
 * whole firmware image that carries the U-Boot environment partition) has no rootfs to run and no MCU to emulate,
 * so its analysis is offline structural parsing: locate the U-Boot environment block in the REAL bytes, decode the
 * `key=value` variables, and reason about the boot posture (root-shell boot args, an interruptible autoboot, a
 * network boot path, an exposed serial console) strictly from what the variables actually contain.
 *
 * Everything here is PURE + unit-tested (the env decoder, the block locator, the audit) except the thin runner,
 * which only reads a bounded prefix of the image and composes the pure parts. It is HONEST: no env block found
 * degrades to found:false with an explicit reason; it never fabricates a boot configuration, and every finding
 * quotes the offending variable. Proof states top out at `static_confirmed` (a fact about the stored env bytes,
 * never a device claim) — a boot-args root shell or a netboot path is `needs_runtime_reproduction` because it is a
 * lead that only a real boot confirms.
 */
import fs from 'node:fs';
import type { FindingDraft } from '../findings-normalize.js';
import { auditKernelCommandLine, truncate } from './boot-cmdline.js';

/** The decoded U-Boot environment: the stored CRC, the `key=value` variables, and how many were parsed. */
export interface ParsedEnv {
  crc: number;
  vars: Record<string, string>;
  entryCount: number;
  /**
   * NUL-separated entries the decoder REFUSED (no `=`, a non-identifier key, a non-printable value). Non-zero
   * means the map below is not everything the block held, which is the difference between "this board has no
   * such variable" and "we could not read it" — see `varsComplete`.
   */
  malformedEntries: number;
}

/** Outcome of a U-Boot analysis run over one image. Honest: `found:false` when no env block is present. */
export interface UbootResult {
  available: boolean;
  found: boolean;
  varCount: number;
  vars: Record<string, string>;
  findings: FindingDraft[];
  reason: string;
  /**
   * True when `vars` is the WHOLE store: the surfaced-variable cap dropped nothing and every entry in the block
   * decoded. Only then may a `${x}` naming a variable that is not here be read as U-Boot's own rule — an unset
   * variable expands to nothing — instead of as our own blind spot. Optional forever: a result stored by an older
   * build does not carry it, and absent must keep meaning "cannot claim completeness".
   */
  varsComplete?: boolean;
  /** What a static read of `bootcmd`/`preboot` found — the command line a script ASSEMBLES. Optional forever. */
  bootScript?: BootScriptReading;
}

// A key is a C-identifier-ish token; a value is any run of printable ASCII (spaces and '=' allowed). A chunk that
// carries a CRC/flags header byte or firmware padding fails these, which is exactly how a wrong start offset loses.
const KEY_RE = /^[A-Za-z_][A-Za-z0-9_.\-]*$/;
const PRINTABLE_RE = /^[\x20-\x7e]*$/;

/** Read `[start,end)` of a byte buffer as an ASCII string (one char per byte; non-ASCII bytes survive for the RE). */
function sliceAscii(buf: Uint8Array, start: number, end: number): string {
  let s = '';
  for (let i = start; i < end; i++) s += String.fromCharCode(buf[i] as number);
  return s;
}

/**
 * Parse NUL-separated `key=value` entries starting at `start`, until a double-NUL (empty entry) or the buffer end.
 * Only well-formed entries (identifier key + printable value) are kept; the first occurrence of a key wins. The
 * refused entries are COUNTED rather than discarded silently: at the winning offset that count is what says
 * whether the returned map is the whole environment.
 */
function parseEntries(buf: Uint8Array, start: number): { vars: Record<string, string>; malformed: number } {
  const vars: Record<string, string> = {};
  let malformed = 0;
  const n = buf.length;
  let i = start;
  while (i < n) {
    let j = i;
    while (j < n && (buf[j] as number) !== 0) j++;
    if (j === i) break; // empty entry → the terminating double-NUL (or a leading NUL)
    const entry = sliceAscii(buf, i, j);
    const eq = entry.indexOf('=');
    if (eq > 0) {
      const key = entry.slice(0, eq);
      const value = entry.slice(eq + 1);
      if (KEY_RE.test(key) && PRINTABLE_RE.test(value)) {
        if (!(key in vars)) vars[key] = value;
      } else {
        malformed++;
      }
    } else {
      malformed++;
    }
    i = j + 1;
  }
  return { vars, malformed };
}

/**
 * Pure: decode a U-Boot environment blob. Layout is `<4-byte little-endian CRC32><entries>`, where `<entries>` is
 * NUL-separated `key=value` up to a double-NUL. Redundant-env stores insert ONE flags byte after the CRC, so the
 * entry data begins at offset 4 (plain) or 5 (redundant); a header-less ASCII block begins at offset 0. We try all
 * three and keep whichever yields the most valid entries. Offset 0 is tried first so a clean header-less parse wins
 * ties over a coincidental mid-key offset, while a real binary CRC/flags header makes the earlier offsets lose.
 */
export function parseUbootEnv(buf: Uint8Array): ParsedEnv {
  const crc =
    buf.length >= 4
      ? ((buf[0] as number) | ((buf[1] as number) << 8) | ((buf[2] as number) << 16) | ((buf[3] as number) << 24)) >>> 0
      : 0;
  let best: Record<string, string> = {};
  let bestMalformed = 0;
  for (const start of [0, 4, 5]) {
    if (start > buf.length) continue;
    const { vars, malformed } = parseEntries(buf, start);
    if (Object.keys(vars).length > Object.keys(best).length) {
      best = vars;
      bestMalformed = malformed;
    }
  }
  return { crc, vars: best, entryCount: Object.keys(best).length, malformedEntries: bestMalformed };
}

/** Case-sensitive byte search for an ASCII needle. */
function indexOfAscii(buf: Uint8Array, needle: string, from = 0): number {
  const n = needle.length;
  outer: for (let i = from; i + n <= buf.length; i++) {
    for (let k = 0; k < n; k++) {
      if ((buf[i + k] as number) !== needle.charCodeAt(k)) continue outer;
    }
    return i;
  }
  return -1;
}

/** The earliest offset of a distinctive U-Boot env marker (`bootcmd=` / `bootargs=`), or -1. */
function findMarker(buf: Uint8Array): number {
  const a = indexOfAscii(buf, 'bootcmd=');
  const b = indexOfAscii(buf, 'bootargs=');
  if (a < 0) return b;
  if (b < 0) return a;
  return Math.min(a, b);
}

const SCAN_WINDOW = 64 * 1024;

/**
 * Pure: locate a plausible U-Boot environment inside a raw firmware image. Anchors on a `bootcmd=`/`bootargs=`
 * marker, then walks backward to the block start (a preceding double-NUL, a binary byte such as the CRC header, or
 * a bounded window edge) and forward to the terminating double-NUL. When the block is abutted by a binary header
 * (the backward scan stopped on a non-printable byte) the returned slice includes 4 header bytes so parseUbootEnv's
 * offset-4 path lands on the entries; otherwise the header-less ASCII region is returned (offset-0 path). Returns
 * null when no marker is present. parseUbootEnv works on either shape.
 */
export function findEnvBlock(image: Uint8Array): Uint8Array | null {
  const marker = findMarker(image);
  if (marker < 0) return null;
  const lo = Math.max(0, marker - SCAN_WINDOW);
  const hi = Math.min(image.length, marker + SCAN_WINDOW);

  // Backward: extend to the first printable byte of the contiguous ASCII env region.
  let asciiStart = marker;
  let stoppedOnBinary = false;
  let zeroRun = 0;
  for (let p = marker - 1; p >= lo; p--) {
    const b = image[p] as number;
    if (b >= 0x20 && b <= 0x7e) {
      asciiStart = p;
      zeroRun = 0;
    } else if (b === 0) {
      zeroRun++;
      if (zeroRun >= 2) break; // a previous block's terminating double-NUL — the boundary
    } else {
      stoppedOnBinary = true; // a CRC/flags header byte or firmware padding
      break;
    }
  }

  // Forward: extend to (and include) the terminating double-NUL.
  let end = hi;
  zeroRun = 0;
  for (let p = marker; p < hi; p++) {
    const b = image[p] as number;
    if (b === 0) {
      zeroRun++;
      if (zeroRun >= 2) {
        end = p + 1;
        break;
      }
    } else {
      zeroRun = 0;
    }
  }

  if (stoppedOnBinary && asciiStart - 4 >= 0) return image.slice(asciiStart - 4, end);
  return image.slice(asciiStart, end);
}

// === The command line a boot script ASSEMBLES ================================================================
//
// `bootargs` is a stored variable, and a `bootcmd` is free to overwrite it before it boots. The Tenda camera in
// this corpus does exactly that — `bootcmd=run boot_normal`, and `boot_normal` performs
// `env set bootargs … ${mtdparts}${mtdparts1} ${mem} ${memsize}` — so on that board the stored variable is not the
// line the kernel receives, and anything that audits or cross-checks it is auditing the wrong string.
//
// What follows READS SCRIPT TEXT. It is not an execution and must never be presented as one: a `bootcmd` may run
// several assignments under an `if`, and which one a board takes depends on state these bytes do not contain. So
// every distinct assignment reachable from `preboot`/`bootcmd` is reported as a VARIANT, the ones sitting under a
// conditional are marked, and a `run` the walk could not follow is named rather than assumed to set nothing. The
// walk is bounded (`MAX_SCRIPT_VARS`) and cycle-safe (a variable is entered once), because a `bootcmd` that runs
// itself is a two-line environment away and must terminate rather than recurse.

/** One `setenv bootargs …` a statically-reachable boot script performs, before any variable expansion. */
export interface AssembledCmdline {
  /** The right-hand side as written — still a template of `${…}` references, exactly as the env stores it. */
  value: string;
  /** The `run` chain that reaches it (`bootcmd`, `boot_normal`, …), so a reader can re-walk the script by hand. */
  via: string[];
  /** The whole statement as parsed, so the finding quotes what was read and not only what was concluded. */
  statement: string;
  /** True when the assignment sits inside an `if`/`while`/`for` block: a static read cannot say this one runs. */
  conditional: boolean;
}

/** A `run` target the walk did not enter, and the reason — never silently dropped. */
export interface UnfollowedRun {
  name: string;
  /** `undefined` = no such variable · `cycle` = already entered on this walk · `cap` = the visit bound was hit. */
  why: 'undefined' | 'cycle' | 'cap';
}

/** What a static read of the boot script established, and — just as load-bearing — what it could not. */
export interface BootScriptReading {
  /** Whether `preboot`/`bootcmd` existed at all. False means there is no script, not that the script sets nothing. */
  present: boolean;
  /** The root variables the walk started from, in the order U-Boot runs them. */
  roots: string[];
  /** Distinct `setenv bootargs` assignments reachable from the roots, in discovery order. */
  variants: AssembledCmdline[];
  /** `run` targets the walk did not enter. A non-`cycle` entry means a variant may exist that this read never saw. */
  unfollowed: UnfollowedRun[];
  /** True when the variant cap dropped assignments — they exist, they are simply not listed. */
  variantsCapped: boolean;
  /** True when the read cannot say WHICH line boots: several variants, a conditional, or an unfollowed `run`. */
  ambiguous: boolean;
  /** One sentence stating what was read and what it refuses to claim. Quoted verbatim by the cross-check. */
  reason: string;
}

/** U-Boot runs `preboot` before `bootcmd`; both may re-set `bootargs`, so both are walked. */
const SCRIPT_ROOTS = ['preboot', 'bootcmd'] as const;
/** How many variables one walk may enter. A boot script deeper than this is not a boot script. */
const MAX_SCRIPT_VARS = 32;
/** How many distinct assembled lines are reported. A bound is not an answer — hitting it is stated. */
const MAX_VARIANTS = 8;

/** `setenv NAME rest` / `env set NAME rest`, with U-Boot's `-f` force flag tolerated. */
const SETENV_RE = /^(?:setenv|env\s+set)\s+(?:-f\s+)?(\S+)\s*([\s\S]*)$/;

/**
 * Split a hush script into commands on `;`, `&&`, `||` and newlines, honouring the backslash escape U-Boot itself
 * requires for a literal `;` inside a `setenv` value — otherwise a quoted separator would silently cut a command
 * line in half and the assembled string would be short by whatever followed it.
 */
function splitCommands(script: string): string[] {
  const out: string[] = [];
  let current = '';
  for (let i = 0; i < script.length; i++) {
    const ch = script[i] as string;
    if (ch === '\\' && i + 1 < script.length) {
      current += ch + (script[i + 1] as string);
      i++;
      continue;
    }
    if (ch === ';' || ch === '\n') {
      out.push(current);
      current = '';
      continue;
    }
    if ((ch === '&' || ch === '|') && script[i + 1] === ch) {
      out.push(current);
      current = '';
      i++;
      continue;
    }
    current += ch;
  }
  out.push(current);
  return out.map((s) => s.trim()).filter((s) => s !== '');
}

/**
 * Strip the hush control keywords a command can be prefixed with, tracking how deep in a conditional it sits.
 * `depth` is carried across the commands of ONE variable's text, which is where an `if … fi` lives.
 */
function stripControl(command: string, depth: { value: number }): string {
  let rest = command;
  for (;;) {
    const m = /^(\S+)\s*([\s\S]*)$/.exec(rest);
    if (!m) return '';
    const head = m[1] as string;
    if (head === 'if' || head === 'while' || head === 'for') {
      depth.value++;
      rest = m[2] as string;
    } else if (head === 'elif' || head === 'then' || head === 'else' || head === 'do') {
      rest = m[2] as string;
    } else if (head === 'fi' || head === 'done') {
      depth.value = Math.max(0, depth.value - 1);
      rest = m[2] as string;
    } else {
      return rest;
    }
  }
}

/** Drop one matching pair of surrounding quotes — `setenv bootargs "a b"` stores `a b`. */
function unquote(s: string): string {
  if (s.length >= 2 && ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'")))) {
    return s.slice(1, -1);
  }
  return s;
}

interface WalkState {
  vars: Record<string, string>;
  visited: Set<string>;
  variants: AssembledCmdline[];
  seenValues: Set<string>;
  unfollowed: UnfollowedRun[];
  variantsCapped: boolean;
}

/** Resolve a `run` target that is itself written as a reference (`run ${next}`); a bare name passes through. */
function runTargetName(token: string, vars: Record<string, string>): string | null {
  if (!token.includes('$')) return token;
  const m = /^\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|\(([A-Za-z_][A-Za-z0-9_]*)\)|([A-Za-z_][A-Za-z0-9_]*))$/.exec(token);
  const name = m?.[1] ?? m?.[2] ?? m?.[3];
  if (name === undefined) return null;
  const resolved = vars[name];
  return resolved === undefined ? null : resolved.trim();
}

/** Enter one script variable, recording its `setenv bootargs` assignments and following its `run` targets. */
function followScript(state: WalkState, name: string, via: string[], conditional: boolean): void {
  if (state.visited.has(name)) {
    state.unfollowed.push({ name, why: 'cycle' });
    return;
  }
  if (state.visited.size >= MAX_SCRIPT_VARS) {
    state.unfollowed.push({ name, why: 'cap' });
    return;
  }
  const script = state.vars[name];
  if (script === undefined) {
    state.unfollowed.push({ name, why: 'undefined' });
    return;
  }
  state.visited.add(name);
  const chain = [...via, name];
  const depth = { value: 0 };

  for (const raw of splitCommands(script)) {
    const command = stripControl(raw, depth);
    if (command === '') continue;
    const inConditional = conditional || depth.value > 0;

    const assignment = SETENV_RE.exec(command);
    if (assignment) {
      if (assignment[1] !== 'bootargs') continue;
      // `setenv bootargs` with no value DELETES the variable. That is a real boot configuration (an empty command
      // line) but not a line to compare, so it is not reported as a variant.
      const value = unquote((assignment[2] ?? '').trim());
      if (value === '' || state.seenValues.has(value)) continue;
      if (state.variants.length >= MAX_VARIANTS) {
        state.variantsCapped = true;
        continue;
      }
      state.seenValues.add(value);
      state.variants.push({ value, via: chain, statement: command, conditional: inConditional });
      continue;
    }

    const tokens = command.split(/\s+/);
    if (tokens[0] !== 'run') continue;
    for (const token of tokens.slice(1)) {
      const target = runTargetName(token, state.vars);
      if (target === null || target === '') {
        state.unfollowed.push({ name: token, why: 'undefined' });
        continue;
      }
      followScript(state, target, chain, inConditional);
    }
  }
}

/**
 * Pure: read `preboot`/`bootcmd` as script text and report every kernel command line they assemble.
 *
 * The result is deliberately a LIST plus an `ambiguous` flag rather than a single answer. Two assignments under an
 * `if` are both reachable, and nothing in a flash dump says which branch a powered board takes; picking one and
 * calling it "the" command line would be the workbench asserting a runtime fact it cannot observe. An empty
 * `variants` is likewise not "the script leaves `bootargs` alone" unless `unfollowed` is clean — a `run` into a
 * variable this environment does not carry could set anything.
 */
export function readBootScript(vars: Record<string, string>): BootScriptReading {
  const roots = SCRIPT_ROOTS.filter((r) => (vars[r] ?? '').trim() !== '');
  const state: WalkState = {
    vars,
    visited: new Set<string>(),
    variants: [],
    seenValues: new Set<string>(),
    unfollowed: [],
    variantsCapped: false,
  };
  for (const root of roots) followScript(state, root, [], false);

  const gaps = state.unfollowed.filter((u) => u.why !== 'cycle');
  const incomplete = gaps.length > 0 || state.variantsCapped;
  const conditional = state.variants.some((v) => v.conditional);
  const ambiguous = state.variants.length > 1 || conditional || incomplete;

  const gapNote = gaps.length
    ? ` ${gaps.length} \`run\` target(s) could not be followed (${gaps.map((g) => `${g.name}: ${g.why}`).join(', ')}), so an assignment this read never saw may exist.`
    : '';
  const capNote = state.variantsCapped
    ? ` More than ${MAX_VARIANTS} distinct assignments were reachable; the first ${MAX_VARIANTS} in walk order are listed and the rest are dropped by that bound, not absent.`
    : '';
  const cycleNote = state.unfollowed.some((u) => u.why === 'cycle')
    ? ' A `run` re-entered a variable already on this walk; the walk stopped there rather than looping, and no text was missed.'
    : '';

  let reason: string;
  if (roots.length === 0) {
    reason = [
      'This environment declares no `bootcmd` or `preboot`, so there is no boot script to read and nothing here',
      'overrides the stored `bootargs`.',
    ].join(' ');
  } else if (state.variants.length === 0) {
    reason = [
      `A static read of ${roots.join(' and ')} (${state.visited.size} variable(s) followed) found no`,
      `\`setenv bootargs\`, so nothing in the script re-sets the stored command line.${gapNote}${cycleNote}`,
    ].join(' ');
  } else if (state.variants.length === 1 && !conditional && !incomplete) {
    const only = state.variants[0] as AssembledCmdline;
    reason = [
      `The boot script assembles the kernel command line: \`${only.via.join(' → ')}\` performs \`${only.statement}\`.`,
      'This is a STATIC read of the script text — it shows the assignment is on the path U-Boot would run, not',
      `that this board ran it, and not that no other state changes the line first.${cycleNote}`,
    ].join(' ');
  } else {
    reason = [
      `A static read of ${roots.join(' and ')} found ${state.variants.length} distinct \`setenv bootargs\``,
      `assignment(s)${conditional ? ', at least one of them inside a conditional' : ''}. Which one a powered`,
      'board takes is not decidable from these bytes, so every one of them is reported and none is presented as',
      `the boot.${gapNote}${capNote}${cycleNote}`,
    ].join(' ');
  }

  return {
    present: roots.length > 0,
    roots: [...roots],
    variants: state.variants,
    unfollowed: state.unfollowed,
    variantsCapped: state.variantsCapped,
    ambiguous,
    reason,
  };
}

const NETBOOT_RE = /\b(tftp|dhcp|nfs|bootp)/i;

/**
 * Pure: turn a decoded env into honest boot-posture findings. Every finding quotes the offending variable and only
 * asserts what the variables actually show:
 *   - boot args drop to a root shell (`init=/bin/sh`, `rdinit=`, ` single`) → high / needs_runtime_reproduction.
 *   - an interruptible autoboot (`bootdelay` present, not 0/-1)             → medium / static_confirmed.
 *   - a network boot path in `bootcmd`/`preboot` (tftp/dhcp/nfs/bootp)      → medium / needs_runtime_reproduction.
 *   - an exposed serial console on the kernel command line (`console=`)     → info / static_confirmed.
 *
 * The two `bootargs`-derived findings come from `boot-cmdline.ts` because the device tree's `/chosen` node carries
 * the same string and must produce the same finding codes; `bootdelay` and `bootcmd` stay here because they are
 * genuinely U-Boot-only facts with no device-tree equivalent.
 *
 * The command line a `bootcmd` script ASSEMBLES is audited too, because a board whose stored `bootargs` is benign
 * and whose `boot_normal` writes `init=/bin/sh` would otherwise be invisible. It contributes only finding KINDS the
 * stored line did not already yield: the code is the class of fact ("this image's kernel command line drops to a
 * root shell"), one image asserting it twice under two provenances would split the ledger into two rows for one
 * fact. The consequence, stated rather than hidden: a variant that answers the SAME question differently (a second
 * `console=`) is not surfaced here — the cross-check is where two lines are compared parameter by parameter.
 */
export function auditBootEnv(vars: Record<string, string>, script?: BootScriptReading): FindingDraft[] {
  const drafts: FindingDraft[] = [];
  const bootargs = vars.bootargs;
  const bootdelay = vars.bootdelay;

  if (bootargs) {
    drafts.push(
      ...auditKernelCommandLine(bootargs, {
        where: 'the stored U-Boot environment',
        evidence: { var: 'bootargs' },
      }),
    );
  }

  const storedKinds = new Set(drafts.map((d) => d.kind));
  for (const variant of (script ?? readBootScript(vars)).variants) {
    const assembled = auditKernelCommandLine(variant.value, {
      where: `the kernel command line \`${variant.via.join(' → ')}\` assembles`,
      evidence: {
        via: variant.via,
        statement: truncate(variant.statement),
        ...(variant.conditional ? { conditional: true } : {}),
      },
    });
    for (const draft of assembled) {
      if (storedKinds.has(draft.kind)) continue;
      storedKinds.add(draft.kind);
      drafts.push({
        ...draft,
        rationale: [
          draft.rationale ?? '',
          `The line is not the stored \`bootargs\` variable but the one \`${variant.via.join(' → ')}\` builds before`,
          'booting — read statically from the script text, which shows the assignment is on the path U-Boot would',
          `run, not that this board ran it.${variant.conditional ? ' It sits inside a conditional, so a static read cannot say this variant is the one that runs.' : ''}`,
        ]
          .join(' ')
          .trim(),
      });
    }
  }

  if (bootdelay !== undefined && bootdelay.trim() !== '' && bootdelay.trim() !== '0' && bootdelay.trim() !== '-1') {
    drafts.push({
      kind: 'uboot-autoboot-interruptible',
      title: `Autoboot is interruptible to a U-Boot console (bootdelay=${truncate(bootdelay.trim(), 16)})`,
      severity: 'medium',
      proofState: 'static_confirmed',
      evidence: { var: 'bootdelay', value: truncate(bootdelay) },
      rationale:
        'A positive bootdelay lets anyone with serial access press a key during the countdown to drop to the ' +
        'U-Boot prompt and rewrite the boot flow. The value is literally present in the env bytes.',
    });
  }

  for (const name of ['bootcmd', 'preboot'] as const) {
    const val = vars[name];
    if (!val) continue;
    const m = NETBOOT_RE.exec(val);
    if (!m) continue;
    drafts.push({
      kind: 'uboot-netboot',
      title: `U-Boot ${name} uses a network boot path (${m[1]})`,
      severity: 'medium',
      proofState: 'needs_runtime_reproduction',
      evidence: { var: name, value: truncate(val), scheme: m[1] },
      rationale:
        'The device fetches boot code over the network at power-on; an attacker on the LAN can answer with a ' +
        'rogue DHCP/TFTP/NFS server and supply their own image. A LAN-position lead — needs_runtime_reproduction.',
    });
  }

  return drafts;
}

const READ_CAP = 32 * 1024 * 1024;
const VAR_CAP = 60;

/** Read at most `cap` bytes from the head of a file. */
function readBounded(p: string, cap: number): Uint8Array {
  const fd = fs.openSync(p, 'r');
  try {
    const len = Math.min(fs.fstatSync(fd).size, cap);
    const buf = Buffer.allocUnsafe(len);
    fs.readSync(fd, buf, 0, len, 0);
    return buf;
  } finally {
    fs.closeSync(fd);
  }
}

/** Cap the surfaced variable map, keeping the boot-relevant keys first so the audit inputs are never dropped. */
function capVars(vars: Record<string, string>, cap: number): Record<string, string> {
  const keys = Object.keys(vars);
  if (keys.length <= cap) return vars;
  const chosen = new Set<string>();
  for (const k of ['bootargs', 'bootcmd', 'preboot', 'bootdelay', 'baudrate', 'ipaddr', 'serverip']) {
    if (k in vars) chosen.add(k);
  }
  for (const k of keys) {
    if (chosen.size >= cap) break;
    chosen.add(k);
  }
  const out: Record<string, string> = {};
  for (const k of chosen) out[k] = vars[k] as string;
  return out;
}

function notFound(reason: string): UbootResult {
  return { available: true, found: false, varCount: 0, vars: {}, findings: [], reason };
}

/**
 * Analyze the U-Boot environment stored in a firmware image — offline and honest. Reads a bounded prefix, locates
 * the env block, decodes it, and audits the boot posture. No env block or no parseable variables → found:false with
 * an explicit reason; a successful decode is `static_confirmed` (a fact about the stored env, not device behavior).
 */
export function runUbootAnalysis(imagePath: string): UbootResult {
  let buf: Uint8Array;
  try {
    buf = readBounded(imagePath, READ_CAP);
  } catch {
    return notFound('The image could not be read.');
  }
  const block = findEnvBlock(buf);
  if (!block) return notFound('No U-Boot environment found in the image.');
  const { vars, entryCount, malformedEntries } = parseUbootEnv(block);
  if (entryCount === 0) return notFound('No U-Boot environment found in the image.');
  const varCount = Object.keys(vars).length;
  const script = readBootScript(vars);
  // Completeness is a claim about what we may infer from a variable's ABSENCE, so it is only made when both ways
  // of losing one are ruled out: the surfaced-variable cap dropped nothing, and every entry in the block decoded.
  const varsComplete = varCount <= VAR_CAP && malformedEntries === 0;
  const assembledNote = script.variants.length
    ? ` A \`bootcmd\`/\`preboot\` script re-sets bootargs: ${script.reason}`
    : '';
  return {
    available: true,
    found: true,
    varCount,
    vars: capVars(vars, VAR_CAP),
    findings: auditBootEnv(vars, script),
    varsComplete,
    bootScript: script,
    reason: `Parsed ${varCount} U-Boot environment variable${varCount === 1 ? '' : 's'} from the image. Static analysis of the stored env bytes — proves the boot configuration, not device behavior.${assembledNote}`,
  };
}
