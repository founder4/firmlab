/**
 * Binary-vuln sweep (W5 breadth) — a rootfs-wide hunt for memory-corruption candidates.
 *
 * W9 already re-plans a targeted decompile of each network daemon (opacidad-leads), but the DVRF re-run showed the
 * app surfaces ZERO binary-level pwnables across the rootfs as a whole — the intentionally-vulnerable stack-BOF
 * binaries that are the entire point of that image. Full memory-safety proof needs symbolic execution; this is the
 * cheap, honest first rung: scan every rootfs ELF for imports of unbounded-copy libc functions (`gets`, `strcpy`,
 * `strcat`, `sprintf`, `vsprintf`, `scanf`-family) and for the ABSENCE of a stack canary (`__stack_chk_fail`).
 * A binary that copies unbounded input with no canary is a stack-overflow CANDIDATE — a lead, never a proof, so
 * the finding is `needs_runtime_reproduction` at MEDIUM. Command-exec imports (`system`/`popen`/`exec*`) are a
 * separate INFO cmdi-sink lead. Symbols are read from the ELF's printable `.dynstr` strings (no nm/readelf
 * dependency), so the detector is PURE and unit-tested; the runner only walks the rootfs and reads bounded prefixes.
 *
 * Closes docs/AUTONOMOUS-WORKERS.md §9 gap #4 — the DVRF pwnables the app never surfaced.
 */
import fs from 'node:fs';
import path from 'node:path';
import type { FindingDraft } from '../findings-normalize.js';

/** Unbounded-copy libc functions — a call to one on attacker-influenced input is the classic stack-BOF primitive. */
export const UNSAFE_COPY_FNS = ['gets', 'strcpy', 'strcat', 'sprintf', 'vsprintf', 'scanf', 'sscanf', 'vscanf'];
/** Command-execution sinks — a cmdi primitive when the argument is attacker-influenced. */
export const CMD_EXEC_FNS = ['system', 'popen', 'execl', 'execlp', 'execve', 'execvp', 'doSystem', 'twsystem'];
/** Presence of this symbol means the binary was built WITH stack-protector — its absence is the risk signal. */
const CANARY_SYMBOL = '__stack_chk_fail';

/** Match a symbol name as a standalone token (so a "strcpy" inside a help string is not a false import). */
function importsSymbol(symbols: Set<string>, name: string): boolean {
  return symbols.has(name);
}

/**
 * Pure: extract candidate symbol tokens from an ELF's printable strings. `.dynstr` stores imported symbol names as
 * NUL-separated ASCII, so the C-identifier tokens in the strings are a superset of the imports. Returns a set of
 * bare identifiers (letters/digits/underscore, length 3..40).
 */
export function extractSymbols(strings: string): Set<string> {
  const out = new Set<string>();
  for (const m of strings.matchAll(/[A-Za-z_][A-Za-z0-9_]{2,39}/g)) out.add(m[0]);
  return out;
}

export interface BinAssessment {
  path: string;
  unsafeCopy: string[];
  cmdExec: string[];
  hasCanary: boolean;
}

/** Pure: assess one binary's symbol set for unsafe-copy / cmd-exec imports and stack-canary presence. */
export function assessBinary(binPath: string, symbols: Set<string>): BinAssessment {
  return {
    path: binPath,
    unsafeCopy: UNSAFE_COPY_FNS.filter((f) => importsSymbol(symbols, f)),
    cmdExec: CMD_EXEC_FNS.filter((f) => importsSymbol(symbols, f)),
    hasCanary: importsSymbol(symbols, CANARY_SYMBOL),
  };
}

/**
 * Pure: turn a binary assessment into findings. A binary importing an unbounded-copy function with NO stack canary
 * is a stack-overflow CANDIDATE (MEDIUM / needs_runtime_reproduction — a lead to reverse/fuzz, not a proof). A
 * command-exec import is an INFO cmdi-sink lead. A hardened binary (canary present) with unsafe imports is NOT
 * flagged as a candidate — honest, so the list stays actionable.
 */
export function buildBinFindings(a: BinAssessment): FindingDraft[] {
  const drafts: FindingDraft[] = [];
  if (a.unsafeCopy.length > 0 && !a.hasCanary) {
    drafts.push({
      kind: 'binary-pwnable-candidate',
      title: `Stack-overflow candidate: ${a.path} calls ${a.unsafeCopy.join('/')} with no stack canary`,
      severity: 'medium',
      proofState: 'needs_runtime_reproduction',
      evidence: { path: a.path, unsafeFns: a.unsafeCopy, canary: false },
      rationale:
        'The binary imports unbounded-copy libc function(s) and was built without a stack canary — the classic ' +
        'stack-buffer-overflow precondition. Whether an attacker reaches one with oversized input needs reversing/' +
        'fuzzing, so this is a candidate lead, not a proven overflow.',
    });
  }
  if (a.cmdExec.length > 0) {
    drafts.push({
      kind: 'binary-cmdexec-sink',
      title: `Command-exec sink: ${a.path} imports ${a.cmdExec.join('/')}`,
      severity: 'info',
      proofState: 'needs_runtime_reproduction',
      evidence: { path: a.path, execFns: a.cmdExec },
      rationale:
        'The binary imports a command-execution function — a command-injection sink if any argument is ' +
        'attacker-influenced. A lead to taint the callers, not a verdict.',
    });
  }
  return drafts;
}

export interface BinVulnResult {
  available: boolean;
  binariesScanned: number;
  candidates: number;
  findings: FindingDraft[];
  reason: string;
}

const WALK_CAP = 12000;
const ELF_SCAN_CAP = 400; // cap ELF binaries examined (a busy rootfs has hundreds)
const FINDING_CAP = 60; // cap emitted candidates so a big rootfs cannot flood the findings list
const BIN_READ_CAP = 4 * 1024 * 1024;

/** Extract printable ASCII runs (>= 3 chars) from a binary buffer as one string, bounded. */
function binaryStrings(buf: Uint8Array): string {
  const out: string[] = [];
  let cur = '';
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i] as number;
    if (b >= 0x20 && b <= 0x7e) cur += String.fromCharCode(b);
    else {
      if (cur.length >= 3) out.push(cur);
      cur = '';
    }
  }
  if (cur.length >= 3) out.push(cur);
  return out.join('\n');
}

/** Read a bounded prefix of a file (missing/unreadable → empty). */
function readBounded(abs: string): Uint8Array {
  try {
    const fd = fs.openSync(abs, 'r');
    try {
      const size = Math.min(fs.fstatSync(fd).size, BIN_READ_CAP);
      const b = Buffer.allocUnsafe(size);
      fs.readSync(fd, b, 0, size, 0);
      return b;
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return new Uint8Array(0);
  }
}

/** Is this file an ELF (magic 0x7F 'E' 'L' 'F')? Reads only the first 4 bytes. */
function isElf(abs: string): boolean {
  try {
    const fd = fs.openSync(abs, 'r');
    try {
      const b = Buffer.allocUnsafe(4);
      fs.readSync(fd, b, 0, 4, 0);
      return b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46;
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return false;
  }
}

/**
 * Sweep an extracted rootfs for memory-corruption candidates. Walks for ELF binaries, extracts each one's symbol
 * tokens from its strings, and applies the pure assessor. Honest: no rootfs → available:false; hardened binaries
 * are not flagged; the candidate list is capped and the overflow is reported in the reason, never silently dropped.
 */
export function runBinVuln(rootfsPath: string | null): BinVulnResult {
  if (!rootfsPath) {
    return { available: false, binariesScanned: 0, candidates: 0, findings: [], reason: 'No extracted rootfs.' };
  }
  const root = path.resolve(rootfsPath);
  try {
    if (!fs.statSync(root).isDirectory()) throw new Error('not a dir');
  } catch {
    return { available: false, binariesScanned: 0, candidates: 0, findings: [], reason: 'No extracted rootfs.' };
  }

  const findings: FindingDraft[] = [];
  let scanned = 0;
  let walked = 0;
  let overflow = 0;
  const stack: string[] = [root];
  while (stack.length > 0 && walked < WALK_CAP && scanned < ELF_SCAN_CAP) {
    const dir = stack.pop() as string;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (walked >= WALK_CAP || scanned >= ELF_SCAN_CAP) break;
      walked++;
      if (e.isSymbolicLink()) continue;
      const abs = path.join(dir, e.name);
      if (e.isDirectory()) {
        stack.push(abs);
        continue;
      }
      if (!e.isFile() || !isElf(abs)) continue;
      scanned++;
      const rel = path.relative(root, abs);
      const assessment = assessBinary(rel, extractSymbols(binaryStrings(readBounded(abs))));
      for (const f of buildBinFindings(assessment)) {
        if (findings.length < FINDING_CAP) findings.push(f);
        else overflow++;
      }
    }
  }

  const candidates = findings.filter((f) => f.kind === 'binary-pwnable-candidate').length;
  const overflowNote = overflow > 0 ? ` (${overflow} further finding(s) beyond the ${FINDING_CAP} cap not listed)` : '';
  return {
    available: true,
    binariesScanned: scanned,
    candidates,
    findings,
    reason: `Binary-vuln sweep: ${scanned} ELF binaries, ${candidates} stack-overflow candidate(s)${overflowNote}. Candidates are unbounded-copy + no-canary leads for reversing/fuzzing, not proven overflows.`,
  };
}
