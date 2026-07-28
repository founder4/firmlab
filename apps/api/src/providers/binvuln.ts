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
 *
 * This is the FALLBACK, not the primary path: a superset is not an import list. `parseDynamicSymbols` below reads
 * the real symbol table and is tried first.
 */
export function extractSymbols(strings: string): Set<string> {
  const out = new Set<string>();
  for (const m of strings.matchAll(/[A-Za-z_][A-Za-z0-9_]{2,39}/g)) out.add(m[0]);
  return out;
}

/** Where a binary's symbol set came from — it decides what the finding is entitled to claim. */
export type SymbolSource = 'dynsym' | 'strings';

/** A little-endian/big-endian aware reader over the ELF bytes. */
function reader(buf: Uint8Array, little: boolean) {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  return {
    u16: (o: number) => dv.getUint16(o, little),
    u32: (o: number) => dv.getUint32(o, little),
    u64: (o: number) => Number(dv.getBigUint64(o, little)),
  };
}

// Program-header and dynamic-array constants for the segment fallback below.
const PT_LOAD = 1;
const PT_DYNAMIC = 2;
const DT_NULL = 0;
const DT_HASH = 4;
const DT_STRTAB = 5;
const DT_SYMTAB = 6;
const DT_STRSZ = 10;
const DT_SYMENT = 11;
/** A sane ceiling on a dynamic symbol table, so a corrupt DT_HASH cannot make the reader loop for minutes. */
const MAX_DYNSYMS = 200000;

/**
 * Pure: read an ELF's dynamic symbols through the PT_DYNAMIC **segment** rather than the section headers.
 *
 * Section headers are optional at run time — the loader never reads them — so a build that strips them still runs.
 * OpenWrt does exactly that, and the whole GL.iNet BE3600 rootfs arrives with `e_shoff == 0` and `e_shnum == 0`:
 * the section-header walk above returns null for every single binary on the corpus's richest image, and callers
 * silently drop to the string superset. That is honest but much weaker — and on `usr/bin/usign` the difference is
 * between "mentions edsign_verify" and "the loader must resolve edsign_verify", which is the whole question the
 * update-path provider asks.
 *
 * The dynamic linker's own route survives stripping: PT_DYNAMIC gives DT_SYMTAB / DT_STRTAB / DT_STRSZ as VIRTUAL
 * addresses, which the PT_LOAD segments map back to file offsets. The entry count comes from DT_HASH's `nchain`
 * (the hash chain has exactly one slot per symbol); when only DT_GNU_HASH is present we fall back to the standard
 * layout where `.dynstr` immediately follows `.dynsym`. Anything that does not add up returns null, so a caller
 * still degrades to the string scan rather than reading garbage as an import list.
 */
function parseDynamicSymbolsFromSegments(buf: Uint8Array, is64: boolean, little: boolean): Set<string> | null {
  const r = reader(buf, little);
  const phoff = is64 ? r.u64(0x20) : r.u32(0x1c);
  const phentsize = r.u16(is64 ? 0x36 : 0x2a);
  const phnum = r.u16(is64 ? 0x38 : 0x2c);
  if (!phoff || !phentsize || !phnum) return null;
  if (phoff + phnum * phentsize > buf.length) return null;

  const loads: Array<{ vaddr: number; offset: number; filesz: number }> = [];
  let dynOff = 0;
  let dynSize = 0;
  for (let i = 0; i < phnum; i++) {
    const ph = phoff + i * phentsize;
    const type = r.u32(ph);
    const p_offset = is64 ? r.u64(ph + 0x08) : r.u32(ph + 0x04);
    const p_vaddr = is64 ? r.u64(ph + 0x10) : r.u32(ph + 0x08);
    const p_filesz = is64 ? r.u64(ph + 0x20) : r.u32(ph + 0x10);
    if (type === PT_LOAD) loads.push({ vaddr: p_vaddr, offset: p_offset, filesz: p_filesz });
    else if (type === PT_DYNAMIC) {
      dynOff = p_offset;
      dynSize = p_filesz;
    }
  }
  if (!dynOff || !dynSize || dynOff + dynSize > buf.length) return null;

  /** Map a virtual address back to a file offset through the PT_LOAD segments; null when nothing covers it. */
  const toOffset = (vaddr: number): number | null => {
    for (const l of loads) {
      if (vaddr >= l.vaddr && vaddr < l.vaddr + l.filesz) return l.offset + (vaddr - l.vaddr);
    }
    return null;
  };

  const step = is64 ? 16 : 8;
  const tags = new Map<number, number>();
  for (let o = dynOff; o + step <= dynOff + dynSize; o += step) {
    const tag = is64 ? r.u64(o) : r.u32(o);
    const val = is64 ? r.u64(o + 8) : r.u32(o + 4);
    if (tag === DT_NULL) break;
    if (!tags.has(tag)) tags.set(tag, val);
  }

  const symVa = tags.get(DT_SYMTAB);
  const strVa = tags.get(DT_STRTAB);
  const strSize = tags.get(DT_STRSZ);
  const symEntSize = tags.get(DT_SYMENT) ?? (is64 ? 24 : 16);
  if (symVa === undefined || strVa === undefined || !strSize || !symEntSize) return null;

  const symOff = toOffset(symVa);
  const strOff = toOffset(strVa);
  if (symOff === null || strOff === null) return null;
  if (strOff + strSize > buf.length) return null;

  // DT_HASH's second word is nchain — one chain slot per dynamic symbol, so it IS the count. Without it, rely on
  // the conventional adjacency of .dynsym and .dynstr rather than guessing.
  let count = 0;
  const hashVa = tags.get(DT_HASH);
  const hashOff = hashVa === undefined ? null : toOffset(hashVa);
  if (hashOff !== null && hashOff + 8 <= buf.length) count = r.u32(hashOff + 4);
  else if (strOff > symOff) count = Math.floor((strOff - symOff) / symEntSize);
  if (count <= 0 || count > MAX_DYNSYMS) return null;
  if (symOff + count * symEntSize > buf.length) return null;

  const names = new Set<string>();
  for (let i = 0; i < count; i++) {
    const nameOff = r.u32(symOff + i * symEntSize); // st_name is the first u32 in both widths
    if (nameOff === 0 || nameOff >= strSize) continue;
    let end = strOff + nameOff;
    while (end < strOff + strSize && buf[end] !== 0) end++;
    const name = Buffer.from(buf.subarray(strOff + nameOff, end)).toString('latin1');
    if (name) names.add(name.split('@')[0] as string);
  }
  return names.size > 0 ? names : null;
}

/**
 * Pure: read an ELF's DYNAMIC SYMBOL table and return the names it actually references.
 *
 * The string-token heuristic above cannot tell an import from a help string, a format specifier or a mention in a
 * usage banner — it flagged `sbin/chkntfs` as importing `system` when angr could resolve no PLT or symbol entry at
 * all. This walks the section headers to `.dynsym` + `.dynstr` and reads the names out of the symbol entries, so
 * "imports" means the loader really does have to resolve it. When the section headers were stripped (they are
 * optional at run time, and OpenWrt strips them) it falls through to the PT_DYNAMIC segment, which the loader
 * itself uses and which therefore survives — see `parseDynamicSymbolsFromSegments`.
 *
 * Returns null when the file is not an ELF, is truncated, or has no dynamic symbol table by either route (a fully
 * static binary legitimately has none) — the caller then falls back to the string scan and SAYS it did, rather
 * than silently reporting a weaker fact under a stronger word. No `readelf` dependency: this module stays pure and
 * unit-tested.
 */
export function parseDynamicSymbols(buf: Uint8Array): Set<string> | null {
  if (buf.length < 64) return null;
  if (!(buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46)) return null;
  const is64 = buf[4] === 2;
  const little = buf[5] === 1;
  if (buf[4] !== 1 && buf[4] !== 2) return null;
  if (buf[5] !== 1 && buf[5] !== 2) return null;

  const fromSegments = (): Set<string> | null => {
    try {
      return parseDynamicSymbolsFromSegments(buf, is64, little);
    } catch {
      return null;
    }
  };

  try {
    const r = reader(buf, little);
    // e_shoff / e_shentsize / e_shnum / e_shstrndx differ in offset and width between ELF32 and ELF64.
    const shoff = is64 ? r.u64(0x28) : r.u32(0x20);
    const shentsize = r.u16(is64 ? 0x3a : 0x2e);
    const shnum = r.u16(is64 ? 0x3c : 0x30);
    // No section headers at all — the stripped case the segment reader exists for.
    if (!shoff || !shentsize || !shnum) return fromSegments();
    if (shoff + shnum * shentsize > buf.length) return fromSegments();

    // Locate .dynsym (sh_type SHT_DYNSYM = 11) and take its linked string table (sh_link).
    const SHT_DYNSYM = 11;
    let symOff = 0;
    let symSize = 0;
    let symEntSize = 0;
    let strIdx = -1;
    for (let i = 0; i < shnum; i++) {
      const sh = shoff + i * shentsize;
      const type = r.u32(sh + 4);
      if (type !== SHT_DYNSYM) continue;
      symOff = is64 ? r.u64(sh + 0x18) : r.u32(sh + 0x10);
      symSize = is64 ? r.u64(sh + 0x20) : r.u32(sh + 0x14);
      symEntSize = is64 ? r.u64(sh + 0x38) : r.u32(sh + 0x24);
      // sh_link sits at a DIFFERENT offset in the two widths (0x18 in ELF32, 0x28 in ELF64) — and ELF32 is the
      // overwhelmingly common case in firmware (mips/arm), so getting this wrong would have broken the majority.
      strIdx = r.u32(sh + (is64 ? 0x28 : 0x18));
      break;
    }
    if (!symOff || !symSize || !symEntSize || strIdx < 0 || strIdx >= shnum) return fromSegments();

    const strSh = shoff + strIdx * shentsize;
    const strOff = is64 ? r.u64(strSh + 0x18) : r.u32(strSh + 0x10);
    const strSize = is64 ? r.u64(strSh + 0x20) : r.u32(strSh + 0x14);
    if (!strOff || strOff + strSize > buf.length) return fromSegments();
    if (symOff + symSize > buf.length) return fromSegments();

    const names = new Set<string>();
    const count = Math.floor(symSize / symEntSize);
    for (let i = 0; i < count; i++) {
      const nameOff = r.u32(symOff + i * symEntSize); // st_name is the first u32 in both widths
      if (nameOff === 0 || nameOff >= strSize) continue;
      let end = strOff + nameOff;
      while (end < strOff + strSize && buf[end] !== 0) end++;
      const name = Buffer.from(buf.subarray(strOff + nameOff, end)).toString('latin1');
      // Versioned imports arrive as `memcpy@GLIBC_2.14`; the base name is the symbol being resolved.
      if (name) names.add(name.split('@')[0] as string);
    }
    return names.size > 0 ? names : fromSegments();
  } catch {
    return fromSegments();
  }
}

const ET_EXEC = 2;
const ET_DYN = 3;
const PT_INTERP = 3;

/**
 * Pure: is this ELF a program you can RUN, as opposed to a shared library?
 *
 * Both are ELFs and both can import `strcpy` without a canary, so both are legitimate entries in the ledger. But
 * the two questions downstream — "is this sink reachable from the entry point" and "run it and see whether it
 * faults" — are ill-posed for a library: it has no entry point to reach from, and qemu cannot execute it. Asking
 * anyway spends a probe that structurally cannot answer.
 *
 * That is not hypothetical. Ranking candidates by ascending size (so the prober gets the binaries it can settle)
 * promoted DVRF's iptables plugins straight to the front: 15 of the 30 listed candidates are `usr/lib/iptables/*.so`
 * at ~6 KB each, just above the three executables that took the budget. On a rootfs with slightly smaller plugins
 * the entire allowance would have gone to libraries.
 *
 * ET_EXEC is a program. ET_DYN is ambiguous — a PIE executable and a library share it — and what separates them is
 * that a PIE names an interpreter to load it, so PT_INTERP is the discriminator rather than the filename.
 */
export function isRunnableElf(buf: Uint8Array): boolean {
  if (buf.length < 64) return false;
  if (!(buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46)) return false;
  const is64 = buf[4] === 2;
  const little = buf[5] === 1;
  if (buf[4] !== 1 && buf[4] !== 2) return false;
  if (buf[5] !== 1 && buf[5] !== 2) return false;
  try {
    const r = reader(buf, little);
    const type = r.u16(0x10);
    if (type === ET_EXEC) return true;
    if (type !== ET_DYN) return false;
    const phoff = is64 ? r.u64(0x20) : r.u32(0x1c);
    const phentsize = r.u16(is64 ? 0x36 : 0x2a);
    const phnum = r.u16(is64 ? 0x38 : 0x2c);
    if (!phoff || !phentsize || !phnum) return false;
    if (phoff + phnum * phentsize > buf.length) return false;
    for (let i = 0; i < phnum; i++) {
      if (r.u32(phoff + i * phentsize) === PT_INTERP) return true;
    }
    return false;
  } catch {
    return false;
  }
}

export interface BinAssessment {
  path: string;
  /**
   * Size of the file on disk in bytes (0 when it could not be read, and 0 from the pure symbol-only assessor,
   * which never touches a file). Carried because it RANKS a candidate: bounded symbolic execution converges on
   * small binaries and reliably times out on large ones, so size decides which leads are worth the probe budget.
   */
  size: number;
  /**
   * Can this ELF be executed (a program), or is it a shared library? A library is a real candidate for the ledger
   * and a dead end for the probe budget — see `isRunnableElf`. True from the symbol-only assessor, which has no
   * file to inspect: unknown must not silently disqualify a binary.
   */
  runnable: boolean;
  unsafeCopy: string[];
  cmdExec: string[];
  hasCanary: boolean;
  /** `dynsym` = read from the real symbol table; `strings` = the token superset, so a MENTION, not an import. */
  symbolSource: SymbolSource;
}

/** Pure: assess one binary's symbol set for unsafe-copy / cmd-exec imports and stack-canary presence. */
export function assessBinary(
  binPath: string,
  symbols: Set<string>,
  symbolSource: SymbolSource = 'strings',
): BinAssessment {
  return {
    path: binPath,
    size: 0, // a symbol set carries no file facts; assessBinaryFile fills these from the bytes it already read.
    runnable: true,
    unsafeCopy: UNSAFE_COPY_FNS.filter((f) => importsSymbol(symbols, f)),
    cmdExec: CMD_EXEC_FNS.filter((f) => importsSymbol(symbols, f)),
    hasCanary: importsSymbol(symbols, CANARY_SYMBOL),
    symbolSource,
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
  // The verb has to match the evidence. A dynamic-symbol entry means the loader really must resolve the name, so
  // "imports" is earned; a token lifted out of the binary's strings is a MENTION, and calling that an import
  // promises more than the bytes carry (`sbin/chkntfs` "importing" system, where angr found no PLT entry at all).
  const fromDynsym = a.symbolSource === 'dynsym';
  const verb = fromDynsym ? 'imports' : 'references';
  const provenance = fromDynsym
    ? 'Read from the ELF dynamic symbol table, so the loader does resolve these names.'
    : 'This binary has no readable dynamic symbol table, so the names were read from its printable strings — a MENTION of the symbol, not proof that it is imported. Treat the lead as weaker accordingly.';

  if (a.unsafeCopy.length > 0 && !a.hasCanary) {
    drafts.push({
      kind: 'binary-pwnable-candidate',
      title: `Stack-overflow candidate: ${a.path} ${verb} ${a.unsafeCopy.join('/')} with no stack canary`,
      severity: 'medium',
      proofState: 'needs_runtime_reproduction',
      evidence: {
        path: a.path,
        size: a.size,
        runnable: a.runnable,
        unsafeFns: a.unsafeCopy,
        canary: false,
        symbolSource: a.symbolSource,
      },
      rationale: `The binary ${verb} unbounded-copy libc function(s) and was built without a stack canary — the classic stack-buffer-overflow precondition. ${provenance} Whether an attacker reaches one with oversized input needs reversing/fuzzing, so this is a candidate lead, not a proven overflow.`,
    });
  }
  if (a.cmdExec.length > 0) {
    drafts.push({
      kind: 'binary-cmdexec-sink',
      title: `Command-exec sink: ${a.path} ${verb} ${a.cmdExec.join('/')}`,
      severity: 'info',
      proofState: 'needs_runtime_reproduction',
      evidence: { path: a.path, size: a.size, execFns: a.cmdExec, symbolSource: a.symbolSource },
      rationale: `The binary ${verb} a command-execution function — a command-injection sink if any argument is attacker-influenced. ${provenance} A lead to taint the callers, not a verdict.`,
    });
  }
  return drafts;
}

export interface BinVulnResult {
  available: boolean;
  binariesScanned: number;
  /**
   * Stack-overflow candidates FOUND — not necessarily listed. `findings` holds what survived FINDING_CAP, so on a
   * busy rootfs this is the larger number; the difference is stated in `reason` rather than left to be inferred.
   */
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

/**
 * Read a bounded prefix of a file, reporting its TRUE size alongside (missing/unreadable → empty, size 0). The
 * size is the whole file's, not the prefix's — a 40 MB binary and a 4 MB one both read `BIN_READ_CAP` bytes, and
 * ranking them as equal would defeat the point of ranking.
 */
function readBounded(abs: string): { bytes: Uint8Array; size: number } {
  try {
    const fd = fs.openSync(abs, 'r');
    try {
      const size = fs.fstatSync(fd).size;
      const b = Buffer.allocUnsafe(Math.min(size, BIN_READ_CAP));
      fs.readSync(fd, b, 0, b.length, 0);
      return { bytes: b, size };
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return { bytes: new Uint8Array(0), size: 0 };
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
 * Assess ONE already-located binary — the sweep's per-file step, exposed for callers that already know their
 * target and only need its symbol facts (the symbolic prober deriving which sinks are worth asking about, and the
 * W4 lead resolver checking that a handler's exec target is a real ELF). `abs` is the absolute path on disk, `rel`
 * the rootfs-relative path that names it in findings. A file that cannot be read yields an empty assessment, so
 * the caller sees "no sinks", never a crash.
 */
export function assessBinaryFile(abs: string, rel: string): BinAssessment {
  const { bytes, size } = readBounded(abs);
  // Real symbol table first; the string superset only when there is none to read (a truly static binary, or a
  // prefix that stopped short of the section headers). The assessment records which, so the finding can say so.
  const dyn = parseDynamicSymbols(bytes);
  const assessed = dyn
    ? assessBinary(rel, dyn, 'dynsym')
    : assessBinary(rel, extractSymbols(binaryStrings(bytes)), 'strings');
  return { ...assessed, size, runnable: isRunnableElf(bytes) };
}

/** Is this file an ELF? Exposed so a caller can reject a shell script before treating it as a binary target. */
export function isElfFile(abs: string): boolean {
  return isElf(abs);
}

/** Read the file size a draft carries; a draft without one sorts last rather than first. */
function draftSize(d: FindingDraft): number {
  const s = (d.evidence as Record<string, unknown> | undefined)?.size;
  return typeof s === 'number' ? s : Number.MAX_SAFE_INTEGER;
}

/** Read the rootfs-relative path a draft carries — the deterministic tiebreak between equal-sized binaries. */
function draftPath(d: FindingDraft): string {
  const p = (d.evidence as Record<string, unknown> | undefined)?.path;
  return typeof p === 'string' ? p : '';
}

/**
 * Pure: choose which findings survive `FINDING_CAP`.
 *
 * The cap has to exist — a busy rootfs yields hundreds of leads and a flooded ledger is unreadable. But WHICH ones
 * it keeps must not be an accident of directory order, and it was. The walk is a LIFO stack, so it descended
 * `usr/` first, filled the cap there, and every directory reached later overflowed. On the real DVRF corpus that
 * silently excluded `bin/`, `sbin/` and the entire `pwnable/` tree — including `pwnable/Intro/stack_bof_01`, the
 * one binary this workbench has ever reproduced a crash in. The list read as "43 candidates" and was in fact the
 * prefix of a reverse-alphabetical walk. Nothing in it was false; it was the *set* that was an artifact.
 *
 * So the selection is explicit and stated. Round-robin across kinds, so a high-volume kind cannot crowd out
 * another (43 pwnable candidates evicted every command-exec sink found after them). Within a kind, SMALLEST
 * FIRST: bounded symbolic execution converges on small binaries and reliably times out on large ones, so the
 * small candidates are the ones the downstream prober can actually settle — and a lead nobody can settle is worth
 * less shelf space than one somebody can. Ties break on path, so the same rootfs yields the same list on any
 * filesystem, which walk order never guaranteed.
 */
export function selectFindings(drafts: FindingDraft[], cap: number): { kept: FindingDraft[]; dropped: number } {
  if (cap <= 0) return { kept: [], dropped: drafts.length };
  const byKind = new Map<string, FindingDraft[]>();
  for (const d of drafts) {
    const list = byKind.get(d.kind);
    if (list) list.push(d);
    else byKind.set(d.kind, [d]);
  }
  const order = (a: FindingDraft, b: FindingDraft): number =>
    draftSize(a) - draftSize(b) || draftPath(a).localeCompare(draftPath(b));
  const kinds = [...byKind.keys()].sort();
  for (const k of kinds) (byKind.get(k) as FindingDraft[]).sort(order);

  const kept: FindingDraft[] = [];
  let progress = true;
  while (kept.length < cap && progress) {
    progress = false;
    for (const k of kinds) {
      if (kept.length >= cap) break;
      const next = (byKind.get(k) as FindingDraft[]).shift();
      if (next) {
        kept.push(next);
        progress = true;
      }
    }
  }
  // Round-robin interleaves the kinds; regroup so the emitted list reads as a list rather than as the draw order.
  kept.sort((a, b) => a.kind.localeCompare(b.kind) || order(a, b));
  return { kept, dropped: drafts.length - kept.length };
}

/**
 * Sweep an extracted rootfs for memory-corruption candidates. Walks for ELF binaries, extracts each one's symbol
 * tokens from its strings, and applies the pure assessor. Honest: no rootfs → available:false; hardened binaries
 * are not flagged; the candidate list is capped by `selectFindings` (smallest-first, not walk order) and both the
 * cap and an exhausted ELF budget are reported in the reason, never silently dropped.
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

  // Every draft the walk produces, capped only at the END. Bounded by ELF_SCAN_CAP binaries × 2 kinds, so this
  // cannot grow large — and collecting first is what lets the cap choose on merit instead of on arrival order.
  const all: FindingDraft[] = [];
  let scanned = 0;
  let walked = 0;
  const stack: string[] = [root];
  while (stack.length > 0 && walked < WALK_CAP && scanned < ELF_SCAN_CAP) {
    const dir = stack.pop() as string;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    // readdir order is filesystem-defined, so an unsorted walk makes WHICH binaries fit under ELF_SCAN_CAP differ
    // between machines for the same image. Sort, and push directories in reverse so the LIFO stack pops them in
    // alphabetical order — the sweep is a reproducible fact about the rootfs, not about the disk that holds it.
    entries.sort((a, b) => a.name.localeCompare(b.name));
    const subdirs: string[] = [];
    for (const e of entries) {
      if (walked >= WALK_CAP || scanned >= ELF_SCAN_CAP) break;
      walked++;
      if (e.isSymbolicLink()) continue;
      const abs = path.join(dir, e.name);
      if (e.isDirectory()) {
        subdirs.push(abs);
        continue;
      }
      if (!e.isFile() || !isElf(abs)) continue;
      scanned++;
      const rel = path.relative(root, abs);
      all.push(...buildBinFindings(assessBinaryFile(abs, rel)));
    }
    for (let i = subdirs.length - 1; i >= 0; i--) stack.push(subdirs[i] as string);
  }

  const { kept, dropped } = selectFindings(all, FINDING_CAP);
  const candidates = all.filter((f) => f.kind === 'binary-pwnable-candidate').length;
  const listed = kept.filter((f) => f.kind === 'binary-pwnable-candidate').length;
  // Both bounds are stated, because either one silently makes a partial answer look like a complete one.
  const capNote =
    dropped > 0
      ? ` The ${FINDING_CAP}-finding cap lists the ${listed} smallest candidate(s) and drops ${dropped} further finding(s) — selected by binary size (what a bounded symbolic probe can settle), not by directory order.`
      : '';
  const budgetNote =
    scanned >= ELF_SCAN_CAP
      ? ` The ${ELF_SCAN_CAP}-binary examination budget was exhausted, so ELFs beyond it were never opened and are absent from these counts, not cleared by them.`
      : '';
  return {
    available: true,
    binariesScanned: scanned,
    candidates,
    findings: kept,
    reason: `Binary-vuln sweep: ${scanned} ELF binaries, ${candidates} stack-overflow candidate(s).${capNote}${budgetNote} Candidates are unbounded-copy + no-canary leads for reversing/fuzzing, not proven overflows.`,
  };
}
