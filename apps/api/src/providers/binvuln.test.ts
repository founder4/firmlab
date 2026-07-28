import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import type { FindingDraft } from '../findings-normalize.js';
import {
  assessBinary,
  buildBinFindings,
  extractSymbols,
  isRunnableElf,
  parseDynamicSymbols,
  runBinVuln,
  selectFindings,
} from './binvuln.js';

describe('symbol extraction + assessment', () => {
  it('extracts C-identifier tokens from strings', () => {
    const syms = extractSymbols('gets\x00strcpy\x00__stack_chk_fail\x00hi\x00some help text with strcpy word');
    expect(syms.has('gets')).toBe(true);
    expect(syms.has('strcpy')).toBe(true);
    expect(syms.has('__stack_chk_fail')).toBe(true);
    expect(syms.has('hi')).toBe(false); // < 3 chars
  });

  it('flags an unsafe binary with no canary as a stack-overflow candidate', () => {
    const a = assessBinary('bin/vuln', new Set(['gets', 'strcpy', 'printf', 'main']));
    expect(a.unsafeCopy).toEqual(['gets', 'strcpy']);
    expect(a.hasCanary).toBe(false);
    const drafts = buildBinFindings(a);
    const cand = drafts.find((d) => d.kind === 'binary-pwnable-candidate');
    expect(cand?.severity).toBe('medium');
    expect(cand?.proofState).toBe('needs_runtime_reproduction');
    expect(cand?.title).toContain('gets/strcpy');
  });

  it('does NOT flag a hardened binary (canary present) as a candidate', () => {
    const a = assessBinary('bin/safe', new Set(['strcpy', '__stack_chk_fail', 'main']));
    expect(a.hasCanary).toBe(true);
    expect(buildBinFindings(a).some((d) => d.kind === 'binary-pwnable-candidate')).toBe(false);
  });

  it('emits a command-exec sink lead for system/popen imports', () => {
    const a = assessBinary('bin/cgi', new Set(['system', 'popen', '__stack_chk_fail']));
    const sink = buildBinFindings(a).find((d) => d.kind === 'binary-cmdexec-sink');
    expect(sink?.severity).toBe('info');
    expect(sink?.evidence).toMatchObject({ execFns: ['system', 'popen'] });
  });

  it('flags nothing for a clean binary', () => {
    expect(buildBinFindings(assessBinary('bin/clean', new Set(['printf', 'malloc', 'main'])))).toHaveLength(0);
  });
});

describe('runBinVuln (rootfs sweep)', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'binvuln-'));
  afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }));

  /** An ELF-magic file whose strings carry `syms`, padded to a chosen size so the ranking has something to rank. */
  const fakeElf = (syms: string[], pad: number): Buffer =>
    Buffer.concat([
      Buffer.from([0x7f, 0x45, 0x4c, 0x46]),
      Buffer.from(`\x00${syms.join('\x00')}\x00`, 'latin1'),
      Buffer.alloc(pad, 0x20),
    ]);

  it('degrades honestly with no rootfs', () => {
    expect(runBinVuln(null).available).toBe(false);
  });

  /**
   * A relocatable object is outside this sweep's question, and the corpus proved it the expensive way.
   *
   * On the deployed GL.iNet BE3600 carve, 14 of the sweep's 22 findings were `lib/modules/5.4.213/*.ko` reported
   * as "Command-exec sink: … references system" — 64% of that image's findings asserting a userland call a kernel
   * module cannot make. `isRunnableElf` did not catch it, because that predicate answers "can a probe run this",
   * which is also false for a `.so` that IS worth listing. The axis is the object type.
   */
  const elfOfType = (type: number, syms: string[]): Buffer => {
    const b = Buffer.alloc(64 + syms.join('\u0000').length + 2, 0);
    b.set([0x7f, 0x45, 0x4c, 0x46, 1, 1], 0); // ELF32, little-endian
    b.writeUInt16LE(type, 0x10);
    b.write(`\u0000${syms.join('\u0000')}\u0000`, 64, 'latin1');
    return b;
  };

  it('passes over a .ko instead of claiming it is a userland command-exec sink', () => {
    const root = path.join(tmp, 'ko-rootfs');
    fs.mkdirSync(path.join(root, 'lib', 'modules'), { recursive: true });
    fs.mkdirSync(path.join(root, 'sbin'), { recursive: true });
    // ET_REL: a kernel module whose strings carry the very tokens the sweep hunts for.
    fs.writeFileSync(path.join(root, 'lib/modules/ath_pktlog.ko'), elfOfType(1, ['system', 'strcpy', 'sprintf']));
    // ET_EXEC beside it: the real target, which must still be found.
    fs.writeFileSync(path.join(root, 'sbin/httpd'), elfOfType(2, ['system', 'strcpy']));

    const r = runBinVuln(root);
    expect(r.binariesScanned).toBe(1); // the .ko is not counted as examined — it was never asked anything
    expect(r.relocatableSkipped).toBe(1);
    expect(r.findings.every((f) => !JSON.stringify(f.evidence).includes('.ko'))).toBe(true);
    expect(r.findings.some((f) => (f.evidence as Record<string, unknown>).path === 'sbin/httpd')).toBe(true);
    // The exclusion is a stated rule, not a silent gap.
    expect(r.reason).toMatch(/relocatable object\(s\)/);
  });

  it('still lists a shared library, which is a different case from a relocatable object', () => {
    const root = path.join(tmp, 'so-rootfs', 'lib');
    fs.mkdirSync(root, { recursive: true });
    // ET_DYN with no PT_INTERP: not runnable, but a genuine candidate this sweep should keep reporting.
    fs.writeFileSync(path.join(root, 'libfstools.so'), elfOfType(3, ['system', 'strcpy']));

    const r = runBinVuln(path.join(tmp, 'so-rootfs'));
    expect(r.binariesScanned).toBe(1);
    expect(r.relocatableSkipped).toBe(0);
    expect(r.findings.length).toBeGreaterThan(0);
  });

  it('finds a vulnerable ELF and ignores a non-ELF file', () => {
    const root = path.join(tmp, 'rootfs', 'bin');
    fs.mkdirSync(root, { recursive: true });
    // A fake ELF whose strings carry unsafe imports and no canary symbol.
    const elf = Buffer.concat([
      Buffer.from([0x7f, 0x45, 0x4c, 0x46]),
      Buffer.from('\x00gets\x00strcpy\x00system\x00main\x00', 'latin1'),
    ]);
    fs.writeFileSync(path.join(root, 'stack_bof'), elf);
    // A non-ELF text file must be ignored even though it mentions strcpy.
    fs.writeFileSync(path.join(root, 'readme.txt'), 'this doc mentions strcpy and gets but is not code');

    const r = runBinVuln(path.join(tmp, 'rootfs'));
    expect(r.available).toBe(true);
    expect(r.binariesScanned).toBe(1);
    expect(r.candidates).toBe(1);
    expect(r.findings.some((f) => f.kind === 'binary-pwnable-candidate')).toBe(true);
    expect(r.findings.some((f) => f.kind === 'binary-cmdexec-sink')).toBe(true);
    // The size is what ranks a candidate downstream, so it has to reach the finding.
    const candidate = r.findings.find((f) => f.kind === 'binary-pwnable-candidate');
    expect((candidate?.evidence as Record<string, unknown>).size).toBe(elf.length);
  });

  /**
   * The regression that motivated the ranked cap, reproduced in miniature.
   *
   * On the real DVRF rootfs the sweep reported 43 candidates, all from `usr/sbin`, `usr/local/samba` and
   * `usr/lib` — because the walk is a LIFO stack that descends `usr/` first, and `FINDING_CAP` then truncated by
   * arrival. `bin/`, `sbin/` and the whole `pwnable/` tree overflowed unexamined, which excluded
   * `pwnable/Intro/stack_bof_01`: a 7 KB binary that angr proves reachable and gdb reproduces a SIGSEGV in, i.e.
   * the single most probe-worthy candidate in the image. Nothing reported was false; the SET was an artifact of
   * directory order.
   */
  it('lists the small candidate an early directory holds instead of a prefix of the walk', () => {
    const root = path.join(tmp, 'capped');
    fs.mkdirSync(path.join(root, 'usr', 'sbin'), { recursive: true });
    fs.mkdirSync(path.join(root, 'pwnable', 'Intro'), { recursive: true });
    // 65 fat candidates in the directory the LIFO walk descends into FIRST (`usr` sorts after `pwnable`)…
    for (let i = 0; i < 65; i++) {
      fs.writeFileSync(path.join(root, 'usr', 'sbin', `daemon${i}`), fakeElf(['strcpy', 'main'], 8192));
    }
    // …and the one small candidate that the old arrival-order cap dropped.
    fs.writeFileSync(path.join(root, 'pwnable', 'Intro', 'stack_bof_01'), fakeElf(['strcpy', 'main'], 16));

    const r = runBinVuln(root);
    expect(r.binariesScanned).toBe(66);
    expect(r.candidates).toBe(66); // every candidate FOUND is counted…
    expect(r.findings).toHaveLength(60); // …even though the cap lists fewer
    const listed = r.findings.map((f) => (f.evidence as Record<string, unknown>).path);
    expect(listed).toContain(path.join('pwnable', 'Intro', 'stack_bof_01'));
    // Smallest-first, so the listed set is a ranking rather than a prefix.
    const sizes = r.findings.map((f) => (f.evidence as Record<string, unknown>).size as number);
    expect([...sizes].sort((a, b) => a - b)).toEqual(sizes);
    // The bound is stated, not implied by a short list.
    expect(r.reason).toMatch(/drops 6 further finding/);
  });

  it('states an exhausted examination budget instead of passing it off as a clean sweep', () => {
    const root = path.join(tmp, 'budget');
    fs.mkdirSync(root, { recursive: true });
    for (let i = 0; i < 401; i++) {
      fs.writeFileSync(path.join(root, `b${String(i).padStart(3, '0')}`), fakeElf(['strcpy'], 8));
    }
    const r = runBinVuln(root);
    expect(r.binariesScanned).toBe(400);
    expect(r.reason).toMatch(/examination budget was exhausted/);
  });
});

describe('isRunnableElf — a library is a candidate the probes cannot question', () => {
  /** Minimal ELF32-LE header with a chosen e_type and program-header table. */
  const elfWith = (type: number, phTypes: number[]): Uint8Array => {
    const PH_OFF = 0x40;
    const PH_ENT = 32;
    const buf = Buffer.alloc(PH_OFF + PH_ENT * Math.max(1, phTypes.length));
    buf[0] = 0x7f;
    buf[1] = 0x45;
    buf[2] = 0x4c;
    buf[3] = 0x46;
    buf[4] = 1; // ELF32
    buf[5] = 1; // little-endian
    buf.writeUInt16LE(type, 0x10); // e_type
    buf.writeUInt32LE(PH_OFF, 0x1c); // e_phoff
    buf.writeUInt16LE(PH_ENT, 0x2a); // e_phentsize
    buf.writeUInt16LE(phTypes.length, 0x2c); // e_phnum
    phTypes.forEach((t, i) => buf.writeUInt32LE(t, PH_OFF + i * PH_ENT));
    return buf;
  };

  it('accepts a plain executable', () => {
    expect(isRunnableElf(elfWith(2, []))).toBe(true);
  });

  it('accepts a PIE, which is ET_DYN but names an interpreter', () => {
    expect(isRunnableElf(elfWith(3, [1, 3]))).toBe(true); // PT_LOAD, PT_INTERP
  });

  it('rejects a shared library — ET_DYN with no interpreter to load it', () => {
    expect(isRunnableElf(elfWith(3, [1, 2]))).toBe(false); // PT_LOAD, PT_DYNAMIC
  });

  it('rejects something that is not an ELF at all', () => {
    expect(isRunnableElf(Buffer.alloc(80, 0x41))).toBe(false);
  });
});

describe('selectFindings — which leads survive the cap is a decision, not an accident', () => {
  const draft = (kind: string, p: string, size: number): FindingDraft => ({
    kind,
    title: `${kind} ${p}`,
    severity: 'medium',
    proofState: 'needs_runtime_reproduction',
    evidence: { path: p, size },
    rationale: '',
  });

  it('keeps everything when the set fits, and reports nothing dropped', () => {
    const drafts = [draft('a', 'x', 3), draft('a', 'y', 1)];
    const { kept, dropped } = selectFindings(drafts, 10);
    expect(kept).toHaveLength(2);
    expect(dropped).toBe(0);
  });

  it('keeps the smallest binaries of each kind when it does not', () => {
    const drafts = [draft('a', 'big', 900), draft('a', 'small', 1), draft('a', 'mid', 50)];
    const { kept, dropped } = selectFindings(drafts, 2);
    expect(kept.map((f) => (f.evidence as Record<string, unknown>).path)).toEqual(['small', 'mid']);
    expect(dropped).toBe(1);
  });

  it('round-robins across kinds so a high-volume kind cannot evict another entirely', () => {
    const many = Array.from({ length: 20 }, (_, i) => draft('candidate', `c${i}`, i));
    const few = [draft('sink', 's0', 5), draft('sink', 's1', 6)];
    const { kept } = selectFindings([...many, ...few], 6);
    const kinds = kept.map((f) => f.kind);
    expect(kinds.filter((k) => k === 'sink')).toHaveLength(2);
    expect(kinds.filter((k) => k === 'candidate')).toHaveLength(4);
  });

  it('gives the same answer whatever order the walk produced', () => {
    const drafts = [draft('a', 'x', 9), draft('b', 'y', 2), draft('a', 'z', 4)];
    const forward = selectFindings(drafts, 2).kept.map((f) => f.title);
    const reversed = selectFindings([...drafts].reverse(), 2).kept.map((f) => f.title);
    expect(forward).toEqual(reversed);
  });
});

// === Real symbol tables (the fix for "imports" that meant "mentions") ===

/**
 * Build a minimal but structurally valid ELF carrying a `.dynsym`/`.dynstr` pair, in either width and endianness.
 * Synthetic rather than a fixture binary so the test stays hermetic and can cover ELF32 big-endian — the shape
 * most of this corpus actually is (mips), and the one whose `sh_link` offset differs from ELF64.
 */
function buildElf(names: string[], opts: { bits: 32 | 64; little: boolean }): Uint8Array {
  const { bits, little } = opts;
  const is64 = bits === 64;
  const shent = is64 ? 64 : 40;
  const syment = is64 ? 24 : 16;
  const STR_OFF = 0x100;
  const SYM_OFF = 0x200;
  const SH_OFF = 0x300;
  const buf = Buffer.alloc(0x400);

  // .dynstr — a leading NUL, then each name NUL-terminated.
  const offsets: number[] = [];
  let cur = 1;
  for (const n of names) {
    offsets.push(cur);
    buf.write(n, STR_OFF + cur, 'latin1');
    cur += n.length + 1;
  }
  const strSize = cur;

  const w32 = (o: number, v: number) => (little ? buf.writeUInt32LE(v, o) : buf.writeUInt32BE(v, o));
  const w16 = (o: number, v: number) => (little ? buf.writeUInt16LE(v, o) : buf.writeUInt16BE(v, o));
  const wN = (o: number, v: number) =>
    is64 ? (little ? buf.writeBigUInt64LE(BigInt(v), o) : buf.writeBigUInt64BE(BigInt(v), o)) : w32(o, v);

  // .dynsym — index 0 is the reserved null entry, then one per name (st_name is the first u32 in both widths).
  for (let i = 0; i < names.length; i++) w32(SYM_OFF + (i + 1) * syment, offsets[i] as number);
  const symSize = (names.length + 1) * syment;

  // ELF header.
  buf.write('\x7fELF', 0, 'latin1');
  buf[4] = is64 ? 2 : 1;
  buf[5] = little ? 1 : 2;
  buf[6] = 1;
  wN(is64 ? 0x28 : 0x20, SH_OFF); // e_shoff
  w16(is64 ? 0x3a : 0x2e, shent); // e_shentsize
  w16(is64 ? 0x3c : 0x30, 3); // e_shnum: null, .dynsym, .dynstr
  w16(is64 ? 0x3e : 0x32, 2); // e_shstrndx

  // [1] .dynsym (SHT_DYNSYM = 11), linked to section 2.
  const sym = SH_OFF + shent;
  w32(sym + 4, 11);
  wN(sym + (is64 ? 0x18 : 0x10), SYM_OFF);
  wN(sym + (is64 ? 0x20 : 0x14), symSize);
  w32(sym + (is64 ? 0x28 : 0x18), 2); // sh_link
  wN(sym + (is64 ? 0x38 : 0x24), syment);

  // [2] .dynstr (SHT_STRTAB = 3).
  const str = SH_OFF + 2 * shent;
  w32(str + 4, 3);
  wN(str + (is64 ? 0x18 : 0x10), STR_OFF);
  wN(str + (is64 ? 0x20 : 0x14), strSize);

  return new Uint8Array(buf);
}

describe('parseDynamicSymbols — "imports" must mean the loader resolves it', () => {
  for (const opts of [
    { bits: 64 as const, little: true },
    { bits: 32 as const, little: true },
    { bits: 32 as const, little: false }, // mips BE — most of this corpus
  ]) {
    it(`reads the dynamic symbol table of an ELF${opts.bits} ${opts.little ? 'LE' : 'BE'} binary`, () => {
      const syms = parseDynamicSymbols(buildElf(['strcpy', 'system', '__stack_chk_fail'], opts));
      expect(syms).not.toBeNull();
      expect([...(syms as Set<string>)].sort()).toEqual(['__stack_chk_fail', 'strcpy', 'system']);
    });
  }

  it('strips the version suffix so a versioned import matches its base name', () => {
    const syms = parseDynamicSymbols(buildElf(['memcpy@GLIBC_2.14'], { bits: 64, little: true }));
    expect(syms?.has('memcpy')).toBe(true);
  });

  it('returns null — not an empty set — for a non-ELF or a table it cannot read', () => {
    expect(parseDynamicSymbols(new Uint8Array([1, 2, 3, 4]))).toBeNull();
    expect(parseDynamicSymbols(new Uint8Array(Buffer.from('\x7fELFnot really an elf at all........')))).toBeNull();
  });
});

/**
 * Build an ELF with NO section headers at all (`e_shoff == 0`, `e_shnum == 0`) whose dynamic symbols are reachable
 * only through PT_DYNAMIC — the shape OpenWrt ships. PT_LOAD maps the file identically (vaddr == offset) so the
 * virtual addresses in the dynamic array resolve back to file offsets the way a real loader resolves them.
 */
function buildStrippedElf(names: string[], opts: { bits: 32 | 64; little: boolean }): Uint8Array {
  const { bits, little } = opts;
  const is64 = bits === 64;
  const phent = is64 ? 56 : 32;
  const syment = is64 ? 24 : 16;
  const dynent = is64 ? 16 : 8;
  const PH_OFF = 0x40;
  const STR_OFF = 0x100;
  const SYM_OFF = 0x200;
  const HASH_OFF = 0x300;
  const DYN_OFF = 0x340;
  const SIZE = 0x600;
  const buf = Buffer.alloc(SIZE);

  const w32 = (o: number, v: number) => (little ? buf.writeUInt32LE(v, o) : buf.writeUInt32BE(v, o));
  const w16 = (o: number, v: number) => (little ? buf.writeUInt16LE(v, o) : buf.writeUInt16BE(v, o));
  const wN = (o: number, v: number) =>
    is64 ? (little ? buf.writeBigUInt64LE(BigInt(v), o) : buf.writeBigUInt64BE(BigInt(v), o)) : w32(o, v);

  const offsets: number[] = [];
  let cur = 1;
  for (const n of names) {
    offsets.push(cur);
    buf.write(n, STR_OFF + cur, 'latin1');
    cur += n.length + 1;
  }
  const strSize = cur;
  for (let i = 0; i < names.length; i++) w32(SYM_OFF + (i + 1) * syment, offsets[i] as number);

  buf.write('\x7fELF', 0, 'latin1');
  buf[4] = is64 ? 2 : 1;
  buf[5] = little ? 1 : 2;
  buf[6] = 1;
  w16(0x10, 2); // e_type = ET_EXEC
  wN(is64 ? 0x20 : 0x1c, PH_OFF); // e_phoff
  w16(is64 ? 0x36 : 0x2a, phent); // e_phentsize
  w16(is64 ? 0x38 : 0x2c, 2); // e_phnum
  // e_shoff / e_shentsize / e_shnum are left at zero — this is the whole point of the fixture.

  // [0] PT_LOAD covering the file, mapped identically so vaddr === file offset.
  w32(PH_OFF, 1);
  if (is64) {
    wN(PH_OFF + 0x08, 0);
    wN(PH_OFF + 0x10, 0);
    wN(PH_OFF + 0x20, SIZE);
  } else {
    w32(PH_OFF + 0x04, 0);
    w32(PH_OFF + 0x08, 0);
    w32(PH_OFF + 0x10, SIZE);
  }

  // [1] PT_DYNAMIC.
  const ph1 = PH_OFF + phent;
  const dynSize = 6 * dynent;
  w32(ph1, 2);
  if (is64) {
    wN(ph1 + 0x08, DYN_OFF);
    wN(ph1 + 0x10, DYN_OFF);
    wN(ph1 + 0x20, dynSize);
  } else {
    w32(ph1 + 0x04, DYN_OFF);
    w32(ph1 + 0x08, DYN_OFF);
    w32(ph1 + 0x10, dynSize);
  }

  // DT_HASH's second word is nchain — one slot per dynamic symbol, so it carries the count.
  w32(HASH_OFF, 1);
  w32(HASH_OFF + 4, names.length + 1);

  const entries: Array<[number, number]> = [
    [4, HASH_OFF], // DT_HASH
    [5, STR_OFF], // DT_STRTAB
    [6, SYM_OFF], // DT_SYMTAB
    [10, strSize], // DT_STRSZ
    [11, syment], // DT_SYMENT
    [0, 0], // DT_NULL
  ];
  entries.forEach(([tag, val], i) => {
    const o = DYN_OFF + i * dynent;
    if (is64) {
      wN(o, tag);
      wN(o + 8, val);
    } else {
      w32(o, tag);
      w32(o + 4, val);
    }
  });

  return new Uint8Array(buf);
}

describe('parseDynamicSymbols — section headers are optional at run time', () => {
  // Measured, not assumed: every binary in the GL.iNet BE3600 rootfs (usign, fwtool, upgraded, …) reports
  // "Start of section headers: 0 / Number of section headers: 0". The section-header walk returns null for all of
  // them, so before this fallback the richest image in the corpus fell to the string superset everywhere — and
  // "usign mentions edsign_verify" is a materially weaker claim than "the loader must resolve edsign_verify".
  for (const opts of [
    { bits: 64 as const, little: true },
    { bits: 32 as const, little: true },
    { bits: 32 as const, little: false },
  ]) {
    it(`reads PT_DYNAMIC when the section headers are stripped (ELF${opts.bits} ${opts.little ? 'LE' : 'BE'})`, () => {
      const syms = parseDynamicSymbols(buildStrippedElf(['edsign_verify', 'strcpy', '__stack_chk_fail'], opts));
      expect(syms).not.toBeNull();
      expect([...(syms as Set<string>)].sort()).toEqual(['__stack_chk_fail', 'edsign_verify', 'strcpy']);
    });
  }

  it('still returns null when neither route has a table to read, so the caller degrades honestly', () => {
    const stripped = Buffer.from(buildStrippedElf(['strcpy'], { bits: 64, little: true }));
    stripped.writeUInt16LE(0, 0x38); // e_phnum = 0 — no program headers either
    expect(parseDynamicSymbols(new Uint8Array(stripped))).toBeNull();
  });
});

describe('buildBinFindings — the verb has to match the evidence', () => {
  // sbin/chkntfs was reported as "imports system" off the string scan, and angr then resolved no PLT or symbol
  // entry for it at all. A token in the binary's strings is a MENTION; only a symbol-table entry is an import.
  it('says "imports" only when the names came from the real symbol table', () => {
    const dyn = buildBinFindings(assessBinary('bin/x', new Set(['system']), 'dynsym'));
    expect(dyn[0]?.title).toContain('imports system');
    expect(dyn[0]?.rationale).toContain('loader does resolve');
    expect(dyn[0]?.evidence?.symbolSource).toBe('dynsym');
  });

  it('downgrades to "references" and flags the weaker basis when it only saw strings', () => {
    const str = buildBinFindings(assessBinary('bin/x', new Set(['system']), 'strings'));
    expect(str[0]?.title).toContain('references system');
    expect(str[0]?.title).not.toContain('imports');
    expect(str[0]?.rationale).toContain('not proof that it is imported');
    expect(str[0]?.evidence?.symbolSource).toBe('strings');
  });
});
