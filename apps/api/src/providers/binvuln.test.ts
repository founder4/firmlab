import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { assessBinary, buildBinFindings, extractSymbols, parseDynamicSymbols, runBinVuln } from './binvuln.js';

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

  it('degrades honestly with no rootfs', () => {
    expect(runBinVuln(null).available).toBe(false);
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
