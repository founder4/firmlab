import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { assessBinary, buildBinFindings, extractSymbols, runBinVuln } from './binvuln.js';

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
