import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { analyzeEncrypted, classifyCipher, parseOtaHeader, runEncryptedAnalysis } from './encrypted.js';

/** Deterministic high-entropy fill (LCG) — near-uniform bytes, no repeated 16-byte blocks. */
function fillEntropy(buf: Buffer, start: number, end: number, seed = 0x1234): void {
  let x = seed >>> 0;
  for (let i = start; i < end; i++) {
    x = (Math.imul(x, 1103515245) + 12345) & 0x7fffffff;
    buf[i] = (x >>> 16) & 0xff;
  }
}

/**
 * A synthetic encrypted OTA mirroring the GE800 framing: big-endian length @0 (= size − 16), a plaintext
 * `fw-type:Cloud` tag, a framed 16-byte IV (`AA55 …16… 55AA`) at 0x114, then a high-entropy body.
 */
function buildEncryptedOta(size = 0x20000): Buffer {
  const buf = Buffer.alloc(size, 0x00);
  buf.writeUInt32BE(size - 16, 0); // length field
  buf.write('fw-type:Cloud\n', 0x11, 'latin1');
  buf[0x114] = 0xaa;
  buf[0x115] = 0x55;
  Buffer.from('4c5e831f534ba1f8f7c918df8fbf7da1', 'hex').copy(buf, 0x116); // the 16-byte IV
  buf[0x126] = 0x55;
  buf[0x127] = 0xaa;
  fillEntropy(buf, 0x128, size);
  return buf;
}

describe('parseOtaHeader', () => {
  const h = parseOtaHeader(buildEncryptedOta(), 0x20000);

  it('recognizes the big-endian length field that matches the file size', () => {
    expect(h.lengthField).toBe(0x20000 - 16);
  });

  it('locates the framed 16-byte IV at 0x116', () => {
    expect(h.ivBlock).toEqual({ offset: 0x116, bytes: '4c5e831f534ba1f8f7c918df8fbf7da1' });
  });

  it('extracts the plaintext header tag and the body offset past the IV frame', () => {
    expect(h.plaintextTags.some((t) => t.includes('fw-type:Cloud'))).toBe(true);
    expect(h.cipherBodyOffset).toBe(0x128);
  });

  it('degrades honestly on an unframed blob (no length field, no IV)', () => {
    const raw = Buffer.alloc(0x2000, 0x00);
    fillEntropy(raw, 0, 0x2000);
    const hr = parseOtaHeader(raw, 0x2000);
    expect(hr.ivBlock).toBeNull();
    expect(hr.lengthField).toBeNull();
  });
});

describe('classifyCipher', () => {
  const buf = buildEncryptedOta();
  const header = parseOtaHeader(buf, 0x20000);

  it('classifies a 16-byte IV + high-entropy body as AES, 128-bit block, CBC/CTR', () => {
    const v = classifyCipher(buf, header, 0x20000);
    expect(v.cipher).toBe('AES');
    expect(v.blockBits).toBe(128);
    expect(v.mode).toBe('CBC-or-CTR');
    expect(v.ivPresent).toBe(true);
    expect(v.bodyEntropy).toBeGreaterThan(7.5);
  });

  it('detects ECB from repeated ciphertext blocks', () => {
    const b = buildEncryptedOta();
    // Duplicate block 0 of the body into block 5 → a repeated 16-byte ciphertext block (the ECB tell).
    b.copy(b, 0x128 + 16 * 5, 0x128, 0x128 + 16);
    expect(classifyCipher(b, parseOtaHeader(b, b.length), b.length).mode).toBe('ECB');
  });
});

describe('analyzeEncrypted', () => {
  const a = analyzeEncrypted(buildEncryptedOta(), 0x20000);

  it('emits a static_confirmed cipher diagnosis carrying the IV', () => {
    const cipher = a.findings.find((f) => f.kind === 'encrypted-cipher');
    expect(cipher?.severity).toBe('high');
    expect(cipher?.proofState).toBe('static_confirmed');
    expect(cipher?.title).toContain('AES');
    expect(cipher?.title).toContain('IV @ 0x116');
    expect((cipher?.evidence as { ivHex: string }).ivHex).toBe('4c5e831f534ba1f8f7c918df8fbf7da1');
  });

  it('emits the honest blocked_by_security "unrecoverable without key" verdict with a recovery path', () => {
    const v = a.findings.find((f) => f.kind === 'encrypted-unrecoverable');
    expect(v?.proofState).toBe('blocked_by_security');
    expect((v?.evidence as { keyRecoveryPaths: string[] }).keyRecoveryPaths.length).toBeGreaterThan(0);
  });

  it('surfaces the leaked plaintext metadata tag', () => {
    const meta = a.findings.find((f) => f.kind === 'encrypted-metadata');
    expect(meta?.title).toContain('fw-type:Cloud');
  });

  it('still gives the unrecoverable verdict on a headerless high-entropy blob (never empty)', () => {
    const raw = Buffer.alloc(0x4000, 0x00);
    fillEntropy(raw, 0, 0x4000);
    const findings = analyzeEncrypted(raw, 0x4000).findings;
    expect(findings.some((f) => f.kind === 'encrypted-unrecoverable')).toBe(true);
  });
});

describe('runEncryptedAnalysis', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-enc-test-'));
  afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it('diagnoses an encrypted OTA on disk', () => {
    const p = path.join(tmp, 'ota.bin');
    fs.writeFileSync(p, buildEncryptedOta());
    const res = runEncryptedAnalysis(p);
    expect(res.available).toBe(true);
    expect(res.verdict.cipher).toBe('AES');
    expect(res.reason).toContain('IV @ 0x116');
    expect(res.findings.some((f) => f.kind === 'encrypted-unrecoverable')).toBe(true);
  });
});
