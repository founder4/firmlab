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
    expect(v.entropySample).toEqual({
      offset: 0x128,
      bytes: 0x10000,
      bodyBytes: 0x20000 - 0x128,
      complete: false,
    });
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
    expect(
      (cipher?.evidence as { entropySample: { bytes: number; bodyBytes: number; complete: boolean } }).entropySample,
    ).toEqual({ offset: 0x128, bytes: 0x10000, bodyBytes: 0x20000 - 0x128, complete: false });
    expect(cipher?.rationale).toContain('characterizes only the stated sample');
    expect(cipher?.rationale).not.toContain('The body is a high-entropy plateau');
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
    expect(res.reason).toContain('sampled body entropy');
    expect(res.reason).toContain('65536 of 130776 body bytes');
    expect(res.findings.some((f) => f.kind === 'encrypted-unrecoverable')).toBe(true);
  });

  it('reports the complete measured scope for a body smaller than the entropy window', () => {
    const p = path.join(tmp, 'small-ota.bin');
    fs.writeFileSync(p, buildEncryptedOta(0x8000));
    const res = runEncryptedAnalysis(p);
    expect(res.verdict.entropySample).toEqual({
      offset: 0x128,
      bytes: 0x8000 - 0x128,
      bodyBytes: 0x8000 - 0x128,
      complete: true,
    });
    expect(res.reason).toContain('over the complete 32472-byte body');
  });
});

/** A synthetic ENC1 per-partition container: magic + orig_len (u32-LE) + IV[16] @ 8 + high-entropy ciphertext @ 32. */
function buildEnc1Partition(size = 0x8000): Buffer {
  const buf = Buffer.alloc(size);
  buf.write('ENC1', 0, 'ascii');
  buf.writeUInt32LE(size - 32, 4);
  for (let i = 8; i < 24; i++) buf[i] = (i * 7) & 0xff;
  fillEntropy(buf, 32, size, 0xbeef);
  return buf;
}

describe('parseOtaHeader — ENC1 container', () => {
  it('recognizes the ENC1 per-partition container (magic + orig_len + IV @ 8, body @ 32)', () => {
    const h = parseOtaHeader(buildEnc1Partition(), 0x8000);
    expect(h.container).toBe('ENC1');
    expect(h.ivBlock?.offset).toBe(8);
    expect(h.cipherBodyOffset).toBe(32);
    expect(h.lengthField).toBe(0x8000 - 32);
  });

  it('does not mistake the four bytes "ENC1" in text for a container (absurd orig_len)', () => {
    const text = Buffer.from('nx_decrypt: not an ENC1 partition here', 'ascii');
    expect(parseOtaHeader(text, text.length).container).toBeUndefined();
  });

  it('rejects a truncated or length-incoherent ENC1 header', () => {
    const short = Buffer.alloc(24);
    short.write('ENC1', 0, 'ascii');
    short.writeUInt32LE(1, 4);
    expect(parseOtaHeader(short, 40).container).toBeUndefined();

    const impossible = Buffer.alloc(40);
    impossible.write('ENC1', 0, 'ascii');
    impossible.writeUInt32LE(1, 4);
    expect(parseOtaHeader(impossible, impossible.length).container).toBeUndefined();
  });
});

describe('analyzeEncrypted — ENC1 names a loader path without inventing loader evidence', () => {
  const a = analyzeEncrypted(buildEnc1Partition(), 0x8000);
  it('keeps the security block until a paired loader proves a derivation', () => {
    const v = a.findings.find((f) => f.kind === 'encrypted-unrecoverable');
    expect(v?.proofState).toBe('blocked_by_security');
    expect((v?.evidence as { container: string }).container).toBe('ENC1');
    expect(v?.title).toMatch(/paired-loader/i);
    expect(v?.rationale).toContain('magic alone never upgrades');
  });
});
