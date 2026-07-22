import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { analyzeEsp, assessSecurePosture, parseNvsRegion, parsePartitionTable, runEspAnalysis } from './esp.js';

/** Little-endian encodings. */
function u32le(n: number): number[] {
  return [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff];
}
function u16le(n: number): number[] {
  return [n & 0xff, (n >>> 8) & 0xff];
}

/** Encode a 16-byte NUL-padded latin1 field. */
function field(s: string, len: number): number[] {
  const out = new Array(len).fill(0);
  for (let i = 0; i < Math.min(s.length, len); i++) out[i] = s.charCodeAt(i);
  return out;
}

/** A 32-byte partition entry: magic AA50, type, subtype, offset, size, label[16], flags. */
function partEntry(type: number, subtype: number, offset: number, size: number, label: string): number[] {
  return [0xaa, 0x50, type, subtype, ...u32le(offset), ...u32le(size), ...field(label, 16), 0, 0, 0, 0];
}

/** A 32-byte NVS entry header: ns, type, span, chunk, crc32, key[16], data[8]. */
function nvsEntry(ns: number, type: number, span: number, key: string, data: number[]): number[] {
  const d = [...data, ...new Array(8).fill(0)].slice(0, 8);
  return [ns, type, span, 0xff, 0, 0, 0, 0, ...field(key, 16), ...d];
}

describe('parsePartitionTable', () => {
  it('parses entries at 0x8000 and names type/subtype, stopping at the md5 marker', () => {
    const buf = Buffer.alloc(0x8100, 0xff);
    const table = [
      ...partEntry(0x01, 0x02, 0x9000, 0x5000, 'nvs'),
      ...partEntry(0x00, 0x10, 0x10000, 0x140000, 'app0'),
      ...partEntry(0x01, 0x82, 0x290000, 0x160000, 'spiffs'),
      0xeb,
      0xeb, // md5 marker → table ends
    ];
    Buffer.from(table).copy(buf, 0x8000);
    const parts = parsePartitionTable(buf);
    expect(parts).toHaveLength(3);
    expect(parts[0]).toMatchObject({ type: 'data', subtype: 'nvs', offset: 0x9000, size: 0x5000, label: 'nvs' });
    expect(parts[1]).toMatchObject({ type: 'app', subtype: 'ota_0', offset: 0x10000, label: 'app0' });
    expect(parts[2]).toMatchObject({ type: 'data', subtype: 'spiffs' });
  });

  it('returns [] when 0x8000 is not a partition table (not an ESP dump)', () => {
    expect(parsePartitionTable(Buffer.alloc(0x8100, 0x00))).toEqual([]);
  });
});

/** Build one 4096-byte NVS page: FULL state, a bitmap, then the given entry slots. `bitmap` is [byte0, byte1]. */
function nvsPage(bitmap: number[], entries: number[][]): Buffer {
  const page = Buffer.alloc(4096, 0xff);
  Buffer.from(u32le(0xfffffffc)).copy(page, 0); // page state FULL (not uninitialized)
  Buffer.from([...bitmap, ...new Array(32 - bitmap.length).fill(0xff)]).copy(page, 32);
  let o = 64;
  for (const e of entries) {
    Buffer.from(e).copy(page, o);
    o += 32;
  }
  return page;
}

describe('parseNvsRegion', () => {
  // si0: name="olduser" (superseded), si2: name="newuser", si4: signkey blob (32B), si6: erased "secret"
  const page = nvsPage(
    [0xaa, 0x8a], // si0-3 written; si4 written, si5 written, si6 ERASED(00), si7 written
    [
      nvsEntry(0x03, 0x21, 2, 'name', u16le(8)), // header
      [...field('olduser', 8), ...new Array(24).fill(0)], // continuation data slot (si1)
      nvsEntry(0x03, 0x21, 2, 'name', u16le(8)),
      [...field('newuser', 8), ...new Array(24).fill(0)],
      nvsEntry(0x04, 0x42, 2, 'signkey', u16le(32)),
      new Array(32).fill(0xab), // 32-byte binary key value
      nvsEntry(0x05, 0x21, 2, 'secret', u16le(7)),
      [...field('leaked', 7), ...new Array(25).fill(0)],
    ],
  );
  const entries = parseNvsRegion(page, 0, 4096);

  it('reads keys, types and reassembled string values', () => {
    const names = entries.filter((e) => e.key === 'name');
    expect(names.map((e) => e.valueText).sort()).toEqual(['newuser', 'olduser']);
  });

  it('recovers a binary blob as key material (sensitive, hex value, no text)', () => {
    const k = entries.find((e) => e.key === 'signkey');
    expect(k?.sensitive).toBe(true);
    expect(k?.valueHex).toBe('ab'.repeat(32));
    expect(k?.valueText).toBeUndefined();
    expect(k?.stale).toBe(false);
  });

  it('flags a superseded duplicate as stale (its value still persists)', () => {
    const old = entries.find((e) => e.valueText === 'olduser');
    const fresh = entries.find((e) => e.valueText === 'newuser');
    expect(old?.stale).toBe(true);
    expect(fresh?.stale).toBe(false);
  });

  it('surfaces an ERASED-but-readable entry as stale', () => {
    const erased = entries.find((e) => e.key === 'secret');
    expect(erased?.state).toBe('erased');
    expect(erased?.stale).toBe(true);
    expect(erased?.valueText).toBe('leaked');
  });
});

describe('assessSecurePosture', () => {
  it('reports OFF when the app partition is a plaintext esp_image (magic 0xE9)', () => {
    const buf = Buffer.alloc(0x100, 0x00);
    buf[0x80] = 0xe9;
    const p = assessSecurePosture(buf, 0x80);
    expect(p.flashEncryption).toBe('off');
    expect(p.secureBoot).toBe('off');
    expect(p.antiRollback).toBe('off');
  });

  it('degrades to unknown when the app image is not plaintext (could be encrypted)', () => {
    const buf = Buffer.alloc(0x100, 0x55);
    const p = assessSecurePosture(buf, 0x80);
    expect(p.flashEncryption).toBe('unknown');
    expect(p.secureBoot).toBe('unknown');
  });

  it('degrades to unknown when there is no app partition', () => {
    expect(assessSecurePosture(Buffer.alloc(16), null).flashEncryption).toBe('unknown');
  });
});

/** A minimal but real-geometry ESP image: table @0x8000 (nvs@0x9000, factory@0x10000), an NVS page, an app image. */
function buildEspImage(): Buffer {
  const buf = Buffer.alloc(0x10001, 0x00);
  const table = [
    ...partEntry(0x01, 0x02, 0x9000, 0x1000, 'nvs'),
    ...partEntry(0x00, 0x00, 0x10000, 0x8000, 'factory'),
    0xeb,
    0xeb,
  ];
  Buffer.from(table).copy(buf, 0x8000);
  const page = nvsPage([0xaa, 0xff], [nvsEntry(0x04, 0x42, 2, 'privkey', u16le(32)), new Array(32).fill(0xcd)]);
  page.copy(buf, 0x9000);
  buf[0x10000] = 0xe9; // plaintext app image → posture OFF
  return buf;
}

describe('analyzeEsp', () => {
  const a = analyzeEsp(buildEspImage());

  it('identifies the dump, inventories partitions, and recovers the NVS signing key', () => {
    expect(a.isEsp).toBe(true);
    expect(a.partitions.map((p) => p.subtype)).toEqual(['nvs', 'factory']);
    const key = a.findings.find((f) => f.kind === 'esp-nvs-key');
    expect(key?.severity).toBe('critical');
    expect(key?.proofState).toBe('static_confirmed');
    expect((key?.evidence as { valueHex: string }).valueHex).toBe('cd'.repeat(32));
  });

  it('emits an OFF security-posture finding', () => {
    const posture = a.findings.find((f) => f.kind === 'esp-secure-posture');
    expect(posture?.severity).toBe('high');
    expect(posture?.title).toContain('Flash-Encryption OFF');
    expect(posture?.title).toContain('Secure-Boot OFF');
  });

  it('degrades honestly on a non-ESP buffer', () => {
    expect(analyzeEsp(Buffer.alloc(0x100, 0x00)).isEsp).toBe(false);
  });
});

describe('runEspAnalysis', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-esp-test-'));
  afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it('analyzes an ESP dump on disk into static_confirmed findings', () => {
    const p = path.join(tmp, 'esp.bin');
    fs.writeFileSync(p, buildEspImage());
    const res = runEspAnalysis(p);
    expect(res.available).toBe(true);
    expect(res.isEsp).toBe(true);
    expect(res.findings.some((f) => f.kind === 'esp-nvs-key')).toBe(true);
    expect(res.reason).toContain('ESP SoC dump');
  });

  it('degrades honestly for a non-ESP blob', () => {
    const p = path.join(tmp, 'random.bin');
    fs.writeFileSync(p, Buffer.alloc(0x100, 0x00));
    const res = runEspAnalysis(p);
    expect(res.available).toBe(true);
    expect(res.isEsp).toBe(false);
    expect(res.reason).toContain('No ESP partition table');
  });
});
