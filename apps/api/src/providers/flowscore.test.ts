import { describe, expect, it } from 'vitest';
import { FIRMWARE_THRESHOLD, scoreFirmwareFlow, urlLooksFirmware } from './flowscore.js';

/** A body starting with the SquashFS magic 'hsqs', padded so it's a plausible size. */
function squashfsBody(size = 300 * 1024): Uint8Array {
  const b = new Uint8Array(size);
  b.set([0x68, 0x73, 0x71, 0x73]); // 'hsqs'
  for (let i = 4; i < size; i++) b[i] = i & 0xff;
  return b;
}

/** A uniform-histogram body → maximal Shannon entropy, i.e. "looks encrypted/compressed" with no magic. */
function highEntropyBody(size = 8192): Uint8Array {
  return Uint8Array.from({ length: size }, (_, i) => i & 0xff);
}

describe('urlLooksFirmware', () => {
  it('matches OTA/firmware paths and binary extensions', () => {
    expect(urlLooksFirmware('https://cdn.example.com/ota/device-v1.2.bin')).toBe(true);
    expect(urlLooksFirmware('https://api.example.com/firmware/latest')).toBe(true);
    expect(urlLooksFirmware('https://example.com/upgrade.img')).toBe(true);
  });
  it('does not match ordinary web paths', () => {
    expect(urlLooksFirmware('https://example.com/index.html')).toBe(false);
    expect(urlLooksFirmware('https://example.com/api/status')).toBe(false);
  });
});

describe('scoreFirmwareFlow', () => {
  it('scores a SquashFS octet-stream on a firmware URL as a strong candidate', () => {
    const r = scoreFirmwareFlow(
      {
        url: 'https://cdn.example.com/ota/fw.bin',
        method: 'GET',
        contentType: 'application/octet-stream',
        contentLength: 300 * 1024,
        tls: 'tls-unpinned',
      },
      squashfsBody(),
    );
    expect(r.isFirmwareCandidate).toBe(true);
    expect(r.score).toBeGreaterThanOrEqual(FIRMWARE_THRESHOLD);
    expect(r.signatureIds).toContain('squashfs-le');
  });

  it('scores a high-entropy encrypted OTA (no magic) as a candidate via entropy + size + URL', () => {
    const r = scoreFirmwareFlow(
      {
        url: 'https://ota.vendor.com/firmware/blob',
        method: 'GET',
        contentType: 'application/octet-stream',
        contentLength: 2 * 1024 * 1024,
        tls: 'tls-unpinned',
      },
      highEntropyBody(),
    );
    expect(r.isFirmwareCandidate).toBe(true);
    expect(r.reasons.some((x) => /entropy/.test(x))).toBe(true);
  });

  it('rejects an HTML page (text content-type is a strong negative)', () => {
    const r = scoreFirmwareFlow(
      {
        url: 'https://example.com/index.html',
        method: 'GET',
        contentType: 'text/html; charset=utf-8',
        contentLength: 4096,
        tls: 'tls-unpinned',
      },
      new TextEncoder().encode('<!DOCTYPE html><html><body>hello</body></html>'),
    );
    expect(r.isFirmwareCandidate).toBe(false);
    expect(r.score).toBe(0);
  });

  it('rejects a small JSON manifest', () => {
    const r = scoreFirmwareFlow(
      {
        url: 'https://api.vendor.com/ota/check',
        method: 'GET',
        contentType: 'application/json',
        contentLength: 120,
        tls: 'tls-unpinned',
      },
      new TextEncoder().encode('{"version":"1.2.3","url":"https://cdn/fw.bin"}'),
    );
    expect(r.isFirmwareCandidate).toBe(false);
  });
});
