import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { parseMediaTekLkHeader } from '../src/mediatek-image.js';

// Complete inert fixture produced by upstream mkimage 2026.10-rc5, whose mtk_image.c is byte-identical to
// pinned v2026.10. Payload is bytes 0..255 followed by 0xa5; provenance/commands are in the accompanying doc.
const GENERATED_BASE64 =
  'iBaIWAEBAABzeW50aGV0aWMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIH/////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '//////////////////////////////////////////////////////////////////////////////////8AAQIDBAUGBwgJCgsM' +
  'DQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZX' +
  'WFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoOEhYaHiImKi4yNjo+QkZKTlJWWl5iZmpucnZ6foKGi' +
  'o6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn6Onq6+zt' +
  '7u/w8fLz9PX29/j5+vv8/f7/pQ==';
function generated(): Uint8Array {
  return Uint8Array.from(Buffer.from(GENERATED_BASE64, 'base64'));
}
function set32(bytes: Uint8Array, at: number, value: number): void {
  new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).setUint32(at, value, true);
}

describe('MediaTek LK legacy header subset', () => {
  it('parses an independent upstream generated fixture without changing bytes', () => {
    const bytes = generated();
    const before = Uint8Array.from(bytes);
    expect(createHash('sha256').update(bytes).digest('hex')).toBe(
      '3829f6203fa47e0a9a71bebcf67311cb47e19211246c9baef3c35771f6a1b689',
    );
    expect(parseMediaTekLkHeader(bytes)).toEqual({
      valid: true,
      name: 'synthetic',
      payloadSize: 257,
      totalSize: 769,
      loadAddress: 0x81000000,
      mode: 0xffffffff,
    });
    expect(bytes).toEqual(before);
  });

  it('rejects every incomplete header and every missing declared payload byte', () => {
    const bytes = generated();
    for (let length = 0; length < bytes.length; length++) {
      expect(parseMediaTekLkHeader(bytes.subarray(0, length)).valid, `length ${length}`).toBe(false);
    }
  });

  it('rejects wrong endian/magic, zero mode, impossible sizes and unsupported reserved bytes', () => {
    for (const [at, value] of [
      [0, 0x88168858],
      [0, 0],
      [4, 258],
      [4, 0xffffffff],
      [4, 0xfffffe01],
      [44, 0],
      [40, 0],
    ] as const) {
      const bytes = generated();
      set32(bytes, at, value);
      expect(parseMediaTekLkHeader(bytes).valid, `field ${at} value ${value}`).toBe(false);
    }
    for (let at = 48; at < 512; at++) {
      const bytes = generated();
      bytes[at] = 0;
      expect(parseMediaTekLkHeader(bytes).valid, `reserved byte ${at}`).toBe(false);
    }
  });

  it('accepts unsigned nonzero addresses and modes without claiming memory or runtime validity', () => {
    const bytes = generated();
    set32(bytes, 40, 1);
    set32(bytes, 44, 1);
    expect(parseMediaTekLkHeader(bytes)).toMatchObject({ valid: true, loadAddress: 1, mode: 1 });
    set32(bytes, 40, 0xffffffff);
    expect(parseMediaTekLkHeader(bytes)).toMatchObject({ valid: true, loadAddress: 0xffffffff });
  });

  it('accepts zero payloads emitted by mkimage -s and empty names', () => {
    const bytes = generated().slice(0, 512);
    set32(bytes, 4, 0);
    bytes.fill(0, 8, 40);
    expect(parseMediaTekLkHeader(bytes)).toMatchObject({ valid: true, payloadSize: 0, totalSize: 512, name: '' });
  });

  it('accepts the actual 31-byte maximum and UTF-8 names, rejecting missing NUL or nonzero NUL padding', () => {
    const bytes = generated();
    bytes.fill(0, 8, 40);
    bytes.set(Buffer.from('1234567890123456789012345678901'), 8);
    expect(parseMediaTekLkHeader(bytes)).toMatchObject({ valid: true, name: '1234567890123456789012345678901' });
    bytes[39] = 65;
    expect(parseMediaTekLkHeader(bytes).valid).toBe(false);
    bytes.fill(0, 8, 40);
    bytes.set(Buffer.from('écho'), 8);
    expect(parseMediaTekLkHeader(bytes)).toMatchObject({ valid: true, name: 'écho' });
    // Generator accepts non-ASCII and control bytes; printable ASCII is not a source-established invariant.
    bytes[8] = 1;
    expect(parseMediaTekLkHeader(bytes).valid).toBe(true);
    bytes[20] = 65;
    expect(parseMediaTekLkHeader(bytes).valid).toBe(false);
  });

  it('uses remaining bytes from a nonzero embedded offset and respects Uint8Array view offsets', () => {
    const backing = new Uint8Array(900).fill(0x55);
    const view = backing.subarray(11, 811);
    view.set(generated(), 7);
    expect(parseMediaTekLkHeader(view, 7)).toMatchObject({ valid: true, totalSize: 769 });
    expect(parseMediaTekLkHeader(view.subarray(0, 775), 7).valid).toBe(false);
    expect(parseMediaTekLkHeader(view, 0).valid).toBe(false);
    expect(parseMediaTekLkHeader(view.subarray(7))).toMatchObject({ valid: true });
  });

  it('bounds offsets before any read and accepts arbitrary trailing bytes outside the declared image', () => {
    for (const offset of [-1, 0.5, Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER, 770]) {
      expect(parseMediaTekLkHeader(generated(), offset).valid).toBe(false);
    }
    const bytes = new Uint8Array(800).fill(0xa5);
    bytes.set(generated());
    expect(parseMediaTekLkHeader(bytes)).toMatchObject({ valid: true, totalSize: 769 });
  });

  it('does not invent integrity verification for a format without an integrity field', () => {
    const bytes = generated();
    bytes[768] ^= 0xff;
    expect(parseMediaTekLkHeader(bytes)).toMatchObject({ valid: true });
  });
});
