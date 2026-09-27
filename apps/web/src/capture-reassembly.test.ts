import { describe, expect, it } from 'vitest';
import { base64ToUint8, hexToUint8, parseCapturePayload, uint8ToBase64 } from './capture-reassembly';

describe('capture-reassembly transport decoding', () => {
  it('converts between uint8, base64, and hex', () => {
    const raw = Uint8Array.from([0xde, 0xad, 0xbe, 0xef]);
    const b64 = uint8ToBase64(raw);
    expect(base64ToUint8(b64)).toEqual(raw);
    const hex = 'deadbeef';
    expect(hexToUint8(hex)).toEqual(raw);
  });

  it('rejects odd-length hex strings', () => {
    expect(() => hexToUint8('abc')).toThrow('Invalid hex string length');
  });

  describe('parseCapturePayload', () => {
    it('decodes binary Uint8Array payload directly to base64', () => {
      const u8 = Uint8Array.from([1, 2, 3, 4]);
      const res = parseCapturePayload(u8, 'chunk.bin');
      expect(res.name).toBe('chunk.bin');
      expect(res.base64Items).toHaveLength(1);
      expect(base64ToUint8(res.base64Items[0] ?? '')).toEqual(u8);
    });

    it('decodes JSON array of base64 chunks and extracts sequence numbers and init packet', () => {
      const json = JSON.stringify({
        name: 'dfu_fw.bin',
        chunks: [
          { seq: 0, data: uint8ToBase64(Uint8Array.from([1, 2])) },
          { seq: 1, data: uint8ToBase64(Uint8Array.from([3, 4])) },
          { seq: 3, data: uint8ToBase64(Uint8Array.from([5, 6])) }, // missing 2
        ],
        initPacket: uint8ToBase64(Uint8Array.from([0xde, 0xad, 0x06, 0x00, 0x00, 0x00])),
      });

      const res = parseCapturePayload(json, 'capture.json');
      expect(res.name).toBe('dfu_fw.bin');
      expect(res.base64Items).toHaveLength(3);
      expect(res.sequences).toEqual([0, 1, 3]);
      expect(res.initPacketBase64).toBeDefined();
    });

    it('decodes line-delimited hex and base64 text', () => {
      const b64 = uint8ToBase64(Uint8Array.from([1, 2, 3]));
      const hex = 'deadbeef';
      const text = `${hex}\n${b64}`;

      const res = parseCapturePayload(text, 'capture.txt');
      expect(res.name).toBe('capture.bin');
      expect(res.base64Items).toHaveLength(2);
      expect(base64ToUint8(res.base64Items[0] ?? '')).toEqual(Uint8Array.from([0xde, 0xad, 0xbe, 0xef]));
      expect(base64ToUint8(res.base64Items[1] ?? '')).toEqual(Uint8Array.from([1, 2, 3]));
    });

    it('reports error on empty text file', () => {
      const res = parseCapturePayload('   \n  ', 'empty.txt');
      expect(res.error).toBe('Empty capture file');
      expect(res.base64Items).toHaveLength(0);
    });

    it('reports error on invalid JSON', () => {
      const res = parseCapturePayload('{ broken json', 'test.json');
      expect(res.error).toContain('Invalid JSON capture');
    });

    it('reports error on unrecognized line format', () => {
      const res = parseCapturePayload('not base64 and not valid hex!!!???', 'test.txt');
      expect(res.error).toContain('Unrecognized line format');
    });
  });
});
