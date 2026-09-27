import { describe, expect, it } from 'vitest';
import {
  base64ToUint8,
  detectMissingSequences,
  extractOtaImage,
  hexToUint8,
  inspectBleReassembly,
  inspectZigbeeReassembly,
  parseCapturePayload,
  parseDfuInitSize,
  parseZigbeeOtaHeader,
  uint8ToBase64,
} from './capture-reassembly';

function buildOta(
  image: Uint8Array,
  opts: { mfr?: number; imageType?: number; fileVersion?: number } = {},
): Uint8Array {
  const HEADER = 56;
  const sub = 6 + image.length;
  const buf = new Uint8Array(HEADER + sub);
  const dv = new DataView(buf.buffer);
  dv.setUint32(0, 0x0beef11e, true);
  dv.setUint16(4, 0x0100, true);
  dv.setUint16(6, HEADER, true);
  dv.setUint16(8, 0, true);
  dv.setUint16(10, opts.mfr ?? 0x1234, true);
  dv.setUint16(12, opts.imageType ?? 0x0001, true);
  dv.setUint32(14, opts.fileVersion ?? 0x00000003, true);
  dv.setUint16(18, 0x0002, true);
  for (let i = 0; i < 'TestFW'.length; i++) buf[20 + i] = 'TestFW'.charCodeAt(i);
  dv.setUint32(52, HEADER + sub, true);
  dv.setUint16(HEADER, 0x0000, true);
  dv.setUint32(HEADER + 2, image.length, true);
  buf.set(image, HEADER + 6);
  return buf;
}

describe('capture-reassembly pure utilities', () => {
  it('converts between uint8, base64, and hex', () => {
    const raw = Uint8Array.from([0xde, 0xad, 0xbe, 0xef]);
    const b64 = uint8ToBase64(raw);
    expect(base64ToUint8(b64)).toEqual(raw);
    const hex = 'deadbeef';
    expect(hexToUint8(hex)).toEqual(raw);
  });

  it('detects missing sequence numbers in block streams', () => {
    expect(detectMissingSequences([0, 1, 2, 3])).toEqual([]);
    expect(detectMissingSequences([0, 1, 3, 4, 6])).toEqual([2, 5]);
    expect(detectMissingSequences([5])).toEqual([]);
  });

  it('parses DFU init packet size', () => {
    const init = Uint8Array.from([0xde, 0xad, 0x00, 0xc0, 0x00, 0x00]);
    expect(parseDfuInitSize(init)).toBe(0xc000);
    expect(parseDfuInitSize(Uint8Array.from([1, 2]))).toBeNull();
  });

  it('parses Zigbee OTA header and unwraps upgrade image', () => {
    const image = Uint8Array.from([10, 20, 30, 40]);
    const ota = buildOta(image, { mfr: 0x115f, imageType: 0x0042, fileVersion: 7 });
    const h = parseZigbeeOtaHeader(ota);
    expect(h).not.toBeNull();
    expect(h?.manufacturerCode).toBe(0x115f);
    expect(h?.imageType).toBe(0x0042);
    expect(h?.fileVersion).toBe(7);
    expect(h?.headerString).toBe('TestFW');
    expect(h?.totalImageSize).toBe(56 + 6 + image.length);

    const extracted = extractOtaImage(ota);
    expect(extracted).not.toBeNull();
    expect(Array.from(extracted ?? [])).toEqual([10, 20, 30, 40]);
  });

  it('inspects complete BLE DFU reassembly against init packet', () => {
    const c1 = Uint8Array.from([1, 2, 3]);
    const c2 = Uint8Array.from([4, 5, 6]);
    // 6 bytes total
    const init = Uint8Array.from([0xde, 0xad, 0x06, 0x00, 0x00, 0x00]);
    const res = inspectBleReassembly([c1, c2], init);
    expect(res.reconstructedBytes).toBe(6);
    expect(res.chunkCount).toBe(2);
    expect(res.expectedSize).toBe(6);
    expect(res.missingBytes).toBe(0);
    expect(res.isComplete).toBe(true);
    expect(res.integrityValid).toBe(true);
  });

  it('inspects incomplete BLE DFU reassembly', () => {
    const c1 = Uint8Array.from([1, 2, 3]);
    // expected 10 bytes
    const init = Uint8Array.from([0xde, 0xad, 0x0a, 0x00, 0x00, 0x00]);
    const res = inspectBleReassembly([c1], init, null, [2]);
    expect(res.reconstructedBytes).toBe(3);
    expect(res.missingBytes).toBe(7);
    expect(res.missingSeqs).toEqual([2]);
    expect(res.isComplete).toBe(false);
    expect(res.integrityValid).toBe(false);
    expect(res.details.some((d) => d.includes('Missing 7 bytes'))).toBe(true);
    expect(res.details.some((d) => d.includes('Missing chunk sequence(s): #2'))).toBe(true);
  });

  it('inspects complete Zigbee OTA reassembly', () => {
    const image = Uint8Array.from([1, 2, 3, 4]);
    const ota = buildOta(image);
    const b1 = ota.subarray(0, 30);
    const b2 = ota.subarray(30);
    const res = inspectZigbeeReassembly([b1, b2]);
    expect(res.isComplete).toBe(true);
    expect(res.reconstructedBytes).toBe(ota.length);
    expect(res.missingBytes).toBe(0);
    expect(res.upgradeImageFound).toBe(true);
    expect(res.upgradeImageBytes).toBe(4);
    expect(res.integrityValid).toBe(true);
  });

  it('inspects incomplete/truncated Zigbee OTA reassembly', () => {
    const image = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]);
    const ota = buildOta(image);
    // Truncate before image data finishes
    const truncated = ota.subarray(0, 58);
    const res = inspectZigbeeReassembly([truncated]);
    expect(res.isComplete).toBe(false);
    expect(res.missingBytes).toBe(ota.length - 58);
    expect(res.details.some((d) => d.includes('Truncated file'))).toBe(true);
  });

  it('parses JSON upload payload with chunks array', () => {
    const json = JSON.stringify({
      name: 'dfu.bin',
      chunks: ['AQID', 'BAUG'],
    });
    const parsed = parseCapturePayload(json, 'capture.json');
    expect(parsed.name).toBe('dfu.bin');
    expect(parsed.base64Items).toEqual(['AQID', 'BAUG']);
    expect(parsed.chunksOrBlocks.length).toBe(2);
    expect(Array.from(parsed.chunksOrBlocks[0] ?? [])).toEqual([1, 2, 3]);
  });

  it('parses JSON upload payload with sequence numbers and detects gaps', () => {
    const json = JSON.stringify({
      chunks: [
        { seq: 0, data: 'AQID' },
        { seq: 2, data: 'BAUG' },
      ],
    });
    const parsed = parseCapturePayload(json, 'capture.json');
    expect(parsed.missingSeqs).toEqual([1]);
    expect(parsed.base64Items.length).toBe(2);
  });

  it('parses hex lines upload payload', () => {
    const hex = '010203\n040506';
    const parsed = parseCapturePayload(hex, 'stream.hex');
    expect(parsed.chunksOrBlocks.length).toBe(2);
    expect(Array.from(parsed.chunksOrBlocks[0] ?? [])).toEqual([1, 2, 3]);
  });
});
