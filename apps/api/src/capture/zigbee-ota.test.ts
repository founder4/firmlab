import { describe, expect, it } from 'vitest';
import { extractOtaImage, parseZigbeeOtaHeader, reassembleOtaBlocks } from './zigbee-ota.js';

/** Build a minimal but spec-shaped Zigbee OTA file wrapping `image` as the tag-0x0000 sub-element. */
function buildOta(
  image: Uint8Array,
  opts: { mfr?: number; imageType?: number; fileVersion?: number } = {},
): Uint8Array {
  const HEADER = 56;
  const sub = 6 + image.length; // tag(2) + len(4) + data
  const buf = new Uint8Array(HEADER + sub);
  const dv = new DataView(buf.buffer);
  dv.setUint32(0, 0x0beef11e, true); // magic
  dv.setUint16(4, 0x0100, true); // header version
  dv.setUint16(6, HEADER, true); // header length
  dv.setUint16(8, 0, true); // field control
  dv.setUint16(10, opts.mfr ?? 0x1234, true);
  dv.setUint16(12, opts.imageType ?? 0x0001, true);
  dv.setUint32(14, opts.fileVersion ?? 0x00000003, true);
  dv.setUint16(18, 0x0002, true); // stack version
  for (let i = 0; i < 'TestFW'.length; i++) buf[20 + i] = 'TestFW'.charCodeAt(i);
  dv.setUint32(52, HEADER + sub, true); // total image size
  // sub-element: tag 0x0000, length, data
  dv.setUint16(HEADER, 0x0000, true);
  dv.setUint32(HEADER + 2, image.length, true);
  buf.set(image, HEADER + 6);
  return buf;
}

describe('reassembleOtaBlocks', () => {
  it('concatenates the Image-Block payloads back into the OTA file', () => {
    const full = buildOta(Uint8Array.from([1, 2, 3, 4]));
    const blocks: Uint8Array[] = [];
    for (let i = 0; i < full.length; i += 16) blocks.push(full.subarray(i, i + 16));
    expect(Array.from(reassembleOtaBlocks(blocks))).toEqual(Array.from(full));
  });
});

describe('parseZigbeeOtaHeader', () => {
  it('parses the standardized header fields', () => {
    const h = parseZigbeeOtaHeader(
      buildOta(Uint8Array.from([9, 9]), { mfr: 0x115f, imageType: 0x0042, fileVersion: 7 }),
    );
    expect(h).not.toBeNull();
    expect(h?.manufacturerCode).toBe(0x115f);
    expect(h?.imageType).toBe(0x0042);
    expect(h?.fileVersion).toBe(7);
    expect(h?.headerString).toBe('TestFW');
  });
  it('rejects a stream that is not a Zigbee OTA file (bad magic)', () => {
    expect(parseZigbeeOtaHeader(Uint8Array.from([0x68, 0x73, 0x71, 0x73, 0, 0, 0, 0]))).toBeNull();
    expect(parseZigbeeOtaHeader(new Uint8Array(10))).toBeNull();
  });
});

describe('extractOtaImage', () => {
  it('unwraps the container to the tag-0x0000 upgrade image, byte-exact', () => {
    const image = Uint8Array.from({ length: 40 }, (_, i) => (i * 7) & 0xff);
    const img = extractOtaImage(buildOta(image));
    expect(img).not.toBeNull();
    expect(Array.from(img as Uint8Array)).toEqual(Array.from(image));
  });
  it('returns null when there is no upgrade-image sub-element', () => {
    // A valid header with the sub-element tag flipped to 0x0001 (not the image tag).
    const ota = buildOta(Uint8Array.from([1, 2, 3]));
    ota[56] = 0x01; // tag low byte → 0x0001
    expect(extractOtaImage(ota)).toBeNull();
  });
});
