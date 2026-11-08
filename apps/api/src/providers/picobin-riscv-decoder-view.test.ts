import { describe, expect, it } from 'vitest';
import { buildPicobinRiscvDecoderView, restoredPicobinOpcode } from './picobin-riscv-decoder-view.js';

describe('buildPicobinRiscvDecoderView', () => {
  it('replaces only exact RV32 BSET and Zba shift-add encodings with same-length NOPs', () => {
    const image = Uint8Array.from([
      0xb3,
      0x16,
      0xa0,
      0x28, // bset x13, x0, x10
      0xb3,
      0x47,
      0xf5,
      0x20, // sh2add x15, x10, x15
      0x33,
      0x65,
      0xc5,
      0x20, // sh3add x10, x10, x12
      0x13,
      0x00,
      0x00,
      0x00,
    ]);
    const view = buildPicobinRiscvDecoderView(image, image.byteLength, {
      entryPoint: 0x2000_0362,
      entryFileOffset: 0,
      mappedRuntimeEnd: 0x2000_0362 + image.byteLength,
    });

    expect(view).not.toBeNull();
    expect(Array.from(view?.bytes ?? [])).toEqual([
      0x13, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00,
    ]);
    expect(view?.substitutions).toEqual([
      {
        address: 0x2000_0362,
        fileOffset: 0,
        instruction: 'bset',
        originalBytesHex: 'b316a028',
      },
      {
        address: 0x2000_0366,
        fileOffset: 4,
        instruction: 'sh2add',
        originalBytesHex: 'b347f520',
      },
      {
        address: 0x2000_036a,
        fileOffset: 8,
        instruction: 'sh3add',
        originalBytesHex: '3365c520',
      },
    ]);
    const bset = view?.substitutions[0];
    const sh2add = view?.substitutions[1];
    const sh3add = view?.substitutions[2];
    expect(bset).toBeDefined();
    expect(sh2add).toBeDefined();
    expect(sh3add).toBeDefined();
    if (!bset || !sh2add || !sh3add) return;
    expect(restoredPicobinOpcode(bset)).toBe('bset x13, x0, x10');
    expect(restoredPicobinOpcode(sh2add)).toBe('sh2add x15, x10, x15');
    expect(restoredPicobinOpcode(sh3add)).toBe('sh3add x10, x10, x12');
    expect(image[0]).toBe(0xb3);
  });

  it('refuses partial files and near-miss encodings', () => {
    const nearMiss = Uint8Array.from([0xb3, 0x16, 0xa0, 0x2a]);
    const mapping = { entryPoint: 0x1000_0000, entryFileOffset: 0, mappedRuntimeEnd: 0x1000_0004 };
    expect(buildPicobinRiscvDecoderView(nearMiss, nearMiss.byteLength, mapping)).toBeNull();
    expect(buildPicobinRiscvDecoderView(nearMiss, nearMiss.byteLength + 1, mapping)).toBeNull();
  });

  it('preserves a JAL whose upper parcel and following instruction resemble BSET', () => {
    const image = Uint8Array.from([
      0xb3,
      0x16,
      0xa0,
      0x28, // real BSET at entry: makes the fallback eligible
      0x6f,
      0x00,
      0xb3,
      0x16, // JAL: its upper half is NOT an instruction start
      0xa0,
      0x28, // a 16-bit parcel; offset 6 would look like BSET across the boundary
      0x01,
      0x00, // C.NOP
      0xb3,
      0x16,
      0xa0,
      0x28, // another real BSET
    ]);
    const original = image.slice();
    const view = buildPicobinRiscvDecoderView(image, image.length, {
      entryPoint: 0x1000_0000,
      entryFileOffset: 0,
      mappedRuntimeEnd: 0x1000_0000 + image.length,
    });
    expect(view?.substitutions.map((row) => row.fileOffset)).toEqual([0, 12]);
    expect(view?.bytes.slice(4, 12)).toEqual(original.slice(4, 12));
    expect(image).toEqual(original);
    expect(view?.bytesExamined).toBe(image.length);
  });

  it('recognizes a 32-bit instruction after a compressed instruction at a halfword boundary', () => {
    const image = Uint8Array.from([0x01, 0x00, 0xb3, 0x16, 0xa0, 0x28]);
    const view = buildPicobinRiscvDecoderView(image, image.length, {
      entryPoint: 0x2000_0000,
      entryFileOffset: 0,
      mappedRuntimeEnd: 0x2000_0000 + image.length,
    });
    expect(view?.substitutions.map((row) => row.address)).toEqual([0x2000_0002]);
    expect(view?.bytes.slice(0, 2)).toEqual(image.slice(0, 2));
  });

  it('stops at longer/reserved or incomplete encodings and reports only the examined prefix', () => {
    for (const suffix of [
      [0x1f, 0x00, 0xb3, 0x16, 0xa0, 0x28], // 48-bit prefix
      [0x3f, 0x00, 0xb3, 0x16, 0xa0, 0x28, 0x01, 0x00], // 64-bit prefix
      [0xff, 0xff, 0xb3, 0x16, 0xa0, 0x28], // reserved longer prefix
      [0xb3, 0x16], // incomplete 32-bit instruction
    ]) {
      const image = Uint8Array.from([0xb3, 0x16, 0xa0, 0x28, ...suffix]);
      const view = buildPicobinRiscvDecoderView(image, image.length, {
        entryPoint: 0x1000_0000,
        entryFileOffset: 0,
        mappedRuntimeEnd: 0x1000_0000 + image.length,
      });
      expect(view?.substitutions.map((row) => row.fileOffset)).toEqual([0]);
      expect(view?.bytesExamined).toBe(4);
      expect(view?.bytes.slice(4)).toEqual(image.slice(4));
    }
  });

  it('reports the actual prefix when the substitution cap ends the walk', () => {
    const image = Uint8Array.from(Array.from({ length: 100 }, () => [0xb3, 0x16, 0xa0, 0x28]).flat());
    const view = buildPicobinRiscvDecoderView(image, image.length, {
      entryPoint: 0x1000_0000,
      entryFileOffset: 0,
      mappedRuntimeEnd: 0x1000_0000 + image.length,
    });
    expect(view?.substitutions).toHaveLength(64);
    expect(view?.bytesExamined).toBe(256);
    expect(view?.bytes.slice(256)).toEqual(image.slice(256));
  });

  it('refuses a misaligned runtime entry and nonintegral mapping bounds', () => {
    const image = Uint8Array.from([0xb3, 0x16, 0xa0, 0x28]);
    const mapping = { entryPoint: 0x1000_0000, entryFileOffset: 0, mappedRuntimeEnd: 0x1000_0004 };
    for (const invalid of [
      { ...mapping, entryPoint: 0x1000_0001 },
      { ...mapping, entryFileOffset: 0.5 },
      { ...mapping, mappedRuntimeEnd: 0x1000_0004 + 0.5 },
      { ...mapping, mappedRuntimeEnd: Number.POSITIVE_INFINITY },
    ]) {
      expect(buildPicobinRiscvDecoderView(image, image.length, invalid)).toBeNull();
    }
  });
});
