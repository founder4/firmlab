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
});
