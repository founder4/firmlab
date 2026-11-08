import { describe, expect, it } from 'vitest';
import {
  buildPicobinRiscvDecoderView,
  restoredPicobinOpcode,
  selectPicobinDecoderCandidates,
} from './picobin-riscv-decoder-view.js';

describe('buildPicobinRiscvDecoderView', () => {
  it('replaces only exact RV32 BSET and Zba shift-add encodings with same-length discarded-destination MOVs', () => {
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
      0x13, 0x80, 0x00, 0x00, 0x13, 0x80, 0x00, 0x00, 0x13, 0x80, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00,
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

  it('clamps a larger backing buffer to the declared file and refuses a short prefix', () => {
    const image = Uint8Array.from([0xb3, 0x16, 0xa0, 0x28, 0xb3, 0x16, 0xa0, 0x28]);
    const mapping = { entryPoint: 0x1000_0000, entryFileOffset: 0, mappedRuntimeEnd: 0x1000_0008 };
    const view = buildPicobinRiscvDecoderView(image, 4, mapping);
    expect(view?.bytes).toHaveLength(4);
    expect(view?.bytesExamined).toBe(4);
    expect(view?.substitutions).toHaveLength(1);
    expect(buildPicobinRiscvDecoderView(image, 12, mapping)).toBeNull();
  });

  it('treats linear matches after inline data as provisional rather than proven instruction starts', () => {
    const image = Uint8Array.from(Buffer.from('11a00300130533100128b316a0288280', 'hex'));
    const view = buildPicobinRiscvDecoderView(image, image.length, {
      entryPoint: 0x1000_0000,
      entryFileOffset: 0,
      mappedRuntimeEnd: 0x1000_0000 + image.length,
    });
    // Offset 6 straddles the actual ADDI and c.jal. The provider must reject the entire recovered decode.
    expect(view?.substitutions.map((row) => row.fileOffset)).toEqual([6, 10]);
    expect(Buffer.from(image).toString('hex')).toBe('11a00300130533100128b316a0288280');
  });
});

describe('selectPicobinDecoderCandidates', () => {
  const entry = 0x1000_0000;
  const at = (hex: string): { image: Uint8Array; mapping: typeof base } => {
    const image = Uint8Array.from(Buffer.from(hex, 'hex'));
    return { image, mapping: { ...base, mappedRuntimeEnd: entry + image.length } };
  };
  const base = { entryPoint: entry, entryFileOffset: 0, mappedRuntimeEnd: entry };
  const BSET = 'b316a028';

  it('is exactly the legacy linear walk without evidence', () => {
    const { image, mapping } = at('11a00300130533100128b316a0288280');
    const selection = selectPicobinDecoderCandidates(image, image.length, mapping);
    expect(selection?.substitutions.map((row) => row.fileOffset)).toEqual([6, 10]);
    expect(selection?.substitutions.every((row) => row.candidateBasis === undefined)).toBe(true);
    expect(selection?.exclusions).toEqual([]);
  });

  it('withholds a proposal overlapping a known instruction and keeps the separately corroborated stop', () => {
    const { image, mapping } = at('11a00300130533100128b316a0288280');
    const evidence = {
      knownInstructions: [
        { address: entry, size: 2 },
        { address: entry + 4, size: 4 },
        { address: entry + 8, size: 2 },
      ],
      boundaries: [entry + 4, entry + 10, entry + 0x18],
    };
    const selection = selectPicobinDecoderCandidates(image, image.length, mapping, evidence);
    expect(selection?.substitutions).toEqual([
      {
        address: entry + 10,
        fileOffset: 10,
        instruction: 'bset',
        originalBytesHex: BSET,
        candidateBasis: 'corroborated-boundary',
      },
    ]);
    expect(selection?.exclusions).toEqual([
      {
        address: entry + 6,
        fileOffset: 6,
        instruction: 'bset',
        originalBytesHex: '33100128',
        reason: 'known-instruction-overlap',
        conflictAddress: entry + 4,
      },
    ]);
    const view = buildPicobinRiscvDecoderView(image, image.length, mapping, evidence);
    expect(Buffer.from(view?.bytes.subarray(0, 10) ?? []).toString('hex')).toBe('11a00300130533100128');
    expect(view?.stop).toBe('window-end');
  });

  it('keeps proposals adjacent to known instructions and boundaries, refusing only a real straddle', () => {
    // 0: known NOP | 4: BSET (starts at known end) | 8: BSET (ends at known start) | 12: known NOP
    const adjacent = at(`13000000${BSET}${BSET}13000000`);
    const known = [
      { address: entry, size: 4 },
      { address: entry + 12, size: 4 },
    ];
    expect(
      selectPicobinDecoderCandidates(adjacent.image, adjacent.image.length, adjacent.mapping, {
        knownInstructions: known,
        boundaries: [entry + 8],
      })?.substitutions.map((row) => [row.fileOffset, row.candidateBasis]),
    ).toEqual([
      [4, 'corroborated-boundary'],
      [8, 'corroborated-boundary'],
    ]);
    // A known instruction starting two bytes into the proposal is a proved overlap.
    const overlap = at(`${BSET}13000000`);
    const overlapped = selectPicobinDecoderCandidates(overlap.image, overlap.image.length, overlap.mapping, {
      knownInstructions: [{ address: entry + 2, size: 2 }],
      boundaries: [],
    });
    // Width must agree with the source: 0xa0 0x28 at offset 2 is a compressed parcel, so the known row stands.
    expect(overlapped?.substitutions).toEqual([]);
    expect(overlapped?.exclusions).toMatchObject([{ fileOffset: 0, reason: 'known-instruction-overlap' }]);
    // A reported non-instruction boundary at +2 (a branch target) is a bisection, not an overlap.
    const bisected = selectPicobinDecoderCandidates(overlap.image, overlap.image.length, overlap.mapping, {
      knownInstructions: [],
      boundaries: [entry + 2],
    });
    expect(bisected?.substitutions).toEqual([]);
    expect(bisected?.exclusions).toMatchObject([
      { fileOffset: 0, reason: 'known-boundary-bisected', conflictAddress: entry + 2 },
    ]);
  });

  it('labels a legacy proposal reached only after its phase was disproved as unanchored, not as data', () => {
    // Legacy: 0 c.j | 2..6 straddles the reported target 4 | 6..10 | 10 BSET. Anchored: 0 | 4..8 | 8..12 | 12.
    const { image, mapping } = at('11a00300130013001300b316a028');
    const selection = selectPicobinDecoderCandidates(image, image.length, mapping, {
      knownInstructions: [{ address: entry, size: 2 }],
      boundaries: [entry + 4],
    });
    expect(selectPicobinDecoderCandidates(image, image.length, mapping)?.substitutions[0]?.fileOffset).toBe(10);
    expect(selection?.substitutions).toEqual([]);
    expect(selection?.exclusions).toEqual([expect.objectContaining({ fileOffset: 10, reason: 'unanchored-phase' })]);
    expect(selection?.exclusions[0]?.conflictAddress).toBeUndefined();
    expect(selection?.resynchronizations).toBe(1);
  });

  it('resumes after an unsupported non-boundary parcel only at a later reported boundary', () => {
    // 0: BSET | 4: 48-bit prefix (data or unsupported) | 6: two halfwords | 8: BSET at a reported target
    const { image, mapping } = at(`${BSET}1f000000${BSET}`);
    const resumed = selectPicobinDecoderCandidates(image, image.length, mapping, {
      knownInstructions: [],
      boundaries: [entry + 8],
    });
    expect(resumed?.substitutions.map((row) => [row.fileOffset, row.candidateBasis])).toEqual([
      [0, 'corroborated-boundary'],
      [8, 'corroborated-boundary'],
    ]);
    expect(resumed?.stop).toBe('window-end');
    // No later boundary, or the unsupported parcel is itself a reported start: stop as the legacy walk does.
    for (const boundaries of [[], [entry + 4]]) {
      const stopped = selectPicobinDecoderCandidates(image, image.length, mapping, {
        knownInstructions: [],
        boundaries,
      });
      expect(stopped?.substitutions.map((row) => row.fileOffset)).toEqual([0]);
      expect(stopped?.stop).toBe('unsupported-encoding');
      expect(stopped?.bytesExamined).toBe(4);
    }
  });

  it('refuses every candidate when known rows contradict the source width or overlap each other', () => {
    const { image, mapping } = at(`01000100${BSET}`);
    for (const knownInstructions of [
      [{ address: entry, size: 4 }],
      [
        { address: entry, size: 2 },
        { address: entry + 1, size: 2 },
      ],
      [{ address: entry + 0x100, size: 4 }],
    ]) {
      const selection = selectPicobinDecoderCandidates(image, image.length, mapping, {
        knownInstructions,
        boundaries: [],
      });
      expect(selection).toMatchObject({ substitutions: [], stop: 'inconsistent-source-evidence' });
      expect(
        buildPicobinRiscvDecoderView(image, image.length, mapping, { knownInstructions, boundaries: [] }),
      ).toBeNull();
    }
  });

  it('keeps the substitution cap and the 4 KiB window with evidence', () => {
    const many = at(BSET.repeat(100));
    const capped = selectPicobinDecoderCandidates(many.image, many.image.length, many.mapping, {
      knownInstructions: [],
      boundaries: [entry + 400],
    });
    expect(capped?.substitutions).toHaveLength(64);
    expect(capped?.stop).toBe('substitution-cap');
    expect(capped?.bytesExamined).toBe(256);
    const wide = new Uint8Array(4100);
    wide.set(Buffer.from(BSET, 'hex'), 0);
    wide.set(Buffer.from(BSET, 'hex'), 4096);
    const windowed = selectPicobinDecoderCandidates(
      wide,
      wide.length,
      { ...base, mappedRuntimeEnd: entry + wide.length },
      { knownInstructions: [], boundaries: [entry + 4096] },
    );
    expect(windowed?.substitutions.map((row) => row.fileOffset)).toEqual([0]);
    expect(windowed?.bytesExamined).toBe(4096);
  });
});
