import { describe, expect, it } from 'vitest';
import {
  FDT_MAGIC,
  decodeFdtValue,
  isPrintableStringList,
  nodeAt,
  parseFdt,
  propCells,
  propString,
  propStrings,
  propU32,
  readFdtHeader,
  readMemReservations,
  scanFdtCandidates,
  walkFdt,
} from './fdt.js';

// === A minimal FDT writer, so the fixtures are real flattened device trees rather than hand-typed byte arrays ===

/** One zero byte, built without ever typing a NUL literal into a source file. */
const NUL = Buffer.alloc(1);

function str(s: string): Buffer {
  return Buffer.concat([Buffer.from(s, 'ascii'), NUL]);
}
function strlist(...v: string[]): Buffer {
  return Buffer.concat(v.map(str));
}
function cells(...v: number[]): Buffer {
  const b = Buffer.alloc(v.length * 4);
  v.forEach((n, i) => b.writeUInt32BE(n >>> 0, i * 4));
  return b;
}
const EMPTY = Buffer.alloc(0);

interface NodeSpec {
  name: string;
  props?: [string, Buffer][];
  children?: NodeSpec[];
}

function pad4(b: Buffer): Buffer {
  const r = b.length % 4;
  return r === 0 ? b : Buffer.concat([b, Buffer.alloc(4 - r)]);
}
function token(t: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(t, 0);
  return b;
}

/** Serialize a node spec into a v17 FDT: header, one terminating memory-reserve entry, struct block, strings block. */
function buildFdt(root: NodeSpec, version = 17): Buffer {
  const names: string[] = [];
  const offsets = new Map<string, number>();
  let stringsLen = 0;
  const nameOff = (n: string): number => {
    const existing = offsets.get(n);
    if (existing !== undefined) return existing;
    const o = stringsLen;
    offsets.set(n, o);
    names.push(n);
    stringsLen += n.length + 1;
    return o;
  };

  const chunks: Buffer[] = [];
  const emit = (node: NodeSpec): void => {
    chunks.push(token(1), pad4(str(node.name)));
    for (const [n, v] of node.props ?? []) {
      const h = Buffer.alloc(8);
      h.writeUInt32BE(v.length, 0);
      h.writeUInt32BE(nameOff(n), 4);
      chunks.push(token(3), h, pad4(v));
    }
    for (const c of node.children ?? []) emit(c);
    chunks.push(token(2));
  };
  emit(root);
  chunks.push(token(9));

  const structBlock = Buffer.concat(chunks);
  const stringsBlock = Buffer.concat(names.map(str));
  const HEADER = 40;
  const memRsv = Buffer.alloc(16); // the terminating all-zero entry
  const offMemRsv = HEADER;
  const offStruct = offMemRsv + memRsv.length;
  const offStrings = offStruct + structBlock.length;
  const totalSize = offStrings + stringsBlock.length;

  const header = Buffer.alloc(HEADER);
  header.writeUInt32BE(FDT_MAGIC, 0);
  header.writeUInt32BE(totalSize, 4);
  header.writeUInt32BE(offStruct, 8);
  header.writeUInt32BE(offStrings, 12);
  header.writeUInt32BE(offMemRsv, 16);
  header.writeUInt32BE(version, 20);
  header.writeUInt32BE(16, 24);
  header.writeUInt32BE(0, 28);
  header.writeUInt32BE(stringsBlock.length, 32);
  header.writeUInt32BE(structBlock.length, 36);
  return Buffer.concat([header, memRsv, structBlock, stringsBlock]);
}

// A board tree shaped like the real ones in the corpus: a GL.iNet-style root, an `ok`-spelled UART, an alias and a
// /chosen console.
const BOARD = buildFdt({
  name: '',
  props: [
    ['#address-cells', cells(2)],
    ['#size-cells', cells(2)],
    ['model', str('GL.iNet BE3600, Inc. IPQ5332/AP-MI04.1-C2')],
    ['compatible', strlist('qcom,ipq5332-ap-mi04.1-c2', 'qcom,ipq5332')],
  ],
  children: [
    {
      name: 'clocks',
      children: [
        {
          name: 'sleep-clk',
          props: [
            ['compatible', str('fixed-clock')],
            // 32768 — the value whose two high bytes are zero, which a naive string test misreads.
            ['clock-frequency', cells(0x7d00)],
            ['#clock-cells', cells(0)],
          ],
        },
      ],
    },
    {
      name: 'soc',
      props: [
        ['#address-cells', cells(1)],
        ['#size-cells', cells(1)],
      ],
      children: [
        {
          name: 'serial@78af000',
          props: [
            ['compatible', strlist('qcom,msm-uartdm-v1.4', 'qcom,msm-uartdm')],
            ['reg', cells(0x78af000, 0x200)],
            ['status', str('ok')],
          ],
        },
      ],
    },
    { name: 'aliases', props: [['serial0', str('/soc/serial@78af000')]] },
    { name: 'chosen', props: [['stdout-path', str('serial0')]] },
  ],
});

describe('readFdtHeader', () => {
  it('reads a v17 header and its block offsets', () => {
    const h = readFdtHeader(BOARD, 0);
    expect(h).not.toBeNull();
    expect(h?.version).toBe(17);
    expect(h?.offMemReserve).toBe(40);
    expect(h?.offStruct).toBe(56);
    expect(h?.totalSize).toBe(BOARD.length);
  });

  it('rejects a magic match whose header is garbage — four bytes of coincidence is not a device tree', () => {
    // Exactly the shape of the three false hits in the IMOU-Ranger-2C image: correct magic, nonsense everywhere else.
    const fake = Buffer.alloc(256, 0x5a);
    fake.writeUInt32BE(FDT_MAGIC, 0);
    fake.writeUInt32BE(0xe4b7ffff, 4); // totalsize
    fake.writeUInt32BE(0xffe4b7ff, 20); // version
    expect(readFdtHeader(fake, 0)).toBeNull();
  });

  it('rejects a header whose struct block is misaligned or runs past totalsize', () => {
    const misaligned = Buffer.from(BOARD);
    misaligned.writeUInt32BE(57, 8); // off_dt_struct must be 4-aligned
    expect(readFdtHeader(misaligned, 0)).toBeNull();

    const overrun = Buffer.from(BOARD);
    overrun.writeUInt32BE(BOARD.length, 36); // size_dt_struct past the end
    expect(readFdtHeader(overrun, 0)).toBeNull();
  });

  it('rejects a header that claims more bytes than the buffer holds', () => {
    expect(readFdtHeader(BOARD.subarray(0, BOARD.length - 8), 0)).toBeNull();
  });

  it('derives the block sizes a pre-v17 header does not carry', () => {
    const v16 = buildFdt({ name: '', props: [['model', str('old board')]] }, 16);
    v16.writeUInt32BE(0, 36); // v16 has no size_dt_struct field
    const h = readFdtHeader(v16, 0);
    expect(h).not.toBeNull();
    expect(h?.sizeStruct).toBeGreaterThan(0);
    const parsed = parseFdt(v16, 0);
    expect(parsed?.outcome.complete).toBe(true);
    expect(propString(parsed?.root as never, 'model')).toBe('old board');
  });
});

describe('scanFdtCandidates', () => {
  it('finds an embedded tree at a non-zero offset and ignores a bare magic sequence', () => {
    const noise = Buffer.alloc(64, 0xff);
    noise.writeUInt32BE(FDT_MAGIC, 16); // magic with no valid header behind it
    const image = Buffer.concat([noise, BOARD, Buffer.alloc(32, 0)]);
    const hits = scanFdtCandidates(image);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.base).toBe(64);
  });
});

describe('walkFdt integrity', () => {
  it('reports a complete walk on a well-formed tree', () => {
    const h = readFdtHeader(BOARD, 0);
    const outcome = walkFdt(BOARD, h as never, {});
    expect(outcome.complete).toBe(true);
    expect(outcome.unnamedProps).toBe(0);
    expect(outcome.nodeCount).toBeGreaterThan(4);
  });

  it('refuses to call a walk complete when the token stream is corrupt', () => {
    const h = readFdtHeader(BOARD, 0);
    const broken = Buffer.from(BOARD);
    broken.writeUInt32BE(0x55424923, (h?.offStruct as number) + 8); // "UBI#" spliced over a token
    const outcome = walkFdt(broken, h as never, {});
    expect(outcome.complete).toBe(false);
    expect(outcome.stopReason).toMatch(/invalid token/i);
  });

  it('counts property names that do not resolve, so a clobbered strings block cannot pass as a tree', () => {
    const h = readFdtHeader(BOARD, 0) as NonNullable<ReturnType<typeof readFdtHeader>>;
    const clobbered = Buffer.from(BOARD);
    clobbered.fill(0xff, h.offStrings, h.offStrings + h.sizeStrings);
    const outcome = walkFdt(clobbered, h, {});
    // The struct block is untouched, so the walk still finishes — but every NAME is now unreadable, which is
    // precisely the GL.iNet raw-scan failure mode and is exactly what the header check cannot see.
    expect(outcome.complete).toBe(true);
    expect(outcome.unnamedProps).toBeGreaterThan(0);
  });
});

describe('decodeFdtValue — dtc typing, not a guess', () => {
  it('treats a zero-length property as the boolean its presence stands for', () => {
    expect(decodeFdtValue(EMPTY)).toEqual({ type: 'empty' });
  });

  it('splits a NUL-separated string list', () => {
    expect(decodeFdtValue(strlist('qcom,ipq5332-ap-mi04.1-c2', 'qcom,ipq5332'))).toEqual({
      type: 'stringlist',
      strings: ['qcom,ipq5332-ap-mi04.1-c2', 'qcom,ipq5332'],
    });
  });

  it('reads <0x7d00> as a cell, not a string — the high zero bytes fool the naive printable test', () => {
    expect(isPrintableStringList(cells(0x7d00))).toBe(false);
    expect(decodeFdtValue(cells(0x7d00))).toEqual({ type: 'cells', cells: [0x7d00] });
  });

  it('reads <0x0> as a cell, not a list of empty strings', () => {
    expect(isPrintableStringList(cells(0))).toBe(false);
    expect(decodeFdtValue(cells(0))).toEqual({ type: 'cells', cells: [0] });
  });

  it('falls back to a byte count for a value that is neither', () => {
    expect(decodeFdtValue(Buffer.from([0x01, 0x02, 0x03]))).toEqual({ type: 'bytes', length: 3 });
  });
});

describe('parseFdt', () => {
  const parsed = parseFdt(BOARD, 0);

  it('builds absolute node paths', () => {
    expect(parsed?.root.path).toBe('/');
    expect(nodeAt(parsed?.root as never, '/soc/serial@78af000')?.name).toBe('serial@78af000');
    expect(nodeAt(parsed?.root as never, '/soc/nope')).toBeUndefined();
  });

  it('reads root identity through the typed accessors', () => {
    const root = parsed?.root as never;
    expect(propString(root, 'model')).toBe('GL.iNet BE3600, Inc. IPQ5332/AP-MI04.1-C2');
    expect(propStrings(root, 'compatible')).toEqual(['qcom,ipq5332-ap-mi04.1-c2', 'qcom,ipq5332']);
    expect(propU32(root, '#address-cells')).toBe(2);
  });

  it('reads a multi-cell reg', () => {
    const uart = nodeAt(parsed?.root as never, '/soc/serial@78af000') as never;
    expect(propCells(uart, 'reg')).toEqual([0x78af000, 0x200]);
  });

  it('parses a tree embedded at a non-zero offset without slicing it out first', () => {
    const image = Buffer.concat([Buffer.alloc(1024, 0xff), BOARD]);
    const embedded = parseFdt(image, 1024);
    expect(embedded?.outcome.complete).toBe(true);
    expect(propString(embedded?.root as never, 'model')).toContain('GL.iNet');
  });

  it('aligns relative to the blob, not the buffer, so an odd embed offset still parses', () => {
    // Every FDT alignment is relative to the start of the blob. Aligning absolute positions instead happens to
    // work for every dtb in the corpus, because they all land on a multiple of 4 — and breaks the moment one does
    // not. Two of the three offsets below are deliberately not 4-aligned.
    for (const pad of [1022, 1023, 1024, 1025]) {
      const image = Buffer.concat([Buffer.alloc(pad, 0xff), BOARD]);
      const embedded = parseFdt(image, pad);
      expect(embedded?.outcome.complete, `embedded at ${pad}`).toBe(true);
      expect(embedded?.outcome.unnamedProps, `embedded at ${pad}`).toBe(0);
      expect(propString(embedded?.root as never, 'model')).toContain('GL.iNet');
    }
  });

  it('returns a partial tree with complete:false rather than throwing on a corrupt one', () => {
    const h = readFdtHeader(BOARD, 0) as NonNullable<ReturnType<typeof readFdtHeader>>;
    const broken = Buffer.from(BOARD);
    broken.writeUInt32BE(0x1000000, h.offStruct + 8);
    const partial = parseFdt(broken, 0);
    expect(partial).not.toBeNull();
    expect(partial?.outcome.complete).toBe(false);
  });
});

describe('readMemReservations', () => {
  it('stops at the terminating all-zero entry', () => {
    const h = readFdtHeader(BOARD, 0) as NonNullable<ReturnType<typeof readFdtHeader>>;
    expect(readMemReservations(BOARD, h)).toEqual([]);
  });

  it('reads a declared reservation', () => {
    const h = readFdtHeader(BOARD, 0) as NonNullable<ReturnType<typeof readFdtHeader>>;
    const withRsv = Buffer.from(BOARD);
    withRsv.writeUInt32BE(0, h.offMemReserve);
    withRsv.writeUInt32BE(0x4a000000, h.offMemReserve + 4);
    withRsv.writeUInt32BE(0, h.offMemReserve + 8);
    withRsv.writeUInt32BE(0x100000, h.offMemReserve + 12);
    expect(readMemReservations(withRsv, h)).toEqual([{ address: 0x4a000000, size: 0x100000 }]);
  });
});
