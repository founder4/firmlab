import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  type FitSubimage,
  parseFitImages,
  parseUbiVolumes,
  pickRootfsVolume,
  planCarve,
  runRecursiveCarve,
} from './carve.js';

const UBI_EC = 0x55424923; // "UBI#"
const UBI_VID = 0x55424921; // "UBI!"
const FDT_BEGIN_NODE = 0x1;
const FDT_END_NODE = 0x2;
const FDT_PROP = 0x3;
const FDT_END = 0x9;
const HSQS = [0x68, 0x73, 0x71, 0x73]; // SquashFS little-endian magic

function writeBE32(b: Uint8Array, o: number, v: number): void {
  b[o] = (v >>> 24) & 0xff;
  b[o + 1] = (v >>> 16) & 0xff;
  b[o + 2] = (v >>> 8) & 0xff;
  b[o + 3] = v & 0xff;
}
function writeBE16(b: Uint8Array, o: number, v: number): void {
  b[o] = (v >>> 8) & 0xff;
  b[o + 1] = v & 0xff;
}
function be32bytes(n: number): number[] {
  return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
}

/** Build a minimal but valid UBI image: PEB0 = layout volume (names), one PEB per user volume. */
function buildUbi(opts: {
  pebSize: number;
  vidOff: number;
  dataOff: number;
  vols: { volId: number; lnum: number; data: number[] }[];
  names?: Record<number, string>;
}): Uint8Array {
  const { pebSize, vidOff, dataOff } = opts;
  const buf = new Uint8Array((1 + opts.vols.length) * pebSize);
  const ec = (start: number): void => {
    writeBE32(buf, start, UBI_EC);
    writeBE32(buf, start + 0x10, vidOff);
    writeBE32(buf, start + 0x14, dataOff);
  };
  const vid = (start: number, volId: number, lnum: number): void => {
    writeBE32(buf, start + vidOff, UBI_VID);
    writeBE32(buf, start + vidOff + 0x08, volId);
    writeBE32(buf, start + vidOff + 0x0c, lnum);
  };
  // PEB0 — the layout volume (vol id 0x7fffefff), carrying the volume-table name records.
  ec(0);
  vid(0, 0x7fffefff, 0);
  for (const [idStr, name] of Object.entries(opts.names ?? {})) {
    const rec = dataOff + Number(idStr) * 172;
    writeBE16(buf, rec + 0x0e, name.length);
    for (let i = 0; i < name.length; i++) buf[rec + 0x10 + i] = name.charCodeAt(i);
  }
  // One PEB per user volume.
  opts.vols.forEach((v, idx) => {
    const start = (idx + 1) * pebSize;
    ec(start);
    vid(start, v.volId, v.lnum);
    buf.set(v.data, start + dataOff);
  });
  return buf;
}

/** Build a minimal FIT/FDT with the given `/images/<name>` sub-images (each with a `type` + inlined `data`). */
function buildFit(images: { name: string; type: string; data: number[] }[]): Uint8Array {
  const strBlock: number[] = [];
  const strMap = new Map<string, number>();
  const intern = (s: string): number => {
    const hit = strMap.get(s);
    if (hit !== undefined) return hit;
    const off = strBlock.length;
    for (const c of s) strBlock.push(c.charCodeAt(0));
    strBlock.push(0);
    strMap.set(s, off);
    return off;
  };
  const struct: number[] = [];
  const pad4 = (): void => {
    while (struct.length % 4 !== 0) struct.push(0);
  };
  const beginNode = (name: string): void => {
    struct.push(...be32bytes(FDT_BEGIN_NODE));
    for (const c of name) struct.push(c.charCodeAt(0));
    struct.push(0);
    pad4();
  };
  const endNode = (): void => {
    struct.push(...be32bytes(FDT_END_NODE));
  };
  const prop = (name: string, value: number[]): void => {
    struct.push(...be32bytes(FDT_PROP), ...be32bytes(value.length), ...be32bytes(intern(name)), ...value);
    pad4();
  };

  beginNode(''); // root
  beginNode('images');
  for (const img of images) {
    beginNode(img.name);
    prop('type', [...img.type].map((c) => c.charCodeAt(0)).concat(0));
    prop('data', img.data);
    endNode();
  }
  endNode(); // images
  endNode(); // root
  struct.push(...be32bytes(FDT_END));

  const HEADER = 40;
  const offStruct = HEADER;
  const offStrings = HEADER + struct.length;
  const total = offStrings + strBlock.length;
  const out = new Uint8Array(total);
  writeBE32(out, 0, 0xd00dfeed); // magic
  writeBE32(out, 4, total);
  writeBE32(out, 8, offStruct);
  writeBE32(out, 12, offStrings);
  writeBE32(out, 32, strBlock.length); // size_dt_strings
  writeBE32(out, 36, struct.length); // size_dt_struct
  out.set(struct, offStruct);
  out.set(strBlock, offStrings);
  return out;
}

describe('parseFitImages', () => {
  it('enumerates sub-images with the absolute range of their inlined data', () => {
    const ubiBytes = [...be32bytes(UBI_EC), 1, 2, 3, 4];
    const fit = buildFit([
      { name: 'ubi', type: 'firmware', data: ubiBytes },
      { name: 'script', type: 'script', data: [0xaa, 0xbb] },
    ]);
    const images = parseFitImages(fit);
    expect(images.map((i) => i.name)).toEqual(['ubi', 'script']);
    const ubi = images.find((i) => i.name === 'ubi') as FitSubimage;
    expect(ubi.type).toBe('firmware');
    expect(ubi.dataSize).toBe(ubiBytes.length);
    // The recorded offset must point at the actual inlined bytes.
    expect([...fit.subarray(ubi.dataOffset, ubi.dataOffset + 4)]).toEqual(be32bytes(UBI_EC));
  });

  it('returns [] for a non-FIT buffer', () => {
    expect(parseFitImages(new Uint8Array([1, 2, 3, 4]))).toEqual([]);
  });
});

describe('parseUbiVolumes + pickRootfsVolume', () => {
  const ubi = buildUbi({
    pebSize: 512,
    vidOff: 64,
    dataOff: 128,
    names: { 0: 'ubi_rootfs', 1: 'rootfs_data' },
    vols: [
      { volId: 0, lnum: 0, data: [...HSQS, ...Array(60).fill(0xa5)] }, // the SquashFS rootfs
      { volId: 1, lnum: 0, data: Array(40).fill(0) }, // the empty UBIFS overlay that aborts the reference tool
    ],
  });

  it('reassembles per-volume LEBs and recovers names, skipping the empty overlay instead of aborting', () => {
    const volumes = parseUbiVolumes(ubi);
    expect(volumes.map((v) => v.volId)).toEqual([0, 1]);
    expect(volumes[0]?.name).toBe('ubi_rootfs');
    expect(volumes[1]?.name).toBe('rootfs_data');
    expect([...(volumes[0]?.data.subarray(0, 4) ?? [])]).toEqual(HSQS);
  });

  it('picks the SquashFS volume as the rootfs (never the overlay)', () => {
    const pick = pickRootfsVolume(parseUbiVolumes(ubi));
    expect(pick.isSquashfs).toBe(true);
    expect(pick.volume?.volId).toBe(0);
    expect(pick.reason).toMatch(/ubi_rootfs/);
  });

  it('degrades honestly when no volume is SquashFS', () => {
    const noRootfs = buildUbi({
      pebSize: 512,
      vidOff: 64,
      dataOff: 128,
      vols: [{ volId: 0, lnum: 0, data: Array(40).fill(0) }],
    });
    const pick = pickRootfsVolume(parseUbiVolumes(noRootfs));
    expect(pick.isSquashfs).toBe(false);
    expect(pick.reason).toMatch(/no SquashFS/);
  });
});

describe('planCarve — recursive FIT → UBI → SquashFS', () => {
  const ubi = buildUbi({
    pebSize: 512,
    vidOff: 64,
    dataOff: 128,
    names: { 0: 'ubi_rootfs' },
    vols: [{ volId: 0, lnum: 0, data: [...HSQS, ...Array(60).fill(0xa5)] }],
  });

  it('carves a FIT(firmware=ubi) all the way to the SquashFS rootfs volume', () => {
    const fit = buildFit([
      { name: 'ubi', type: 'firmware', data: [...ubi] }, // type is 'firmware' like GL.iNet — matched by UBI magic
      { name: 'script', type: 'script', data: [0, 1] },
    ]);
    const plan = planCarve(fit);
    expect(plan.terminalFormat).toBe('squashfs');
    expect(plan.squashfs).not.toBeNull();
    expect([...(plan.squashfs?.subarray(0, 4) ?? [])]).toEqual(HSQS);
    expect(plan.trace.map((s) => s.format)).toEqual(['fit', 'ubi', 'squashfs']);
  });

  it('stops with an honest reason when the UBI has no SquashFS volume', () => {
    const emptyUbi = buildUbi({
      pebSize: 512,
      vidOff: 64,
      dataOff: 128,
      vols: [{ volId: 0, lnum: 0, data: Array(40).fill(0) }],
    });
    const fit = buildFit([{ name: 'ubi', type: 'firmware', data: [...emptyUbi] }]);
    const plan = planCarve(fit);
    expect(plan.squashfs).toBeNull();
    expect(plan.terminalFormat).toBe('ubi');
    expect(plan.terminalReason).toMatch(/no SquashFS/);
  });
});

describe('runRecursiveCarve — honest degradation', () => {
  it('reports the carved SquashFS but no rootfs dir when it cannot be extracted', async () => {
    const ubi = buildUbi({
      pebSize: 512,
      vidOff: 64,
      dataOff: 128,
      names: { 0: 'ubi_rootfs' },
      vols: [{ volId: 0, lnum: 0, data: [...HSQS, ...Array(60).fill(0xa5)] }],
    });
    const fit = buildFit([{ name: 'ubi', type: 'firmware', data: [...ubi] }]);
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'carve-'));
    try {
      const imagePath = path.join(dir, 'image.bin');
      fs.writeFileSync(imagePath, fit);
      const logs: string[] = [];
      const result = await runRecursiveCarve(imagePath, path.join(dir, 'out'), { log: (l) => logs.push(l) });
      // The SquashFS volume was carved (a real, non-empty artifact) even though a 60-byte fake cannot be
      // extracted by any real unsquashfs — so rootfsDir stays null with an honest reason, never a silent empty.
      expect(result.squashfsPath).not.toBeNull();
      expect(result.rootfsDir).toBeNull();
      expect(result.terminalReason).toBeTruthy();
      expect(result.trace.map((s) => s.format)).toEqual(['fit', 'ubi', 'squashfs']);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('stops honestly on a blob it cannot carve at all', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'carve-'));
    try {
      const imagePath = path.join(dir, 'image.bin');
      fs.writeFileSync(imagePath, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]));
      const result = await runRecursiveCarve(imagePath, path.join(dir, 'out'), { log: () => {} });
      expect(result.squashfsPath).toBeNull();
      expect(result.rootfsDir).toBeNull();
      expect(result.terminalReason).toBeTruthy();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
