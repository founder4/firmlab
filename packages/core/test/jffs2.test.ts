import { describe, expect, it } from 'vitest';
import { isJffs2Node } from '../src/jffs2.js';
import { scanSignaturesDetailed } from '../src/signatures.js';
import { inferIdentity } from '../src/structure.js';
import type { SignatureHit } from '../src/types.js';

function jffs2Hit(id: 'jffs2-le' | 'jffs2-be', offset: number): SignatureHit {
  return {
    id,
    offset,
    description: 'JFFS2 node',
    category: 'filesystem',
    confidence: 'medium',
  };
}

describe('JFFS2 node corroboration', () => {
  it.each([
    ['jffs2-le', [0x85, 0x19, 0x02, 0xe0]],
    ['jffs2-be', [0x19, 0x85, 0xe0, 0x02]],
  ] as const)('accepts a valid %s inode and promotes it to consistent', (id, bytes) => {
    const buf = Uint8Array.from(bytes);
    expect(isJffs2Node(buf, 0, id)).toBe(true);
    const scan = scanSignaturesDetailed(buf);
    expect(scan.hits).toMatchObject([{ id, tier: 'consistent', score: 85 }]);
    expect(scan.matched).toBe(1);
    expect(scan.rejected).toBe(0);
  });

  it.each([
    ['jffs2-le', [0x85, 0x19, 0x34, 0x12]],
    ['jffs2-be', [0x19, 0x85, 0x12, 0x34]],
  ] as const)('rejects incidental %s magic and preserves its denominator', (id, bytes) => {
    const buf = Uint8Array.from(bytes);
    expect(isJffs2Node(buf, 0, id)).toBe(false);
    const scan = scanSignaturesDetailed(buf);
    expect(scan.hits).toEqual([]);
    expect(scan.matched).toBe(1);
    expect(scan.rejected).toBe(1);
    expect(scan.rejectedByRule).toEqual({ [id]: 1 });
  });

  it('makes scanner and classifier agree while rechecking legacy hits', () => {
    const buf = new Uint8Array(2048);
    const offsets = [0, 128, 256, 384];
    for (const offset of offsets) buf.set([0x85, 0x19, 0x02, 0xe0], offset);
    buf.set([0x85, 0x19, 0x00, 0x00], 512);

    const scan = scanSignaturesDetailed(buf);
    expect(scan.hits.filter((hit) => hit.id === 'jffs2-le')).toHaveLength(4);
    expect(scan.rejectedByRule).toEqual({ 'jffs2-le': 1 });
    expect(inferIdentity(buf, scan.hits)).toMatchObject({ firmwareClass: 'embedded-linux', filesystems: ['jffs2'] });

    const legacyHits = [...scan.hits, jffs2Hit('jffs2-le', 512)];
    expect(inferIdentity(buf, legacyHits)).toEqual(inferIdentity(buf, scan.hits));
  });

  it('rejects before the listing cap and still retains a valid late JFFS2 rule', () => {
    const buf = new Uint8Array(4096);
    for (let offset = 0; offset < 2000; offset += 4) buf.set([0x85, 0x19, 0x00, 0x00], offset);
    buf.set([0x85, 0x19, 0x02, 0xe0], 3000);

    const scan = scanSignaturesDetailed(buf, { maxHits: 0 });
    expect(scan.hits).toMatchObject([{ id: 'jffs2-le', offset: 3000, tier: 'consistent' }]);
    expect(scan.matched).toBe(501);
    expect(scan.rejected).toBe(500);
    expect(scan.rejectedByRule).toEqual({ 'jffs2-le': 500 });
    expect(scan.distinctIds).toBe(1);
  });
});
