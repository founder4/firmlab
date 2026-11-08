import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { type StaticAnalysis, analyzeBuffer } from '../src/analyze.js';
import { parseMediaTekBromHeader } from '../src/mediatek-image.js';
import {
  SIGNATURE_DIGEST_MAX_BYTES,
  SIGNATURE_DIGEST_MAX_EXECUTIONS,
  type SignatureDigestOptions,
  planMediaTekDigest,
  verifySignatureDigests,
} from '../src/signature-digests.js';
import { scanSignaturesDetailed } from '../src/signatures.js';
import type { SignatureHit } from '../src/types.js';

const BROM_NOR_BASE64 =
  'U0ZfQk9PVAD/////AQAAAAACAAD/////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '//////////////////////////////////////////////////////////////////////////////////9CUkxZVAAAAAEAAAAA' +
  'BgAAIQoAAEJCQkIHAAEAAAYAACEKAAD/////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////////////////////////////////////////////////////////' +
  '////////////////////////////////////////////////TU1NATgAAABGSUxFX0lORk8AAAABAAAAAQAFAQANIAAhBAAAIQoA' +
  'AAADAAAgAAAAAAMAAAEAAABNTU0BDAABAAEAAABNTU0DZAAHAJABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiBMAAAAAAAAAAAAATU1NARQCAwAAAAAAAAAAAAAAAAAA' +
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE1NTQEUAAIAAAAAABAA' +
  'AACAAAAATU1NATAACAADAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAECAwQFBgcICQoLDA0ODxAREhMU' +
  'FRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f' +
  'YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmq' +
  'q6ytrq+wsbKztLW2t7i5uru8vb6/wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t/g4eLj5OXm5+jp6uvs7e7v8PHy8/T1' +
  '9vf4+fr7/P3+/6VLLq1qkzlkvEucrCqMfLJX0ImhBSdIuZd/s2MRyA02Tw==';

const sha256 = (bytes: Uint8Array): Uint8Array => createHash('sha256').update(bytes).digest();
function fixture(): Uint8Array {
  const bytes = Uint8Array.from(Buffer.from(BROM_NOR_BASE64, 'base64'));
  expect(createHash('sha256').update(bytes).digest('hex')).toBe(
    'e90664dda0beec0b9af8e8dfc17a693407e711128caef3e75f0059815464c9e9',
  );
  return bytes;
}
function hit(offset = 0, id = 'mediatek-brom-nor'): SignatureHit {
  return { offset, id, description: 'test envelope', category: 'container', confidence: 'high' };
}
function run(bytes = fixture(), options: SignatureDigestOptions = { sha256 }) {
  return verifySignatureDigests(bytes, [hit()], options);
}
function resized(coveredBytes: number): Uint8Array {
  const out = new Uint8Array(0x600 + coveredBytes + 32);
  out.set(fixture().subarray(0, 0x900));
  const dv = new DataView(out.buffer);
  for (const offset of [0x210, 0x220, 0x624]) dv.setUint32(offset, out.length, true);
  dv.setUint32(0x620, out.length - 0x600, true);
  out.set(sha256(out.subarray(0x600, out.length - 32)), out.length - 32);
  return out;
}

describe('listed MediaTek BootROM digest verification', () => {
  it('recomputes actual mkimage bytes and gives precisely scoped verified 99', () => {
    const bytes = fixture();
    const before = bytes.slice();
    const out = run(bytes);
    expect(out.hits[0]).toMatchObject({
      tier: 'verified',
      score: 99,
      confidence: 'high',
      meta: {
        size: 2593,
        digest: 'verified',
        digestCoveredStart: 0x600,
        digestCoveredEnd: 2561,
        digestUnhashedHeaderStart: 0,
        digestUnhashedHeaderEnd: 0x600,
      },
    });
    expect(out.hits[0]?.rationale).toContain('No authenticity, device, boot, execution or whole-image clean proof');
    expect(out.coverage).toMatchObject({
      listed: 1,
      planned: 1,
      attempted: 1,
      completed: 1,
      matched: 1,
      mismatched: 0,
      unavailable: 0,
      skipped: 0,
      invalidCandidates: 0,
      bytesPlanned: 1025,
      bytesSubmitted: 1025,
      bytesCompleted: 1025,
    });
    expect(bytes).toEqual(before);
  });

  it.each([0x900, 0x61c, 2592])('retains a structurally consistent row on mutation at %i', (at) => {
    const bytes = fixture();
    bytes[at] = (bytes[at] ?? 0) ^ 1;
    const out = run(bytes);
    expect(out.hits).toHaveLength(1);
    expect(out.hits[0]).toMatchObject({ tier: 'consistent', score: 85, meta: { digest: 'mismatch' } });
    expect(out.coverage).toMatchObject({ attempted: 1, completed: 1, matched: 0, mismatched: 1 });
    expect(parseMediaTekBromHeader(bytes).valid).toBe(true);
  });

  it('does not authenticate device/BRLYT: another valid media declaration retains the same hash match', () => {
    const bytes = fixture();
    bytes.fill(0xff, 0, 12);
    bytes.set(Buffer.from('EMMC_BOOT\0'));
    new DataView(bytes.buffer).setUint32(0x218, 0x10005, true);
    const out = verifySignatureDigests(bytes, [hit(0, 'mediatek-brom-emmc')], { sha256 });
    expect(out.hits[0]).toMatchObject({ tier: 'verified', meta: { declaredMedia: 'emmc', digest: 'verified' } });
    expect(out.hits[0]?.rationale).toContain('first 0x600 device/BRLYT bytes');
    expect(out.hits[0]?.rationale).toContain('unhashed');
  });

  it('uses actual byte bounds at embedded offsets and nonzero Uint8Array byteOffset; ignores trailing bytes', () => {
    const backing = new Uint8Array(4000).fill(0xa5);
    const bytes = backing.subarray(13, 3513);
    bytes.set(fixture(), 7);
    const before = backing.slice();
    let submitted: Uint8Array | undefined;
    const out = verifySignatureDigests(bytes, [hit(7)], {
      sha256: (b) => {
        submitted = b.slice();
        return sha256(b);
      },
    });
    expect(submitted).toEqual(bytes.subarray(7 + 0x600, 7 + 2561));
    expect(out.hits[0]).toMatchObject({ tier: 'verified', meta: { digestCoveredStart: 1543, digestCoveredEnd: 2568 } });
    expect(backing).toEqual(before);
  });

  it('reparses bytes and rule/media agreement despite forged metadata and a previous verified tier', () => {
    const forged = {
      ...hit(),
      tier: 'verified' as const,
      score: 99,
      meta: {
        digest: 'verified',
        digestOffset: -999,
        digestCoveredStart: 0,
        size: 1,
        computedHash: 'secret',
        expectedHash: 'secret',
      },
    };
    const valid = verifySignatureDigests(fixture(), [forged], { sha256 });
    expect(valid.hits[0]).toMatchObject({ tier: 'verified', meta: { digestOffset: 2561, size: 2593 } });
    expect(JSON.stringify(valid)).not.toContain('secret');
    for (const [bytes, candidate] of [
      [fixture().subarray(0, 2592), forged],
      [fixture(), { ...forged, id: 'mediatek-brom-emmc' }],
      [fixture(), { ...forged, offset: 1 }],
      [new Uint8Array(3000), forged],
    ] as [Uint8Array, SignatureHit][]) {
      let calls = 0;
      const out = verifySignatureDigests(bytes, [candidate], {
        sha256: (b) => {
          calls++;
          return sha256(b);
        },
      });
      expect(calls).toBe(0);
      expect(out.hits[0]).toMatchObject({ tier: 'magic', score: 25, meta: { digest: 'invalid_candidate' } });
      expect(out.coverage).toMatchObject({ listed: 1, planned: 0, invalidCandidates: 1, attempted: 0, completed: 0 });
      expect(JSON.stringify(out)).not.toContain('secret');
    }
    expect(forged.meta.size).toBe(1);
  });

  it.each([-1, 0.5, Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER])(
    'refuses invalid actual offsets %s before calling the primitive',
    (offset) => {
      expect(planMediaTekDigest(fixture(), hit(offset))).toMatchObject({ supported: true, valid: false });
    },
  );

  it('leaves LK and every unrelated hit unchanged, including their tiers and metadata', () => {
    const hits = [hit(0, 'mediatek-lk'), hit(0, 'uimage'), hit(0, 'mediatek-brom-other'), hit(0, 'toString')];
    const out = verifySignatureDigests(fixture(), hits, {
      sha256: () => {
        throw new Error('should not call');
      },
    });
    expect(out.hits).toEqual(hits);
    out.hits.forEach((h, i) => expect(h).toBe(hits[i]));
    expect(out.coverage).toMatchObject({ listed: 0, planned: 0, attempted: 0, completed: 0 });
  });

  it.each([
    ['absent', undefined, 0, 'sha256_capability_missing'],
    ['wrong function type', 'verified', 0, 'sha256_capability_missing'],
    [
      'throws',
      () => {
        throw new Error('secret hash');
      },
      1,
      'sha256_capability_threw',
    ],
    ['undefined', () => undefined, 1, 'sha256_result_malformed'],
    ['null', () => null, 1, 'sha256_result_malformed'],
    ['string', () => '0'.repeat(64), 1, 'sha256_result_malformed'],
    ['array', () => Array(32).fill(0), 1, 'sha256_result_malformed'],
    ['object', () => ({ length: 32, verified: true }), 1, 'sha256_result_malformed'],
    ['promise', () => Promise.resolve(new Uint8Array(32)), 1, 'sha256_result_malformed'],
    ['wrong typed array', () => new Uint16Array(32), 1, 'sha256_result_malformed'],
    ['proxy typed array', () => new Proxy(new Uint8Array(32), {}), 1, 'sha256_result_malformed'],
    ['31 bytes', () => new Uint8Array(31), 1, 'sha256_result_malformed'],
    ['33 bytes', () => new Uint8Array(33), 1, 'sha256_result_malformed'],
  ])('reports %s capability as unavailable, never a negative or verified', (_, primitive, calls, reason) => {
    const options = { sha256: primitive } as SignatureDigestOptions;
    const out = run(fixture(), options);
    expect(out.hits[0]).toMatchObject({
      tier: 'consistent',
      score: 85,
      meta: { digest: 'unavailable', digestReason: reason },
    });
    expect(out.coverage).toMatchObject({
      listed: 1,
      planned: 1,
      attempted: calls,
      completed: 0,
      matched: 0,
      mismatched: 0,
      unavailable: 1,
      bytesSubmitted: calls * 1025,
      bytesCompleted: 0,
    });
    expect(JSON.stringify(out)).not.toContain('secret hash');
  });

  it('never preserves an older verified tier when this run cannot compute a valid digest', () => {
    const stale = { ...hit(), tier: 'verified' as const, score: 99, meta: { digest: 'verified' } };
    for (const options of [{}, { sha256: () => new Uint8Array(31) }]) {
      const out = verifySignatureDigests(fixture(), [stale], options);
      expect(out.hits[0]).toMatchObject({ tier: 'consistent', score: 85, meta: { digest: 'unavailable' } });
      expect(out.coverage.completed).toBe(0);
      expect(out.coverage.matched).toBe(0);
    }
  });

  it('does not let an accidental mutating capability change the source bytes', () => {
    const bytes = Buffer.from(fixture());
    const before = Uint8Array.from(bytes);
    run(bytes, {
      sha256: (b) => {
        b.fill(0);
        throw new Error('bad internal provider');
      },
    });
    expect(Uint8Array.from(bytes)).toEqual(before);
  });

  it('records absent capability and zero candidates explicitly, without claiming complete or clean', () => {
    const out = verifySignatureDigests(new Uint8Array(0), []);
    expect(out.coverage).toMatchObject({ scope: 'listed_mediatek_brom_hits', listed: 0, attempted: 0, completed: 0 });
    expect(out.coverage.capability).toBe('unavailable');
    expect(verifySignatureDigests(new Uint8Array(0), [], { sha256 }).coverage.capability).toBe('provided');
    expect(out.coverage.note).toContain('scanner listing caps may omit matches');
    expect(out.coverage.note).toContain('not whole-image clean');
    expect(run(fixture(), {}).hits[0]?.tier).toBe('consistent');
  });
});

describe('digest work budgets', () => {
  it('schedules by offset, preserves original row order and caps executions at 8 even when widened', () => {
    const unit = fixture();
    const bytes = new Uint8Array(unit.length * 10);
    const candidates: SignatureHit[] = [];
    for (let n = 0; n < 10; n++) {
      bytes.set(unit, unit.length * n);
      candidates.unshift(hit(unit.length * n));
    }
    for (const maxExecutions of [undefined, 1000, Number.POSITIVE_INFINITY]) {
      const out = verifySignatureDigests(bytes, candidates, {
        sha256,
        ...(maxExecutions === undefined ? {} : { maxExecutions }),
      });
      expect(out.coverage).toMatchObject({
        listed: 10,
        planned: 10,
        attempted: 8,
        completed: 8,
        matched: 8,
        skipped: 2,
        skippedExecutionBudget: 2,
        bytesSubmitted: 8 * 1025,
        maxExecutions: SIGNATURE_DIGEST_MAX_EXECUTIONS,
      });
      expect(out.hits.map((h) => h.offset)).toEqual(candidates.map((h) => h.offset));
      expect(out.hits.slice(0, 2).every((h) => h.meta?.digest === 'skipped_budget')).toBe(true);
      expect(out.hits.slice(2).every((h) => h.tier === 'verified')).toBe(true);
    }
  });

  it.each([0, 1])('honors lower execution budget %i', (maxExecutions) => {
    const out = verifySignatureDigests(fixture(), [hit(), hit()], { sha256, maxExecutions });
    expect(out.coverage).toMatchObject({
      attempted: maxExecutions,
      completed: maxExecutions,
      skipped: 2 - maxExecutions,
    });
  });

  it.each([0, 1024, 1025])('checks lower byte budget %i before the primitive', (maxBytes) => {
    let calls = 0;
    const out = run(fixture(), {
      sha256: (b) => {
        calls++;
        return sha256(b);
      },
      maxBytes,
    });
    expect(calls).toBe(maxBytes < 1025 ? 0 : 1);
    expect(out.coverage).toMatchObject({
      attempted: calls,
      skippedByteBudget: 1 - calls,
      bytesSubmitted: calls * 1025,
    });
  });

  it('skips an oversized early candidate while allowing a later small one within the remaining byte budget', () => {
    const big = fixture();
    const small = resized(769);
    const bytes = new Uint8Array(big.length + small.length);
    bytes.set(big);
    bytes.set(small, big.length);
    const out = verifySignatureDigests(bytes, [hit(big.length), hit()], { sha256, maxBytes: 769 });
    expect(out.coverage).toMatchObject({
      listed: 2,
      planned: 2,
      attempted: 1,
      completed: 1,
      matched: 1,
      skippedByteBudget: 1,
      bytesPlanned: 1025 + 769,
      bytesSubmitted: 769,
      bytesCompleted: 769,
    });
    expect(out.hits[0]?.tier).toBe('verified');
    expect(out.hits[1]?.meta?.digestReason).toBe('byte_budget');
  });

  it('hard-clamps TOTAL submitted bytes to 64 MiB, including failed calls', () => {
    const big = resized(SIGNATURE_DIGEST_MAX_BYTES);
    const small = fixture();
    const bytes = new Uint8Array(big.length + small.length);
    bytes.set(big);
    bytes.set(small, big.length);
    let calls = 0;
    const out = verifySignatureDigests(bytes, [hit(), hit(big.length)], {
      sha256: () => {
        calls++;
        throw new Error('failure');
      },
      maxBytes: Number.MAX_SAFE_INTEGER,
    });
    expect(calls).toBe(1);
    expect(out.coverage).toMatchObject({
      attempted: 1,
      completed: 0,
      unavailable: 1,
      skippedByteBudget: 1,
      bytesSubmitted: SIGNATURE_DIGEST_MAX_BYTES,
      bytesCompleted: 0,
      maxBytes: SIGNATURE_DIGEST_MAX_BYTES,
    });
  });

  it('never calls the primitive for a single candidate beyond the hard byte ceiling', () => {
    const out = run(resized(SIGNATURE_DIGEST_MAX_BYTES + 1), { sha256, maxBytes: Number.POSITIVE_INFINITY });
    expect(out.coverage).toMatchObject({
      attempted: 0,
      skippedByteBudget: 1,
      bytesSubmitted: 0,
      maxBytes: SIGNATURE_DIGEST_MAX_BYTES,
    });
  });

  it.each([-1, Number.NaN, Number.NEGATIVE_INFINITY, 0.9])('fails closed for invalid/lower limits %s', (limit) => {
    const out = run(fixture(), { sha256, maxExecutions: limit, maxBytes: limit });
    expect(out.coverage).toMatchObject({ maxExecutions: 0, maxBytes: 0, attempted: 0, skipped: 1 });
  });

  it('charges throwing calls against execution budget without claiming completed work', () => {
    const out = verifySignatureDigests(fixture(), [hit(), hit()], {
      sha256: () => {
        throw new Error('failure');
      },
      maxExecutions: 1,
    });
    expect(out.coverage).toMatchObject({
      attempted: 1,
      completed: 0,
      unavailable: 1,
      skippedExecutionBudget: 1,
      bytesSubmitted: 1025,
      bytesCompleted: 0,
    });
  });
});

describe('analysis digest coherence and persisted compatibility', () => {
  it('applies verification before building structure and keeps analysis/signatureScan/structure metadata coherent', () => {
    const bytes = fixture();
    const scan = scanSignaturesDetailed(bytes);
    const core = analyzeBuffer(bytes);
    const native = analyzeBuffer(bytes, { signatureDigests: { sha256 } });
    expect(native.signatures).toBe(native.signatureScan?.hits);
    expect(native.signatureScan).toEqual({ ...scan, hits: native.signatures });
    expect(core.identity).toEqual(native.identity);
    expect(native.signatures.map((h) => [h.offset, h.id, h.confidence])).toEqual(
      core.signatures.map((h) => [h.offset, h.id, h.confidence]),
    );
    expect(native.structure).toHaveLength(core.structure.length);
    expect(native.structure.find((s) => s.start === 0)?.meta).toEqual(native.signatures[0]?.meta);
    expect(core.signatureDigests).toMatchObject({ unavailable: 1, attempted: 0, completed: 0 });
    expect(native.signatureDigests).toMatchObject({ matched: 1, attempted: 1, completed: 1 });
    expect(JSON.stringify(native)).not.toContain(Buffer.from(bytes.subarray(2561)).toString('hex'));
  });

  it('preserves zero/partial coverage through JSON and does not invent coverage on legacy JSON', () => {
    const bytes = fixture();
    for (const analysis of [
      analyzeBuffer(new Uint8Array(0)),
      analyzeBuffer(bytes, { signatureDigests: { sha256, maxBytes: 0 } }),
    ]) {
      expect(JSON.parse(JSON.stringify(analysis))).toEqual(analysis);
    }
    const analysis = analyzeBuffer(bytes);
    const { signatureDigests: _coverage, ...legacy } = analysis;
    const old: StaticAnalysis = JSON.parse(JSON.stringify(legacy));
    expect(old.signatureDigests).toBeUndefined();
    expect(old.signatures[0]?.tier).toBe('consistent');
  });

  it('does not extend coverage past a bounded scanner listing', () => {
    const bytes = new Uint8Array(fixture().length * 5);
    for (let n = 0; n < 5; n++) bytes.set(fixture(), n * 2593);
    // The scanner retains one representative per rule despite maxHits=0; digest work covers that list only.
    const scan = scanSignaturesDetailed(bytes, { maxHits: 0 });
    const out = verifySignatureDigests(bytes, scan.hits, { sha256 });
    expect(scan.matched).toBe(5);
    expect(out.coverage).toMatchObject({ listed: 1, attempted: 1, completed: 1, matched: 1 });
    expect(scan.hits).toHaveLength(1);
  });
});
