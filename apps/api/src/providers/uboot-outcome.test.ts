import { describe, expect, it } from 'vitest';
import {
  UBOOT_WORKER,
  type UbootCoverageResult,
  latestUbootCoverageStep,
  readLoaderKeyAudit,
  ubootCoverageStep,
} from './uboot-outcome.js';

function result(
  leadsFound: number,
  scan: { bytesRead: number; totalBytes: number; complete: boolean },
): UbootCoverageResult {
  return {
    findings: Array.from({ length: leadsFound }, () => ({ kind: 'bootloader-derived-flash-key' })),
    loaderKeyAudit: { attempted: true, completed: true, leadsFound, scan },
  };
}

const fullScan = { bytesRead: 2048, totalBytes: 2048, complete: true };

function job(audit: unknown, marker: string): { kind: string; status: string; resultJson: string } {
  return { kind: 'uboot', status: 'done', resultJson: JSON.stringify({ findings: [], marker, loaderKeyAudit: audit }) };
}

describe('U-Boot loader-key coverage outcome', () => {
  it('leaves legacy results absent instead of turning missing coverage into an empty audit', () => {
    expect(ubootCoverageStep({ findings: [] })).toBeNull();
    expect(
      latestUbootCoverageStep([
        { kind: 'uboot', status: 'done', resultJson: JSON.stringify({ found: false, findings: [] }) },
      ]),
    ).toBeNull();
  });

  it('reports a completed empty audit as a scoped negative, never as proof of no derived key', () => {
    const step = ubootCoverageStep(result(0, fullScan));
    expect(step).toMatchObject({ worker: UBOOT_WORKER, status: 'ran', findingCount: 0 });
    expect(step?.summary).toContain('completed across 2048/2048 bytes; 0 lead(s)');
    expect(step?.note).toContain('within the recorded 2048/2048 bytes scan');
    expect(step?.note).toContain('not proof that the firmware has no derived key');
  });

  it('keeps a completed but bounded audit degraded and names how to extend it', () => {
    const step = ubootCoverageStep(result(0, { bytesRead: 4096, totalBytes: 8192, complete: false }));
    expect(step).toMatchObject({ status: 'degraded', remedy: 'raise-bound', findingCount: 0 });
    expect(step?.summary).toContain('completed within 4096/8192 bytes');
    expect(step?.note).toContain('remain unexamined');
  });

  it('surfaces a recorded lead without upgrading it beyond runtime reproduction', () => {
    const step = ubootCoverageStep(result(1, { bytesRead: 4096, totalBytes: 4096, complete: true }));
    expect(step).toMatchObject({ status: 'ran', findingCount: 1 });
    expect(step?.summary).toContain('1 lead(s)');
    expect(step?.note).toContain('requires runtime reproduction');
    expect(step?.note).toContain('no device behavior is confirmed');
  });

  it('reads the producer’s unreadable-image shape as not attempted, not as empty', () => {
    expect(readLoaderKeyAudit({ attempted: false, completed: false, leadsFound: 0 })).toEqual({
      kind: 'not-attempted',
    });
    const step = ubootCoverageStep({
      findings: [],
      loaderKeyAudit: { attempted: false, completed: false, leadsFound: 0 },
    });
    expect(step).toMatchObject({ status: 'degraded', remedy: 'reacquire-input' });
  });

  it('reads a completed audit over zero bytes as unreadable input, never as a scoped negative', () => {
    const audit = {
      attempted: true,
      completed: true,
      leadsFound: 0,
      scan: { bytesRead: 0, totalBytes: 0, complete: true },
    };
    expect(readLoaderKeyAudit(audit)).toEqual({ kind: 'no-bytes' });
    const step = ubootCoverageStep({ findings: [], loaderKeyAudit: audit });
    expect(step).toMatchObject({ status: 'degraded', remedy: 'reacquire-input' });
    expect(step?.summary).toContain('examined 0 bytes');
    expect(step?.summary).not.toContain('completed');
    expect(step?.note).not.toContain('No loader-derived key lead was found');
    expect(readLoaderKeyAudit({ ...audit, leadsFound: 1 })).toEqual({ kind: 'unknown' });
  });

  it.each([
    ['truthy string flags', { attempted: 'true', completed: 'true', leadsFound: 0, scan: fullScan }],
    ['string "false" flags', { attempted: 'false', completed: 'false', leadsFound: 0 }],
    ['numeric flags', { attempted: 1, completed: 1, leadsFound: 0, scan: fullScan }],
    ['string complete', { attempted: true, completed: true, leadsFound: 0, scan: { ...fullScan, complete: 'true' } }],
    ['missing scan on a completed audit', { attempted: true, completed: true, leadsFound: 0 }],
    ['non-object scan', { attempted: true, completed: true, leadsFound: 0, scan: 'all' }],
    [
      'string byte counts',
      { attempted: true, completed: true, leadsFound: 0, scan: { ...fullScan, bytesRead: '2048' } },
    ],
    ['negative bytes', { attempted: true, completed: true, leadsFound: 0, scan: { ...fullScan, bytesRead: -1 } }],
    [
      'infinite total',
      {
        attempted: true,
        completed: true,
        leadsFound: 0,
        scan: { bytesRead: 1, totalBytes: Number.POSITIVE_INFINITY, complete: false },
      },
    ],
    ['fractional bytes', { attempted: true, completed: true, leadsFound: 0, scan: { ...fullScan, bytesRead: 2047.5 } }],
    [
      'bytesRead beyond totalBytes',
      { attempted: true, completed: true, leadsFound: 0, scan: { bytesRead: 4096, totalBytes: 2048, complete: false } },
    ],
    [
      'complete with bytes missing',
      { attempted: true, completed: true, leadsFound: 0, scan: { bytesRead: 1024, totalBytes: 2048, complete: true } },
    ],
    [
      'incomplete over every byte',
      { attempted: true, completed: true, leadsFound: 0, scan: { ...fullScan, complete: false } },
    ],
    ['string lead count', { attempted: true, completed: true, leadsFound: '0', scan: fullScan }],
    ['missing lead count', { attempted: true, completed: true, scan: fullScan }],
    ['completed without attempting', { attempted: false, completed: true, leadsFound: 0, scan: fullScan }],
    ['leads without attempting', { attempted: false, completed: false, leadsFound: 2 }],
    ['null', null],
    ['array', [true, true, 0]],
  ])('degrades %s to unknown coverage, never ran or empty', (_label, audit) => {
    expect(readLoaderKeyAudit(audit)).toEqual({ kind: 'unknown' });
    const step = ubootCoverageStep({ findings: [], loaderKeyAudit: audit });
    expect(step).toMatchObject({ status: 'degraded', remedy: 'retry' });
    expect(step?.summary).toContain('coverage unknown');
    expect(step?.summary).not.toContain('completed');
    expect(step?.note).not.toContain('No loader-derived key lead was found');
  });

  it('does not invent a zero finding count when the stored findings are not an array', () => {
    const step = ubootCoverageStep({
      findings: 'none' as unknown as [],
      loaderKeyAudit: result(0, fullScan).loaderKeyAudit,
    });
    expect(step?.findingCount).toBeUndefined();
    expect(step?.summary).toContain('findings not recorded');
  });

  it('takes the first job in store order, so a tied timestamp resolves to the later insertion', () => {
    const later = job({ attempted: true, completed: true, leadsFound: 1, scan: fullScan }, 'later');
    const earlier = job({ attempted: true, completed: true, leadsFound: 0, scan: fullScan }, 'earlier');
    // `listJobs` orders by createdAt DESC, rowid DESC; the tie between these two is resolved there.
    expect(latestUbootCoverageStep([later, earlier])?.summary).toContain('1 lead(s)');
  });

  it('lets a newer malformed audit report unknown rather than falling back to an older clean one', () => {
    const malformed = job({ attempted: 'true', completed: 'true', leadsFound: 0, scan: fullScan }, 'new');
    const clean = job({ attempted: true, completed: true, leadsFound: 0, scan: fullScan }, 'old');
    expect(latestUbootCoverageStep([malformed, clean])).toMatchObject({ status: 'degraded' });
    expect(latestUbootCoverageStep([malformed, clean])?.summary).toContain('coverage unknown');
  });

  it('skips unparseable and non-object results instead of letting them mask an older audit', () => {
    const clean = job({ attempted: true, completed: true, leadsFound: 0, scan: fullScan }, 'old');
    const step = latestUbootCoverageStep([
      { kind: 'uboot', status: 'done', resultJson: '{broken' },
      { kind: 'uboot', status: 'done', resultJson: 'null' },
      clean,
    ]);
    expect(step).toMatchObject({ status: 'ran' });
  });
});
