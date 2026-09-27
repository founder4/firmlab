import { describe, expect, it } from 'vitest';
import { UBOOT_WORKER, type UbootCoverageResult, latestUbootCoverageStep, ubootCoverageStep } from './uboot-outcome.js';

function result(
  leadsFound: number,
  scan: { bytesRead: number; totalBytes: number; complete: boolean },
): UbootCoverageResult {
  return {
    findings: Array.from({ length: leadsFound }, () => ({ kind: 'bootloader-derived-flash-key' })),
    loaderKeyAudit: { attempted: true, completed: true, leadsFound, scan },
  };
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
    const step = ubootCoverageStep(result(0, { bytesRead: 2048, totalBytes: 2048, complete: true }));
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
});
