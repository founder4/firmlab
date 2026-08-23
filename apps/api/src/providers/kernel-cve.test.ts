import { describe, expect, it } from 'vitest';
import { normalizeKernelCves, selectKernelCveCandidate } from './kernel-cve.js';
import type { KernelPostureResult } from './kernelposture.js';
import type { NvdComponentResult } from './nvd.js';

function posture(overrides: Partial<KernelPostureResult> = {}): KernelPostureResult {
  return {
    available: true,
    located: true,
    version: '2.6.31--LSDK-9.2.0_U6.616',
    versionSource: 'module-vermagic',
    versionConflicts: [],
    banner: null,
    bannerPath: null,
    configPath: null,
    rootfsPath: '/firmware/rootfs',
    rootfsDiscovered: false,
    blob: null,
    modules: null,
    age: null,
    answers: [],
    findings: [],
    searched: [],
    bounds: [],
    reason: 'fixture',
    ...overrides,
  };
}

describe('selectKernelCveCandidate', () => {
  it('strips only the vendor suffix and keeps where the version came from', () => {
    const selected = selectKernelCveCandidate(posture());
    expect(selected.candidate).toEqual({ name: 'linux-kernel', version: '2.6.31' });
    expect(selected.detectedVersion).toBe('2.6.31--LSDK-9.2.0_U6.616');
    expect(selected.versionSource).toBe('module-vermagic');
  });

  it('refuses to choose between conflicting version sources', () => {
    const selected = selectKernelCveCandidate(
      posture({
        versionConflicts: [{ a: '2.6.31', aSource: 'module-vermagic', b: '3.10.0', bSource: 'kernel-banner' }],
      }),
    );
    expect(selected.candidate).toBeNull();
    expect(selected.reason).toContain('conflict');
  });
});

describe('normalizeKernelCves', () => {
  it('persists an advisory as a lead and states that a truncated answer is only a prefix', () => {
    const selected = selectKernelCveCandidate(posture());
    const component: NvdComponentResult = {
      name: 'linux-kernel',
      version: '2.6.31',
      matchedBy: 'cpe',
      freshness: { origin: 'network', fetchedAt: '2026-08-23T18:00:00.000Z', ageMs: 0 },
      uncheckedIdentities: [],
      totalMatching: 2037,
      advisories: [
        {
          id: 'CVE-2023-52435',
          summary: 'net: prevent a kernel fault',
          severity: 'HIGH',
          score: 7.8,
          references: ['https://git.kernel.org/stable/c/example'],
        },
      ],
    };
    const [finding] = normalizeKernelCves(selected, component);
    expect(finding?.proofState).toBe('needs_runtime_reproduction');
    expect(finding?.evidenceChannel).toBe('external_advisory');
    expect(finding?.evidence).toMatchObject({ queryVersion: '2.6.31', totalMatching: 2037, truncated: true });
    expect(finding?.rationale).toContain('vendor backports');
    expect(finding?.rationale).toContain('prefix');
  });
});
