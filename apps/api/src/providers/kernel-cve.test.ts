import { describe, expect, it } from 'vitest';
import { type DeviceContext, privilegeBoundaryFromPasswd, processSupervisionForClass } from './cve-device-triage.js';
import type { DecodedKallsyms } from './kallsyms.js';
import {
  KERNEL_CVE_RULES,
  type KernelConfigEvidence,
  assessKernelCves,
  inferKernelOption,
  kernelCveFindings,
  kernelVersionAffected,
  normalizeKernelCves,
  selectKernelCveCandidate,
} from './kernel-cve.js';
import type { KernelPostureResult } from './kernelposture.js';
import type { NvdComponentResult } from './nvd.js';

function kallsyms(...names: string[]): DecodedKallsyms {
  return {
    names: new Set(names),
    symbolCount: names.length,
    uniqueNameCount: new Set(names).size,
    wordBytes: 4,
    complete: true,
  };
}

function evidence(over: Partial<KernelConfigEvidence> = {}): KernelConfigEvidence {
  return { config: null, kallsyms: null, modules: null, kernelStrings: null, ...over };
}

describe('kernel CONFIG inference', () => {
  it('treats a shipped config as authoritative for both enabled and absent options', () => {
    const ev = evidence({ config: { CONFIG_PACKET: 'm' } });
    expect(inferKernelOption('CONFIG_PACKET', ev)).toMatchObject({ state: 'on', evidence: 'kernel-config:m' });
    expect(inferKernelOption('CONFIG_USER_NS', ev)).toMatchObject({
      state: 'off',
      evidence: 'kernel-config:not-enabled',
    });
  });

  it('uses incomplete module inventories only to rule in, never to rule out', () => {
    const ev = evidence({ modules: { names: new Set(['af-packet']), complete: false } });
    expect(inferKernelOption('CONFIG_PACKET', ev)).toMatchObject({ state: 'on', evidence: 'module:af_packet.ko' });
    expect(inferKernelOption('CONFIG_NF_TABLES', ev).state).toBe('unknown');
  });

  it('rules out builtin-only subsystems from complete kallsyms, but modular ones also need complete module coverage', () => {
    const ks = kallsyms('packet_rcv', 'do_exit');
    expect(inferKernelOption('CONFIG_USER_NS', evidence({ kallsyms: ks }))).toMatchObject({
      state: 'off',
      evidence: 'complete-kallsyms:no-builtin-symbol',
    });
    expect(inferKernelOption('CONFIG_NF_TABLES', evidence({ kallsyms: ks })).state).toBe('unknown');
    expect(
      inferKernelOption('CONFIG_NF_TABLES', evidence({ kallsyms: ks, modules: { names: new Set(), complete: true } })),
    ).toMatchObject({ state: 'off', evidence: 'complete-kallsyms+complete-module-inventory:no-match' });
  });

  it('accepts distinctive strings as weak positive evidence only', () => {
    expect(inferKernelOption('CONFIG_IO_URING', evidence({ kernelStrings: 'io_uring setup failed' }))).toMatchObject({
      state: 'on',
      evidence: 'kernel-string:io_uring',
    });
    expect(inferKernelOption('CONFIG_OVERLAY_FS', evidence({ kernelStrings: 'nothing relevant' })).state).toBe(
      'unknown',
    );
  });
});

describe('kernel CVE triage', () => {
  it('uses half-open mainline ranges', () => {
    const dirtyCow = KERNEL_CVE_RULES.find((rule) => rule.id === 'CVE-2016-5195');
    expect(dirtyCow).toBeDefined();
    expect(kernelVersionAffected('2.6.21', dirtyCow as NonNullable<typeof dirtyCow>)).toBe(false);
    expect(kernelVersionAffected('2.6.22', dirtyCow as NonNullable<typeof dirtyCow>)).toBe(true);
    expect(kernelVersionAffected('4.8.2', dirtyCow as NonNullable<typeof dirtyCow>)).toBe(true);
    expect(kernelVersionAffected('4.8.3', dirtyCow as NonNullable<typeof dirtyCow>)).toBe(false);
  });

  it('reproduces the Tenda gating: USER_NS absent is dismissed while AF_PACKET remains a lead', () => {
    const results = assessKernelCves(
      '4.4.282',
      evidence({ kallsyms: kallsyms('packet_rcv', 'tpacket_rcv', 'do_exit') }),
    );
    expect(results.find((result) => result.id === 'CVE-2022-0185')).toMatchObject({
      state: 'ruled_out',
      reason: expect.stringContaining('CONFIG_USER_NS'),
    });
    expect(results.find((result) => result.id === 'CVE-2016-8655')).toMatchObject({ state: 'applicable' });
  });

  it('keeps a gated in-range CVE unknown when the subsystem evidence is unavailable', () => {
    const results = assessKernelCves('4.4.282', evidence());
    expect(results.find((result) => result.id === 'CVE-2022-0185')).toMatchObject({ state: 'unknown' });
  });

  it('maps applicable, ruled-out and unknown to three distinct proof states', () => {
    const assessments = assessKernelCves(
      '4.4.282',
      evidence({ kallsyms: kallsyms('packet_rcv', 'tpacket_rcv', 'do_exit') }),
    );
    const findings = kernelCveFindings('4.4.282', assessments);
    const proof = (id: string) => findings.find((finding) => finding.title.startsWith(id))?.proofState;
    expect(proof('CVE-2016-8655')).toBe('needs_runtime_reproduction');
    expect(proof('CVE-2022-0185')).toBe('false_positive');
    expect(proof('CVE-2021-22555')).toBe('blocked_by_platform');
  });
});

describe('external NVD kernel selection remains bounded and provisional', () => {
  const posture = (over: Partial<KernelPostureResult> = {}): KernelPostureResult => ({
    available: true,
    located: true,
    version: '2.6.31--vendor',
    versionSource: 'module-vermagic',
    versionConflicts: [],
    banner: null,
    bannerPath: null,
    configPath: null,
    rootfsPath: null,
    rootfsDiscovered: false,
    blob: null,
    modules: null,
    age: null,
    answers: [],
    configOptions: [],
    cves: [],
    findings: [],
    searched: [],
    bounds: [],
    reason: 'fixture',
    ...over,
  });

  it('strips only the vendor suffix and refuses conflicting sources', () => {
    expect(selectKernelCveCandidate(posture()).candidate).toEqual({ name: 'linux-kernel', version: '2.6.31' });
    expect(
      selectKernelCveCandidate(
        posture({
          versionConflicts: [{ a: '2.6.31', aSource: 'module-vermagic', b: '5.4.0', bSource: 'kernel-banner' }],
        }),
      ).candidate,
    ).toBeNull();
  });

  it('keeps an NVD prefix as external-advisory reproduction leads', () => {
    const component: NvdComponentResult = {
      name: 'linux-kernel',
      version: '2.6.31',
      matchedBy: 'cpe',
      freshness: { origin: 'network', fetchedAt: '2026-09-10T00:00:00.000Z', ageMs: 0 },
      uncheckedIdentities: [],
      totalMatching: 2037,
      advisories: [{ id: 'CVE-2023-52435', summary: 'example', severity: 'HIGH', score: 7.8, references: [] }],
    };
    const [finding] = normalizeKernelCves(selectKernelCveCandidate(posture()), component);
    expect(finding).toMatchObject({
      proofState: 'needs_runtime_reproduction',
      evidenceChannel: 'external_advisory',
    });
    expect(finding?.evidence).toMatchObject({ totalMatching: 2037, truncated: true });
  });
});

/**
 * Device context on the kernel rows. `impactSeverity` mapped LPE→high on every image alike, which is the flat
 * reading the triage replaces — and the confinement to `applicable` is the part worth pinning, because putting
 * a confident severity on an `unknown` row would argue the opposite of what that row says.
 */
describe('kernelCveFindings under a device context', () => {
  const noBoundary: DeviceContext = {
    firmwareClass: 'embedded-linux',
    privilegeBoundary: privilegeBoundaryFromPasswd('root:x:0:0::/root:/bin/ash\nnobody:x:99:99::/:/bin/false'),
    processSupervision: processSupervisionForClass('embedded-linux'),
  };
  // Dirty Pipe: LPE, no subsystem gate, so it lands `applicable` on a 5.10 kernel with no evidence at all.
  const dirtyPipe = assessKernelCves('5.10', evidence({}));
  const row = (findings: ReturnType<typeof kernelCveFindings>, id: string) =>
    findings.find((f) => f.title.startsWith(id));

  it('lowers an applicable LPE where the image ships no privilege to escalate from', () => {
    const withCtx = row(kernelCveFindings('5.10', dirtyPipe, noBoundary), 'CVE-2022-0847');
    const without = row(kernelCveFindings('5.10', dirtyPipe), 'CVE-2022-0847');
    expect(without?.severity).toBe('high');
    expect(withCtx?.severity).toBe('medium');
    const ev = withCtx?.evidence as Record<string, unknown>;
    expect(ev.publishedSeverity).toBe('high');
    expect(ev.deviceTriage).toBe('lpe-without-privilege-boundary');
    // The gating sentence the row already carried is kept, not replaced.
    expect(withCtx?.rationale).toContain('curated mainline range');
    expect(withCtx?.rationale).toContain('no privilege to escalate from');
  });

  it('does not re-weight a row whose applicability could not be decided', () => {
    // CVE-2021-22555 needs CONFIG_NETFILTER; with no evidence it is `unknown` → blocked_by_platform. Adjusting
    // its severity would put a confident number on the one row whose whole message is that nobody could tell.
    const assessments = assessKernelCves('4.4.282', evidence({}));
    const unknown = assessments.find((a) => a.id === 'CVE-2021-22555');
    expect(unknown?.state).toBe('unknown');
    const withCtx = row(kernelCveFindings('4.4.282', assessments, noBoundary), 'CVE-2021-22555');
    expect(withCtx?.proofState).toBe('blocked_by_platform');
    expect((withCtx?.evidence as Record<string, unknown>).deviceTriage).toBeUndefined();
  });

  it('changes no row at all when no context is supplied', () => {
    const plain = kernelCveFindings('5.10', dirtyPipe);
    for (const f of plain) expect((f.evidence as Record<string, unknown>).deviceTriage).toBeUndefined();
  });

  it('emits the same number of rows with and without a context', () => {
    expect(kernelCveFindings('5.10', dirtyPipe, noBoundary)).toHaveLength(dirtyPipe.length);
    expect(kernelCveFindings('5.10', dirtyPipe)).toHaveLength(dirtyPipe.length);
  });
});
