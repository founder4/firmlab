import { describe, expect, it } from 'vitest';
import { type DeviceContext, privilegeBoundaryFromPasswd, processSupervisionForClass } from './cve-device-triage.js';
import type { DecodedKallsyms } from './kallsyms.js';
import {
  KERNEL_CVE_RULES,
  type KernelConfigEvidence,
  type KernelCveSelection,
  type KernelOptionAssessment,
  assessKernelCves,
  inferKernelOption,
  kernelCveFindings,
  kernelVersionAffected,
  normalizeKernelCves,
  selectKernelCveCandidate,
  subsystemGate,
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

/**
 * Subsystem gating of the BROAD NVD candidate list — the 2 037-row problem, not the curated table.
 *
 * The dangerous direction here is pruning too much: every row this removes from an operator's attention is a
 * row they will not look at again. So the cases below spend most of their weight on the inputs that must NOT
 * prune — an undetermined option, a subsystem merely mentioned in passing, an image with no evidence at all.
 */
describe('subsystemGate', () => {
  const opt = (
    option: string,
    state: 'on' | 'off' | 'unknown',
    evidence: string | null = 'kernel-config:not-enabled',
  ) => ({
    option,
    state,
    evidence,
  });
  const CNA = 'In the Linux kernel, the following vulnerability has been resolved:';

  it('reads the subsystem out of the commit-subject prefix the Linux CNA quotes', () => {
    const g = subsystemGate(`${CNA}  drm/amdgpu: fix use-after-free bug`, [opt('CONFIG_DRM', 'off')]);
    expect(g?.option).toBe('CONFIG_DRM');
    expect(g?.state).toBe('off');
    expect(g?.marker).toBe('drm/');
  });

  it('matches the multi-word gadget prefix rather than stopping at a bare usb', () => {
    const g = subsystemGate(`${CNA} usb: gadget: f_fs: Clear ffs_eventfd in ffs_data_clear`, [
      opt('CONFIG_USB_GADGET', 'off'),
    ]);
    expect(g?.option).toBe('CONFIG_USB_GADGET');
  });

  it('does NOT gate on a subsystem merely mentioned inside the text', () => {
    // The inference is that the flaw IS in that subsystem, and only the leading commit-subject prefix supports
    // it. A scheduler bug whose description happens to say "drm" must not be dismissed on a GPU-less image.
    // The marker appears VERBATIM in the body — `drm/amdgpu` — and still must not gate, because the flaw is in
    // the scheduler. A `includes` test passes the previous wording of this case and fails this one, which is
    // why the wording changed: the first version proved nothing.
    const g = subsystemGate(`${CNA} sched/fair: fix a race in the drm/amdgpu client wakeup path`, [
      opt('CONFIG_DRM', 'off'),
    ]);
    expect(g).toBeNull();
  });

  it('says nothing for the majority of advisories, which carry no recognised prefix', () => {
    expect(subsystemGate(`${CNA} mm: fix a page-cache race`, [opt('CONFIG_DRM', 'off')])).toBeNull();
    expect(subsystemGate(null, [opt('CONFIG_DRM', 'off')])).toBeNull();
    expect(subsystemGate('', [opt('CONFIG_DRM', 'off')])).toBeNull();
  });

  it('returns unknown — never off — when the option was not resolved', () => {
    const g = subsystemGate(`${CNA} ALSA: usb-audio: fix a leak`, [opt('CONFIG_SOUND', 'unknown', null)]);
    expect(g?.state).toBe('unknown');
  });

  it('returns null when the image assessed no options at all', () => {
    // An image with no config, no kallsyms and no module list prunes nothing. That is the whole safety property.
    expect(subsystemGate(`${CNA} drm/i915: fix a leak`, [])).toBeNull();
  });
});

describe('normalizeKernelCves gates the candidate rows it was handed', () => {
  const selection = (options: KernelOptionAssessment[]): KernelCveSelection => ({
    candidate: { name: 'linux-kernel', version: '5.4' },
    detectedVersion: '5.4.213',
    queryVersion: '5.4',
    versionSource: 'kernel-banner',
    reason: 'test',
    configOptions: options,
  });
  const answer = (summary: string): NvdComponentResult =>
    ({
      name: 'linux-kernel',
      version: '5.4',
      matchedBy: 'cpe',
      totalMatching: 1,
      freshness: null,
      advisories: [{ id: 'CVE-2024-26656', severity: 'MEDIUM', score: 5.5, summary, references: [] }],
    }) as unknown as NvdComponentResult;
  const CNA = 'In the Linux kernel, the following vulnerability has been resolved:';

  it('dismisses a GPU advisory on an image whose config says DRM is not built', () => {
    const rows = normalizeKernelCves(
      selection([{ option: 'CONFIG_DRM', state: 'off', evidence: 'kernel-config:not-enabled' }]),
      answer(`${CNA} drm/amdgpu: fix use-after-free bug`),
    );
    expect(rows).toHaveLength(1); // the row STAYS — the count never changes
    expect(rows[0]?.proofState).toBe('false_positive');
    expect(rows[0]?.rationale).toContain('the code it is in is not here');
    expect((rows[0]?.evidence as Record<string, unknown>).subsystemState).toBe('off');
  });

  it('keeps it a lead when the option could not be determined, and says so', () => {
    const rows = normalizeKernelCves(
      selection([{ option: 'CONFIG_DRM', state: 'unknown', evidence: null }]),
      answer(`${CNA} drm/amdgpu: fix use-after-free bug`),
    );
    expect(rows[0]?.proofState).toBe('needs_runtime_reproduction');
    expect(rows[0]?.rationale).toContain('undetermined is not absent');
  });

  it('removes the "maybe the subsystem is absent" escape when the subsystem IS built', () => {
    const rows = normalizeKernelCves(
      selection([{ option: 'CONFIG_DRM', state: 'on', evidence: 'module:drm.ko' }]),
      answer(`${CNA} drm/amdgpu: fix use-after-free bug`),
    );
    expect(rows[0]?.proofState).toBe('needs_runtime_reproduction');
    expect(rows[0]?.rationale).toContain('does not apply to this row');
    expect(rows[0]?.rationale).not.toContain('may be absent or disabled');
  });

  it('leaves an ungated advisory exactly as it was, escape clause included', () => {
    const rows = normalizeKernelCves(selection([]), answer(`${CNA} mm: fix a page-cache race`));
    expect(rows[0]?.proofState).toBe('needs_runtime_reproduction');
    expect(rows[0]?.rationale).toContain('may be absent or disabled');
    expect((rows[0]?.evidence as Record<string, unknown>).subsystem).toBeUndefined();
  });
});
