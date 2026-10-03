import { beforeEach, describe, expect, it, vi } from 'vitest';
import { normalizeSbom } from './findings-normalize.js';
import { composeDeterministicNarrative } from './opacidad-narrative.js';
import type { OpacidadStep } from './opacidad-narrative.js';
import { summarizeVendorVexSearch } from './providers/vendor-vex-coverage.js';
import { emptySbom, vexPersistenceCases } from './providers/vendor-vex-persistence.test-fixtures.js';

const mocks = vi.hoisted(() => ({
  getImage: vi.fn(),
  listJobs: vi.fn(),
  syncFindings: vi.fn(),
  runSbom: vi.fn(),
  discover: vi.fn(),
  normalize: vi.fn(),
}));
vi.mock('./store.js', () => ({
  getImage: mocks.getImage,
  listJobs: mocks.listJobs,
  listFindings: () => [],
  listBinaries: () => [],
}));
vi.mock('./corpus.js', () => ({}));
vi.mock('./llm.js', () => ({}));
vi.mock('./findings.js', () => ({
  syncFindings: mocks.syncFindings,
  deviceContextFor: () => undefined,
  normalizeSbom: mocks.normalize,
  rowToFinding: vi.fn(),
}));
vi.mock('./providers/sbom.js', () => ({ runSbom: mocks.runSbom }));
vi.mock('./providers/vendor-vex-discover.js', async (original) => ({
  ...(await original<typeof import('./providers/vendor-vex-discover.js')>()),
  discoverVendorVex: mocks.discover,
}));
// Exercise the real executor and persisted step projection, without executing unrelated W9 providers.
vi.mock('./opacidad-plan.js', async (original) => ({
  ...(await original<typeof import('./opacidad-plan.js')>()),
  specsForClass: () => [
    { worker: 'SBOM', provider: 'sbom', built: true, needsRootfs: true, reason: 'fixture SBOM step' },
    { worker: 'Unbuilt fixture', built: false, needsRootfs: false, reason: 'fixture unrelated step' },
  ],
}));

import { runOpacidad } from './opacidad.js';

describe('W9 vendor VEX step persistence', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getImage.mockReturnValue({
      filename: 'synthetic.bin',
      identityJson: JSON.stringify({ firmwareClass: 'embedded-linux', arch: 'mips' }),
      analysisJson: null,
    });
    mocks.listJobs.mockReturnValue([
      { kind: 'extract', status: 'done', resultJson: JSON.stringify({ rootfsPath: '/synthetic-rootfs' }) },
    ]);
    mocks.runSbom.mockResolvedValue(emptySbom());
    mocks.normalize.mockImplementation(normalizeSbom);
  });

  async function roundTrip(): Promise<OpacidadStep[]> {
    const result = await runOpacidad('image', '/synthetic.bin', { id: 'job', log: vi.fn() }, null);
    const stored = JSON.parse(JSON.stringify(result));
    expect(stored.steps[1]).not.toHaveProperty('vendorVex');
    return stored.steps;
  }

  it.each(vexPersistenceCases())('persists $name with zero CVE rows', async ({ discovery }) => {
    mocks.discover.mockReturnValue(discovery);
    const steps = await roundTrip();
    expect(steps[0]).toMatchObject({ status: 'ran', findingCount: 0, vendorVex: summarizeVendorVexSearch(discovery) });
    expect(mocks.discover).toHaveBeenCalledExactlyOnceWith('/synthetic-rootfs');
    expect(mocks.normalize.mock.calls[0]?.[2]).toBe(discovery);
    expect(mocks.syncFindings).toHaveBeenCalledWith('image', 'sbom', []);
  });

  it.each([
    { available: false, syftOutcome: 'tool_absent' as const, reason: 'syft is missing' },
    { grypeAvailable: false, grypeOutcome: 'tool_absent' as const, grypeReason: 'grype is missing' },
  ])('retains tool-failure note and independent coverage: %j', async (over) => {
    mocks.discover.mockReturnValue(vexPersistenceCases()[3]?.discovery);
    mocks.runSbom.mockResolvedValue(emptySbom(over));
    const steps = await roundTrip();
    expect(steps[0]).toMatchObject({
      status: 'degraded',
      note: 'reason' in over ? over.reason : over.grypeReason,
      remedy: 'install-tool',
      vendorVex: { attempted: true, refused: 1 },
    });
    expect(mocks.discover).toHaveBeenCalledTimes(1);
  });

  it('does not drop or upgrade unmatched findings', async () => {
    mocks.discover.mockReturnValue(vexPersistenceCases()[2]?.discovery);
    const result = emptySbom({
      vulnerabilities: [
        { id: 'CVE-2020-0001', packageName: 'busybox', packageVersion: '1.30.1', severity: 'High', fixedIn: null },
      ],
    });
    mocks.runSbom.mockResolvedValue(result);
    const steps = await roundTrip();
    expect(steps[0]?.findingCount).toBe(1);
    expect(mocks.syncFindings).toHaveBeenCalledWith('image', 'sbom', normalizeSbom(result));
  });

  it('does not fabricate executor coverage when the no-rootfs gate skips SBOM', async () => {
    mocks.listJobs.mockReturnValue([]);
    const steps = await roundTrip();
    expect(steps[0]).toMatchObject({ status: 'skipped', note: 'no extracted rootfs available' });
    expect(steps[0]).not.toHaveProperty('vendorVex');
    expect(mocks.discover).not.toHaveBeenCalled();
    expect(mocks.runSbom).not.toHaveBeenCalled();
  });

  it('continues composing legacy steps with no coverage field', () => {
    const steps: OpacidadStep[] = JSON.parse('[{"worker":"SBOM","status":"ran","summary":"0 CVEs"}]');
    expect(() =>
      composeDeterministicNarrative({
        filename: 'legacy.bin',
        firmwareClass: 'embedded-linux',
        arch: 'mips',
        plan: [],
        steps,
        findings: [],
      }),
    ).not.toThrow();
    expect(steps[0]).not.toHaveProperty('vendorVex');
  });
});
