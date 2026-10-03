import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { type KernelCveSelection, normalizeKernelCves } from '../providers/kernel-cve.js';
import type { NvdComponentResult } from '../providers/nvd.js';
import { summarizeVendorVexSearch } from '../providers/vendor-vex-coverage.js';
import { emptySbom, vexPersistenceCases } from '../providers/vendor-vex-persistence.test-fixtures.js';

const mocks = vi.hoisted(() => ({
  getImage: vi.fn(),
  listJobs: vi.fn(),
  config: vi.fn(),
  syncFindings: vi.fn(),
  queryNvd: vi.fn(),
  discover: vi.fn(),
  normalize: vi.fn(),
  selectKernel: vi.fn(),
}));
vi.mock('../store.js', () => ({ getImage: mocks.getImage, listJobs: mocks.listJobs }));
vi.mock('../corpus.js', () => ({}));
vi.mock('../agent/intel.js', () => ({}));
vi.mock('../llm.js', () => ({ loadLlmConfig: () => null }));
vi.mock('../findings.js', () => ({ syncFindings: mocks.syncFindings }));
vi.mock('./config.js', () => ({ loadResearchConfig: mocks.config, RESEARCH_DISABLED: 'research disabled' }));
vi.mock('../providers/component-cve.js', () => ({ runComponentCve: () => ({ hits: [] }) }));
vi.mock('../providers/kernelposture.js', () => ({ runKernelPosture: () => ({}) }));
vi.mock('../providers/kernel-cve.js', async (original) => ({
  ...(await original<typeof import('../providers/kernel-cve.js')>()),
  selectKernelCveCandidate: mocks.selectKernel,
  normalizeKernelCves: mocks.normalize,
}));
vi.mock('../providers/nvd.js', () => ({ queryNvdBatch: mocks.queryNvd }));
vi.mock('../providers/osv.js', () => ({
  osvEcosystem: () => null,
  queryOsvBatch: async () => ({
    queried: 0,
    skipped: 0,
    withAdvisories: 0,
    totalAdvisories: 0,
    components: [],
    truncated: [],
    cache: { hits: 0, misses: 0, oldestAgeMs: 0 },
  }),
}));
vi.mock('../providers/kev.js', () => ({
  collectCveIds: () => [],
  fetchAndMatchKev: async () => ({ matches: [], available: false }),
  kevLogLine: () => 'Synthetic KEV result',
}));
vi.mock('../providers/securitytxt.js', () => ({ fetchSecurityTxt: vi.fn() }));
vi.mock('../providers/hashlookup.js', () => ({ runHashLookup: async () => ({ enabled: false }) }));
vi.mock('../providers/vendor-vex-discover.js', async (original) => ({
  ...(await original<typeof import('../providers/vendor-vex-discover.js')>()),
  discoverVendorVex: mocks.discover,
}));

import { type ResearchResult, runResearch } from './run.js';

const selection: KernelCveSelection = {
  candidate: { name: 'linux-kernel', version: '5.4' },
  detectedVersion: '5.4.213',
  queryVersion: '5.4',
  versionSource: 'kernel-banner',
  reason: 'synthetic kernel',
  configOptions: [],
};
const kernelAnswer: NvdComponentResult = {
  name: 'linux-kernel',
  version: '5.4',
  matchedBy: 'cpe',
  freshness: null,
  uncheckedIdentities: [],
  totalMatching: 0,
  advisories: [],
};

function nvdAnswer(components: NvdComponentResult[]) {
  return {
    queried: components.length,
    withAdvisories: 0,
    totalAdvisories: 0,
    components,
    truncated: [],
    uncheckedIdentities: [],
    askedByCpe: components.length,
    askedByKeyword: 0,
    cache: { hits: 0, misses: 0, oldestAgeMs: 0 },
  };
}

describe('research vendor VEX persistence', () => {
  beforeEach(async () => {
    vi.clearAllMocks();
    vi.stubGlobal(
      'fetch',
      vi.fn(() => {
        throw new Error('Network forbidden in VEX persistence tests');
      }),
    );
    mocks.config.mockReturnValue({ hashLookup: false, allowlist: [] });
    mocks.getImage.mockReturnValue({
      path: '/synthetic.bin',
      identityJson: JSON.stringify({ firmwareClass: 'embedded-linux' }),
      analysisJson: JSON.stringify({ secrets: [], signatures: [] }),
    });
    // A legacy SBOM without vendorVex remains readable as research input.
    mocks.listJobs.mockReturnValue([
      { kind: 'extract', status: 'done', resultJson: JSON.stringify({ rootfsPath: '/synthetic-rootfs' }) },
      { kind: 'sbom', status: 'done', resultJson: JSON.stringify(emptySbom()) },
    ]);
    mocks.queryNvd.mockResolvedValue(nvdAnswer([kernelAnswer]));
    mocks.selectKernel.mockReturnValue(selection);
    const actual = await vi.importActual<typeof import('../providers/kernel-cve.js')>('../providers/kernel-cve.js');
    mocks.normalize.mockImplementation(actual.normalizeKernelCves);
  });
  afterEach(() => vi.unstubAllGlobals());

  async function roundTrip(): Promise<ResearchResult> {
    const result = await runResearch('image', { id: 'job', log: vi.fn() });
    return JSON.parse(JSON.stringify(result));
  }

  it.each(vexPersistenceCases())('persists $name even with an empty kernel answer', async ({ discovery }) => {
    mocks.discover.mockReturnValue(discovery);
    const result = await roundTrip();
    expect(result.vendorVex).toEqual(summarizeVendorVexSearch(discovery));
    expect(mocks.discover).toHaveBeenCalledExactlyOnceWith('/synthetic-rootfs');
    expect(mocks.normalize.mock.calls[0]?.[2]).toBe(discovery);
    expect(mocks.syncFindings).toHaveBeenCalledWith('image', 'kernel-cve', []);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('does not drop or upgrade unmatched kernel findings', async () => {
    mocks.discover.mockReturnValue(vexPersistenceCases()[2]?.discovery);
    const answer: NvdComponentResult = {
      ...kernelAnswer,
      totalMatching: 1,
      advisories: [{ id: 'CVE-2020-0001', severity: 'HIGH', score: 7.5, summary: 'synthetic', references: [] }],
    };
    mocks.queryNvd.mockResolvedValue(nvdAnswer([answer]));
    const actual = await vi.importActual<typeof import('../providers/kernel-cve.js')>('../providers/kernel-cve.js');
    const expected = actual.normalizeKernelCves(selection, answer);
    await roundTrip();
    expect(expected).toHaveLength(1);
    expect(mocks.syncFindings).toHaveBeenCalledWith('image', 'kernel-cve', expected);
  });

  it.each([[], [{ ...kernelAnswer, name: 'busybox' }]])(
    'records not attempted when there is no Linux-kernel answer: %j',
    async (...components) => {
      mocks.queryNvd.mockResolvedValue(nvdAnswer(components));
      const result = await roundTrip();
      expect(result.vendorVex).toEqual({
        attempted: false,
        notAttemptedReason: 'No Linux-kernel NVD answer, so no vendor VEX correlation was attempted in this run.',
      });
      expect(mocks.discover).not.toHaveBeenCalled();
      expect(mocks.normalize).not.toHaveBeenCalled();
      expect(mocks.syncFindings).not.toHaveBeenCalled();
    },
  );

  it('records no rootfs without changing kernel normalization or its finding sync', async () => {
    mocks.listJobs.mockReturnValue([]);
    const result = await roundTrip();
    expect(result.vendorVex).toEqual({
      attempted: false,
      notAttemptedReason: 'No extracted rootfs, so no vendor VEX correlation was attempted in this run.',
    });
    expect(mocks.discover).not.toHaveBeenCalled();
    expect(mocks.normalize).toHaveBeenCalledExactlyOnceWith(selection, kernelAnswer, undefined);
    expect(mocks.syncFindings).toHaveBeenCalledWith('image', 'kernel-cve', []);
  });

  it('retains the disabled-research gate without attempting discovery', async () => {
    mocks.config.mockReturnValue(null);
    await expect(roundTrip()).rejects.toThrow('research disabled');
    expect(mocks.discover).not.toHaveBeenCalled();
    expect(mocks.queryNvd).not.toHaveBeenCalled();
  });

  it('leaves vendorVex absent when legacy research JSON is read', async () => {
    mocks.queryNvd.mockResolvedValue(nvdAnswer([]));
    const { vendorVex: _notRecorded, ...legacy } = await roundTrip();
    const stored: ResearchResult = JSON.parse(JSON.stringify(legacy));
    expect(stored.vendorVex).toBeUndefined();
    expect(stored).not.toHaveProperty('vendorVex');
  });
});
