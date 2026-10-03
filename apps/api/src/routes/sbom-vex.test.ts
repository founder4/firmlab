import Fastify from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { normalizeSbom } from '../findings-normalize.js';
import type { JobHandle } from '../providers/jobs.js';
import type { SbomResult } from '../providers/sbom.js';
import { summarizeVendorVexSearch } from '../providers/vendor-vex-coverage.js';
import { emptySbom, vexPersistenceCases } from '../providers/vendor-vex-persistence.test-fixtures.js';

const mocks = vi.hoisted(() => ({
  getImage: vi.fn(),
  listJobs: vi.fn(),
  startJob: vi.fn(),
  syncFindings: vi.fn(),
  recordComponents: vi.fn(),
  runSbom: vi.fn(),
  discover: vi.fn(),
  normalize: vi.fn(),
}));
vi.mock('../store.js', () => ({ getImage: mocks.getImage, listJobs: mocks.listJobs }));
vi.mock('../providers/jobs.js', () => ({ startJob: mocks.startJob }));
vi.mock('../corpus.js', () => ({ recordComponents: mocks.recordComponents }));
vi.mock('../findings.js', () => ({
  syncFindings: mocks.syncFindings,
  deviceContextFor: () => undefined,
  normalizeSbom: mocks.normalize,
}));
vi.mock('../providers/sbom.js', () => ({ runSbom: mocks.runSbom }));
vi.mock('../providers/vendor-vex-discover.js', async (original) => ({
  ...(await original<typeof import('../providers/vendor-vex-discover.js')>()),
  discoverVendorVex: mocks.discover,
}));

import { sbomRoutes } from './sbom.js';

describe('manual SBOM vendor VEX persistence', () => {
  let work: ((handle: JobHandle) => Promise<SbomResult>) | undefined;
  beforeEach(() => {
    vi.clearAllMocks();
    work = undefined;
    mocks.getImage.mockReturnValue({ id: 'image' });
    mocks.listJobs.mockReturnValue([
      { kind: 'extract', status: 'done', resultJson: JSON.stringify({ rootfsPath: '/synthetic-rootfs' }) },
    ]);
    mocks.startJob.mockImplementation((_id, _kind, _params, run) => {
      work = run;
      return 'job';
    });
    mocks.runSbom.mockResolvedValue(emptySbom());
    mocks.normalize.mockImplementation(normalizeSbom);
  });

  async function roundTrip(): Promise<SbomResult> {
    const app = Fastify();
    try {
      await app.register(sbomRoutes);
      const post = await app.inject({ method: 'POST', url: '/images/image/sbom' });
      expect(post.statusCode).toBe(202);
      if (!work) throw new Error('No queued SBOM job');
      const result = await work({ id: 'job', log: vi.fn() });
      mocks.listJobs.mockReturnValue([{ kind: 'sbom', status: 'done', resultJson: JSON.stringify(result) }]);
      const get = await app.inject({ method: 'GET', url: '/images/image/sbom' });
      expect(get.statusCode).toBe(200);
      expect(get.json()).toEqual({ result });
      return get.json().result;
    } finally {
      await app.close();
    }
  }

  it.each(vexPersistenceCases())('round-trips $name even with zero vulnerabilities', async ({ discovery }) => {
    mocks.discover.mockReturnValue(discovery);
    const result = await roundTrip();
    expect(result.vendorVex).toEqual(summarizeVendorVexSearch(discovery));
    expect(mocks.discover).toHaveBeenCalledExactlyOnceWith('/synthetic-rootfs');
    expect(mocks.normalize.mock.calls[0]?.[2]).toBe(discovery);
    expect(mocks.syncFindings).toHaveBeenCalledWith('image', 'sbom', []);
  });

  it.each([
    { available: false, syftOutcome: 'tool_absent' as const, reason: 'syft is missing' },
    { grypeAvailable: false, grypeOutcome: 'tool_absent' as const, grypeReason: 'grype is missing' },
  ])('keeps independent discovery when a tool is unavailable: %j', async (over) => {
    const discovery = vexPersistenceCases()[3]?.discovery;
    mocks.discover.mockReturnValue(discovery);
    mocks.runSbom.mockResolvedValue(emptySbom(over));
    const result = await roundTrip();
    expect(result).toMatchObject(over);
    expect(result.vendorVex).toMatchObject({ attempted: true, refused: 1 });
    expect(mocks.discover).toHaveBeenCalledTimes(1);
  });

  it('keeps an unmatched finding and its severity/proof state unchanged', async () => {
    mocks.discover.mockReturnValue(vexPersistenceCases()[2]?.discovery);
    const result = emptySbom({
      vulnerabilities: [
        { id: 'CVE-2020-0001', packageName: 'busybox', packageVersion: '1.30.1', severity: 'High', fixedIn: null },
      ],
    });
    mocks.runSbom.mockResolvedValue(result);
    await roundTrip();
    expect(mocks.syncFindings).toHaveBeenCalledWith('image', 'sbom', normalizeSbom(result));
  });

  it('loads legacy JSON with coverage absent, without fabricating a zero search', async () => {
    const legacy: SbomResult = emptySbom();
    mocks.listJobs.mockReturnValue([{ kind: 'sbom', status: 'done', resultJson: JSON.stringify(legacy) }]);
    const app = Fastify();
    await app.register(sbomRoutes);
    const get = await app.inject({ method: 'GET', url: '/images/image/sbom' });
    await app.close();
    expect(get.json()).toEqual({ result: legacy });
    expect(get.json().result).not.toHaveProperty('vendorVex');
    expect(mocks.discover).not.toHaveBeenCalled();
  });

  it('keeps the no-rootfs gate without starting a search or a job', async () => {
    mocks.listJobs.mockReturnValue([{ kind: 'extract', status: 'done', resultJson: '{"rootfsPath":null}' }]);
    const app = Fastify();
    await app.register(sbomRoutes);
    const post = await app.inject({ method: 'POST', url: '/images/image/sbom' });
    await app.close();
    expect(post.statusCode).toBe(422);
    expect(mocks.startJob).not.toHaveBeenCalled();
    expect(mocks.discover).not.toHaveBeenCalled();
  });
});
