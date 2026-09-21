import Fastify from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  getImage: vi.fn(),
  listJobs: vi.fn(),
  runComponentCve: vi.fn(),
  startJob: vi.fn(),
  syncFindings: vi.fn(),
}));

vi.mock('../store.js', () => ({
  getImage: mocks.getImage,
  listJobs: mocks.listJobs,
}));
vi.mock('../providers/component-cve.js', () => ({ runComponentCve: mocks.runComponentCve }));
vi.mock('../providers/jobs.js', () => ({ startJob: mocks.startJob }));
vi.mock('../findings.js', () => ({ syncFindings: mocks.syncFindings }));

import { componentCveRoutes } from './component-cve.js';

type QueuedWork = (handle: { id: string; log: (line: string) => void }) => Promise<unknown>;

describe('component CVE route', () => {
  let queuedWork: QueuedWork | undefined;

  beforeEach(() => {
    vi.clearAllMocks();
    queuedWork = undefined;
    mocks.getImage.mockReturnValue({ id: 'image-1' });
    mocks.listJobs.mockReturnValue([]);
    mocks.startJob.mockImplementation((_imageId, _kind, _params, work: QueuedWork) => {
      queuedWork = work;
      return 'component-cve-job';
    });
  });

  async function buildApp() {
    const app = Fastify();
    await app.register(componentCveRoutes, { prefix: '/api' });
    return app;
  }

  it('returns 404 for an unknown image without creating a job', async () => {
    mocks.getImage.mockReturnValue(undefined);
    const app = await buildApp();

    const response = await app.inject({ method: 'POST', url: '/api/images/missing/component-cve' });

    expect(response.statusCode).toBe(404);
    expect(response.json()).toEqual({ error: 'Image not found' });
    expect(mocks.startJob).not.toHaveBeenCalled();
    await app.close();
  });

  it('creates a component-cve job over the latest extracted rootfs', async () => {
    mocks.listJobs.mockReturnValue([
      {
        kind: 'extract',
        status: 'done',
        resultJson: JSON.stringify({ rootfsPath: '/extract/latest-rootfs' }),
      },
      {
        kind: 'extract',
        status: 'done',
        resultJson: JSON.stringify({ rootfsPath: '/extract/older-rootfs' }),
      },
    ]);
    const app = await buildApp();

    const response = await app.inject({ method: 'POST', url: '/api/images/image-1/component-cve' });

    expect(response.statusCode).toBe(202);
    expect(response.json()).toEqual({ jobId: 'component-cve-job' });
    expect(mocks.startJob).toHaveBeenCalledWith('image-1', 'component-cve', {}, expect.any(Function));
    expect(queuedWork).toBeTypeOf('function');
    await app.close();
  });

  it('returns the provider result and synchronizes only the component-cve source', async () => {
    const findings = [
      {
        kind: 'component-cve',
        title: 'CVE proof from bundled bytes',
        severity: 'high',
        proofState: 'static_confirmed',
      },
    ];
    const providerResult = {
      available: true,
      hits: [{ component: 'busybox', version: '1.36.0', path: 'bin/busybox' }],
      findings,
      entriesWalked: 17,
      walkTruncated: false,
      reason: 'Scanned the extracted rootfs.',
    };
    mocks.listJobs.mockReturnValue([
      {
        kind: 'extract',
        status: 'done',
        resultJson: JSON.stringify({ rootfsPath: '/extract/rootfs' }),
      },
    ]);
    mocks.runComponentCve.mockReturnValue(providerResult);
    const app = await buildApp();
    await app.inject({ method: 'POST', url: '/api/images/image-1/component-cve' });

    const result = await queuedWork?.({ id: 'component-cve-job', log: vi.fn() });

    expect(mocks.runComponentCve).toHaveBeenCalledWith('/extract/rootfs');
    expect(result).toBe(providerResult);
    expect(mocks.syncFindings).toHaveBeenCalledTimes(1);
    expect(mocks.syncFindings).toHaveBeenCalledWith('image-1', 'component-cve', findings);
    await app.close();
  });

  it('preserves the provider missing-rootfs result while clearing only its own stale findings', async () => {
    const unavailable = {
      available: false,
      hits: [],
      findings: [],
      reason: 'No extracted rootfs — run extraction first.',
    };
    mocks.runComponentCve.mockReturnValue(unavailable);
    const app = await buildApp();
    await app.inject({ method: 'POST', url: '/api/images/image-1/component-cve' });

    const result = await queuedWork?.({ id: 'component-cve-job', log: vi.fn() });

    expect(mocks.runComponentCve).toHaveBeenCalledWith(null);
    expect(result).toBe(unavailable);
    expect(mocks.syncFindings).toHaveBeenCalledWith('image-1', 'component-cve', []);
    await app.close();
  });
});
