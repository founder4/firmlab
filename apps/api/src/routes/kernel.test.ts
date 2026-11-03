import Fastify from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  compareKernelBackports: vi.fn(),
  getImage: vi.fn(),
  listJobs: vi.fn(),
  runKernelPosture: vi.fn(),
  startJob: vi.fn(),
  syncFindings: vi.fn(),
}));

vi.mock('../store.js', () => ({ getImage: mocks.getImage, listJobs: mocks.listJobs }));
vi.mock('../providers/jobs.js', () => ({ startJob: mocks.startJob }));
vi.mock('../providers/kernelposture.js', () => ({ runKernelPosture: mocks.runKernelPosture }));
vi.mock('../findings.js', () => ({ deviceContextFor: vi.fn(), syncFindings: mocks.syncFindings }));
vi.mock('../providers/kernel-backport.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../providers/kernel-backport.js')>()),
  compareKernelBackports: mocks.compareKernelBackports,
}));

import { kernelRoutes } from './kernel.js';

type QueuedWork = () => Promise<unknown>;

function record() {
  return {
    dataType: 'CVE_RECORD',
    dataVersion: '5.1',
    cveMetadata: { cveId: 'CVE-2026-43286', assignerShortName: 'Linux' },
    containers: {
      cna: {
        providerMetadata: { shortName: 'Linux' },
        affected: [
          {
            vendor: 'Linux',
            product: 'Linux',
            repo: 'https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git',
            programFiles: ['mm/hugetlb.c'],
            versions: [
              {
                versionType: 'git',
                status: 'affected',
                version: 'a'.repeat(40),
                lessThan: 'b'.repeat(40),
              },
            ],
          },
        ],
      },
    },
  };
}

describe('kernel backport routes', () => {
  let queuedWork: QueuedWork | undefined;

  beforeEach(() => {
    vi.clearAllMocks();
    queuedWork = undefined;
    mocks.getImage.mockReturnValue({ id: 'image-1', path: '/images/fw.bin' });
    mocks.listJobs.mockReturnValue([]);
    mocks.startJob.mockImplementation((_imageId, _kind, _params, work: QueuedWork) => {
      queuedWork = work;
      return 'kernel-backport-job';
    });
  });

  async function buildApp() {
    const app = Fastify();
    await app.register(kernelRoutes, { prefix: '/api' });
    return app;
  }

  it('refuses an unknown image or malformed request before creating a job', async () => {
    const app = await buildApp();
    mocks.getImage.mockReturnValueOnce(undefined);
    const missing = await app.inject({
      method: 'POST',
      url: '/api/images/missing/kernel-backport',
      payload: { repoPath: '/srv/linux', record: record() },
    });
    expect(missing.statusCode).toBe(404);

    const invalid = await app.inject({
      method: 'POST',
      url: '/api/images/image-1/kernel-backport',
      payload: { repoPath: '../linux', record: record() },
    });
    expect(invalid.statusCode).toBe(400);
    expect(mocks.startJob).not.toHaveBeenCalled();
    await app.close();
  });

  it('queues only the parsed record and persists source-tree evidence without findings', async () => {
    const evidence = { artifactBinding: 'unverified', coverage: 'complete', matches: [] };
    mocks.compareKernelBackports.mockResolvedValue(evidence);
    const app = await buildApp();
    const response = await app.inject({
      method: 'POST',
      url: '/api/images/image-1/kernel-backport',
      payload: { repoPath: '/srv/linux', record: record(), limits: { maxCommits: 8 } },
    });
    expect(response.statusCode).toBe(202);
    expect(response.json()).toEqual({ jobId: 'kernel-backport-job' });
    expect(mocks.startJob).toHaveBeenCalledWith(
      'image-1',
      'kernel-backport',
      {
        repoPath: '/srv/linux',
        cveId: 'CVE-2026-43286',
        limits: { maxCommits: 8, timeoutMs: 30_000, maxPatchBytes: 2 * 1024 * 1024 },
      },
      expect.any(Function),
    );
    expect(await queuedWork?.()).toBe(evidence);
    expect(mocks.compareKernelBackports).toHaveBeenCalledWith(
      '/srv/linux',
      expect.objectContaining({ cveId: 'CVE-2026-43286', fixCommits: ['b'.repeat(40)] }),
      { maxCommits: 8, timeoutMs: 30_000, maxPatchBytes: 2 * 1024 * 1024 },
    );
    expect(mocks.syncFindings).not.toHaveBeenCalled();
    await app.close();
  });

  it('returns the newest completed backport job result', async () => {
    mocks.listJobs.mockReturnValue([
      { kind: 'kernel-backport', status: 'done', resultJson: '{"coverage":"partial"}' },
      { kind: 'kernel-backport', status: 'done', resultJson: '{"coverage":"complete"}' },
    ]);
    const app = await buildApp();
    const response = await app.inject({ method: 'GET', url: '/api/images/image-1/kernel-backport' });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ result: { coverage: 'partial' } });
    await app.close();
  });
});
