import Fastify from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  getImage: vi.fn(),
  listJobs: vi.fn(),
  startJob: vi.fn(),
  runSwitchFamilyAnalysis: vi.fn(),
  syncFindings: vi.fn(),
}));
vi.mock('../store.js', () => ({ getImage: mocks.getImage, listJobs: mocks.listJobs }));
vi.mock('../providers/jobs.js', () => ({ startJob: mocks.startJob }));
vi.mock('../providers/switch-family.js', () => ({ runSwitchFamilyAnalysis: mocks.runSwitchFamilyAnalysis }));
vi.mock('../findings.js', () => ({ syncFindings: mocks.syncFindings }));

import { switchFamilyRoutes } from './switch-family.js';

describe('switch-family routes', () => {
  let queued: ((handle: { log: (line: string) => void; signal?: AbortSignal }) => Promise<unknown>) | undefined;
  beforeEach(() => {
    vi.clearAllMocks();
    queued = undefined;
    mocks.getImage.mockReturnValue({ path: '/image.bin' });
    mocks.listJobs.mockReturnValue([]);
    mocks.startJob.mockImplementation((_id, _kind, _params, work) => {
      queued = work;
      return 'switch-job';
    });
    mocks.runSwitchFamilyAnalysis.mockResolvedValue({
      raw: { reason: 'raw scan completed' },
      rootfs: { status: 'not-run', reason: 'not run: no extracted rootfs' },
      overall: { summary: 'static lead' },
    });
  });

  async function request(method: 'GET' | 'POST') {
    const app = Fastify();
    await app.register(switchFamilyRoutes);
    try {
      return await app.inject({ method, url: '/images/image-1/switch-family' });
    } finally {
      await app.close();
    }
  }

  it('returns 404 for an unknown image and creates no job', async () => {
    mocks.getImage.mockReturnValue(undefined);
    expect((await request('POST')).statusCode).toBe(404);
    expect(mocks.startJob).not.toHaveBeenCalled();
  });

  it('queues raw-only analysis when extraction has not run, preserving the gate explanation', async () => {
    const response = await request('POST');
    expect(response.statusCode).toBe(202);
    expect(response.json()).toEqual({ jobId: 'switch-job' });
    expect(mocks.startJob).toHaveBeenCalledWith('image-1', 'switch-family', {}, expect.any(Function));
    const result = await queued?.({ log: vi.fn() });
    expect(mocks.runSwitchFamilyAnalysis).toHaveBeenCalledWith('/image.bin', null, undefined, undefined);
    expect(result).toMatchObject({
      rootfs: { status: 'not-run', reason: expect.stringContaining('extraction-not-run') },
    });
    expect(mocks.syncFindings).not.toHaveBeenCalled();
  });

  it('uses a previously completed rootfs even if a newer extraction failed and forwards cancellation', async () => {
    mocks.listJobs.mockReturnValue([
      { kind: 'extract', status: 'error' },
      { kind: 'extract', status: 'done', resultJson: JSON.stringify({ rootfsPath: '/rootfs' }) },
    ]);
    await request('POST');
    const signal = new AbortController().signal;
    await queued?.({ log: vi.fn(), signal });
    expect(mocks.runSwitchFamilyAnalysis).toHaveBeenCalledWith('/image.bin', '/rootfs', undefined, signal);
    expect(mocks.syncFindings).not.toHaveBeenCalled();
  });

  it('keeps an extraction with no rootfs distinct from extraction never run', async () => {
    mocks.listJobs.mockReturnValue([{ kind: 'extract', status: 'done', resultJson: '{"rootfsPath":null}' }]);
    expect((await request('POST')).statusCode).toBe(202);
    expect(await queued?.({ log: vi.fn() })).toMatchObject({
      rootfs: { reason: expect.stringContaining('extraction-found-no-rootfs') },
    });
  });

  it('returns null before a completed result exists', async () => {
    mocks.listJobs.mockReturnValue([{ kind: 'switch-family', status: 'running' }]);
    expect((await request('GET')).json()).toEqual({ result: null });
  });

  it('returns the latest done result, skipping running and unrelated jobs', async () => {
    mocks.listJobs.mockReturnValue([
      { kind: 'switch-family', status: 'running' },
      { kind: 'rtos', status: 'done', resultJson: '{}' },
      { kind: 'switch-family', status: 'done', resultJson: '{"overall":{"verdict":"ambiguous"}}' },
      { kind: 'switch-family', status: 'done', resultJson: '{"overall":{"verdict":"none-observed"}}' },
    ]);
    expect((await request('GET')).json()).toEqual({ result: { overall: { verdict: 'ambiguous' } } });
  });
});
