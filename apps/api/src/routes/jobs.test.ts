/** Cancellation HTTP contract without opening the persisted corpus. */
import Fastify from 'fastify';
import { expect, it, vi } from 'vitest';
const state = vi.hoisted(() => ({ get: vi.fn(), cancel: vi.fn() }));
vi.mock('../store.js', () => ({ getJob: state.get, getImage: vi.fn(), listJobs: vi.fn() }));
vi.mock('../providers/jobs.js', () => ({ cancelJob: state.cancel, startJob: vi.fn() }));
vi.mock('../providers/extract.js', () => ({ runExtraction: vi.fn() }));
import { jobRoutes } from './jobs.js';
it('returns 404 for unknown jobs and 202 with the durable status for known jobs', async () => {
  const app = Fastify();
  await app.register(jobRoutes);
  try {
    state.get.mockReturnValue(undefined);
    expect((await app.inject({ method: 'POST', url: '/jobs/missing/cancel' })).statusCode).toBe(404);
    expect(state.cancel).not.toHaveBeenCalled();
    state.get.mockReturnValue({
      id: 'known',
      status: 'cancelled',
      params: '{}',
      log: '',
      resultJson: null,
      error: null,
    });
    const response = await app.inject({ method: 'POST', url: '/jobs/known/cancel' });
    expect(response.statusCode).toBe(202);
    expect(response.json().job.status).toBe('cancelled');
    expect(state.cancel).toHaveBeenCalledWith('known');
  } finally {
    await app.close();
  }
});
