/** Cancellation cannot replace a previously persisted finding set with partial provider output. */
import { expect, it, vi } from 'vitest';
import { JobCancellation, jobCancellation } from './job-cancellation.js';
const mutations = vi.hoisted(() => ({ delete: vi.fn(), insert: vi.fn() }));
vi.mock('./store.js', () => ({
  deleteFindingsBySource: mutations.delete,
  insertFindings: mutations.insert,
  getFinding: vi.fn(),
  getImage: vi.fn(),
  insertImageNote: vi.fn(),
  listFindingsBySource: vi.fn(),
  updateFindingAssertion: vi.fn(),
}));
import { syncFindings } from './findings.js';
it('refuses findings synchronization before any mutation after cancellation', () => {
  const owner = new JobCancellation();
  owner.cancel();
  expect(() => jobCancellation.run(owner, () => syncFindings('img', 'extract', []))).toThrow('Job cancelled');
  expect(mutations.delete).not.toHaveBeenCalled();
  expect(mutations.insert).not.toHaveBeenCalled();
});
