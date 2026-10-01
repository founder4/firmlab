import { expect, it, vi } from 'vitest';
import { JobCancelledError } from '../job-cancellation.js';
import { agentJobFailureStatus, waitForAgentJob } from './job-wait.js';
it('halts the next agent stage immediately on operator cancellation without interpreting a result', async () => {
  const read = vi.fn(() => ({ status: 'cancelled', resultJson: '{"ran":true}', error: null }));
  const next = vi.fn();
  await expect(waitForAgentJob(read).then(next)).rejects.toBeInstanceOf(JobCancelledError);
  expect(next).not.toHaveBeenCalled();
  expect(read).toHaveBeenCalledTimes(1);
  expect(agentJobFailureStatus(new JobCancelledError())).toBe('halted');
  expect(agentJobFailureStatus(new Error('tool failed'))).toBe('error');
});
it('waits through pending cleanup and halts once cancellation is terminal', async () => {
  const read = vi
    .fn()
    .mockReturnValueOnce({ status: 'cancelling', resultJson: null, error: null })
    .mockReturnValue({ status: 'cancelled', resultJson: null, error: null });
  await expect(waitForAgentJob(read, 1000, 1)).rejects.toBeInstanceOf(JobCancelledError);
  expect(read).toHaveBeenCalledTimes(2);
});
