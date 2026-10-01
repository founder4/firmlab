/** Store-free job polling for agent stages: operator cancellation halts the chain before any result interpretation. */
import { JobCancelledError } from '../job-cancellation.js';
export interface AgentJobRow {
  status: string;
  resultJson: string | null;
  error: string | null;
}
export async function waitForAgentJob(
  read: () => AgentJobRow | undefined,
  timeoutMs = 15 * 60_000,
  pollMs = 250,
): Promise<{ status: string; result: unknown; error: string | null }> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const row = read();
    if (row?.status === 'cancelled') throw new JobCancelledError();
    if (row && (row.status === 'done' || row.status === 'error')) {
      return { status: row.status, result: row.resultJson ? JSON.parse(row.resultJson) : null, error: row.error };
    }
    if (Date.now() > deadline) return { status: 'error', result: null, error: 'job timed out' };
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
}
export function agentJobFailureStatus(error: unknown): 'halted' | 'error' {
  return error instanceof JobCancelledError ? 'halted' : 'error';
}
