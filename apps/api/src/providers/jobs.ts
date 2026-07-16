/**
 * Minimal in-process job runner. Long-running providers (extraction, emulation, SBOM, decompilation) run as
 * jobs so the UI can poll status/log without blocking a request. Jobs are persisted in SQLite; this runner
 * just moves a job through queued → running → done/error and streams log lines into the row.
 */
import { randomUUID } from 'node:crypto';
import { type JobKind, appendJobLog, insertJob, updateJobStatus } from '../store.js';

export interface JobHandle {
  id: string;
  log: (line: string) => void;
}

/**
 * Create a job row and run `work` in the background. Returns the job id immediately. `work` receives a handle
 * it can use to append log lines; its resolved value is stored as the job result JSON.
 */
export function startJob<T>(
  imageId: string,
  kind: JobKind,
  params: Record<string, unknown>,
  work: (handle: JobHandle) => Promise<T>,
): string {
  const id = randomUUID().slice(0, 12);
  const now = Date.now();
  insertJob({
    id,
    imageId,
    kind,
    status: 'running',
    createdAt: now,
    updatedAt: now,
    params: JSON.stringify(params),
    log: '',
    resultJson: null,
    error: null,
  });

  const handle: JobHandle = { id, log: (line: string) => appendJobLog(id, line) };

  // Fire-and-forget; the row carries all state the UI needs.
  void (async () => {
    try {
      const result = await work(handle);
      updateJobStatus(id, 'done', JSON.stringify(result ?? null), null);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      appendJobLog(id, `ERROR: ${message}`);
      updateJobStatus(id, 'error', null, message);
    }
  })();

  return id;
}
