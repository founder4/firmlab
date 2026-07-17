/**
 * Minimal in-process job runner with bounded concurrency. Long-running providers (extraction, emulation, SBOM,
 * decompilation, gitleaks, diff) run as jobs so the UI can poll status/log without blocking a request. Jobs are
 * persisted in SQLite; this runner moves a job through queued → running → done/error and streams log lines into
 * the row. At most FIRMLAB_MAX_CONCURRENT_JOBS run at once (default 2) so a burst of heavy tool invocations
 * (binwalk -Me + syft + QEMU …) can't exhaust CPU/RAM; the rest wait in `queued`.
 */
import { randomUUID } from 'node:crypto';
import { type JobKind, appendJobLog, insertJob, updateJobStatus } from '../store.js';

export interface JobHandle {
  id: string;
  log: (line: string) => void;
}

const MAX_CONCURRENT = Math.max(1, Number(process.env.FIRMLAB_MAX_CONCURRENT_JOBS ?? 2));

let active = 0;
/** Starters for jobs admitted while the runner was at capacity; each launches one queued job. */
const waiting: Array<() => void> = [];

/**
 * Create a job row and run `work` respecting the concurrency cap. Returns the job id immediately. `work`
 * receives a handle it can use to append log lines; its resolved value is stored as the job result JSON. A job
 * admitted while `MAX_CONCURRENT` are already running is persisted as `queued` and started when a slot frees.
 */
export function startJob<T>(
  imageId: string,
  kind: JobKind,
  params: Record<string, unknown>,
  work: (handle: JobHandle) => Promise<T>,
): string {
  const id = randomUUID().slice(0, 12);
  const now = Date.now();
  const admitNow = active < MAX_CONCURRENT;
  insertJob({
    id,
    imageId,
    kind,
    status: admitNow ? 'running' : 'queued',
    createdAt: now,
    updatedAt: now,
    params: JSON.stringify(params),
    log: '',
    resultJson: null,
    error: null,
  });

  const handle: JobHandle = { id, log: (line: string) => appendJobLog(id, line) };

  const run = (): void => {
    active++;
    // Fire-and-forget; the row carries all state the UI needs.
    void (async () => {
      try {
        const result = await work(handle);
        updateJobStatus(id, 'done', JSON.stringify(result ?? null), null);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        appendJobLog(id, `ERROR: ${message}`);
        updateJobStatus(id, 'error', null, message);
      } finally {
        active--;
        pump();
      }
    })();
  };

  if (admitNow) {
    run();
  } else {
    waiting.push(() => {
      updateJobStatus(id, 'running', null, null);
      run();
    });
  }

  return id;
}

/** Start the next queued job if a concurrency slot is free. */
function pump(): void {
  if (active >= MAX_CONCURRENT) return;
  const next = waiting.shift();
  if (next) next();
}
