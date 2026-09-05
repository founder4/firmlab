/**
 * Minimal in-process job runner with bounded concurrency. Long-running providers (extraction, emulation, SBOM,
 * decompilation, gitleaks, diff) run as jobs so the UI can poll status/log without blocking a request. Jobs are
 * persisted in SQLite; this runner moves a job through queued → running → done/error and streams log lines into
 * the row. Completed rows are durable, but executable closures are intentionally process-local: startup marks
 * leftover queued/running rows as interrupted rather than claiming to resume them. At most
 * FIRMLAB_MAX_CONCURRENT_JOBS run at once (default 2) so a burst of heavy tool invocations (binwalk -Me + syft +
 * QEMU …) can't exhaust CPU/RAM; the rest wait in `queued`.
 *
 * The admission rule itself lives in job-scheduler.ts and is unit-tested there: this module imports store.js, and
 * anything in a module that imports store.js is out of vitest's reach. What stays here is exactly the part that
 * needs a row — persisting the initial status the scheduler's answer implies, and releasing the slot in a
 * `finally` so a failed or throwing job frees capacity the same way a successful one does.
 */
import { randomUUID } from 'node:crypto';
import { type JobKind, appendJobLog, insertJob, updateJobStatus } from '../store.js';
import { type JobSlot, createJobScheduler, resolveConcurrencyCap } from './job-scheduler.js';

export interface JobHandle {
  id: string;
  log: (line: string) => void;
}

export interface JobLifecycle<T> {
  /** Runs only after the successful result is durable. Cleanup failures are logged and never rewrite success. */
  afterPersist?: (handle: JobHandle, result: T) => void;
}

const scheduler = createJobScheduler(resolveConcurrencyCap(process.env.FIRMLAB_MAX_CONCURRENT_JOBS, 2));

/**
 * Create a job row and run `work` respecting the concurrency cap. Returns the job id immediately. `work`
 * receives a handle it can use to append log lines; its resolved value is stored as the job result JSON. A job
 * admitted while `FIRMLAB_MAX_CONCURRENT_JOBS` are already running is persisted as `queued` and started when a
 * slot frees.
 */
export function startJob<T>(
  imageId: string,
  kind: JobKind,
  params: Record<string, unknown>,
  work: (handle: JobHandle) => Promise<T>,
  lifecycle: JobLifecycle<T> = {},
): string {
  const id = randomUUID().slice(0, 12);
  const now = Date.now();
  const slot = scheduler.tryAdmit();
  try {
    insertJob({
      id,
      imageId,
      kind,
      status: slot ? 'running' : 'queued',
      createdAt: now,
      updatedAt: now,
      params: JSON.stringify(params),
      log: '',
      resultJson: null,
      error: null,
    });
  } catch (err) {
    // The slot is taken BEFORE the row exists, because the row has to record which status admission implied. So
    // the one statement between taking it and being able to release it in `run`'s `finally` is this insert, and
    // an insert that throws would strand the slot — permanently lowering the cap for the life of the process,
    // one failed insert at a time, until nothing starts at all. The old code could not have this bug because it
    // did not count a slot until `run()`; the extraction moved the decision earlier and has to pay for it here.
    slot?.release();
    throw err;
  }

  const handle: JobHandle = { id, log: (line: string) => appendJobLog(id, line) };

  const run = (held: JobSlot): void => {
    // Fire-and-forget; the row carries all state the UI needs.
    void (async () => {
      try {
        const result = await work(handle);
        updateJobStatus(id, 'done', JSON.stringify(result ?? null), null);
        try {
          lifecycle.afterPersist?.(handle, result);
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          appendJobLog(id, `WARNING: post-persist cleanup failed: ${message}`);
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        appendJobLog(id, `ERROR: ${message}`);
        updateJobStatus(id, 'error', null, message);
      } finally {
        // Releasing hands the slot straight to the next queued job, if there is one.
        held.release();
      }
    })();
  };

  if (slot) {
    run(slot);
  } else {
    scheduler.enqueue((granted) => {
      updateJobStatus(id, 'running', null, null);
      run(granted);
    });
  }

  return id;
}
