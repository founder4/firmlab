/** Process-local cancellation ownership. Async context follows nested provider calls without changing persisted results. */
import { AsyncLocalStorage } from 'node:async_hooks';
import type { ChildProcess } from 'node:child_process';
import { processGroupSockets, waitForProcessGroupExit } from './process-group.js';

export class JobCancelledError extends Error {
  constructor() {
    super('Job cancelled by operator; coverage incomplete and no conclusion about the target');
    this.name = 'JobCancelledError';
  }
}

export class JobCancellation {
  readonly controller = new AbortController();
  private readonly failures: Error[] = [];
  private readonly killed = new WeakSet<ChildProcess>();
  private readonly sockets = new WeakMap<ChildProcess, Set<string>>();
  private readonly children = new Set<ChildProcess>();
  private readonly pending = new Set<Promise<void>>();
  get cancelled(): boolean {
    return this.controller.signal.aborted;
  }
  check(): void {
    if (this.cancelled) throw new JobCancelledError();
  }
  track(child: ChildProcess): void {
    this.children.add(child);
    const closed = new Promise<void>((resolve) => {
      const finish = () => {
        void (async () => {
          try {
            this.terminate(child);
          } catch {
            // Verification below decides whether cleanup succeeded even if signalling raced with process exit.
          }
          if (child.pid && process.platform !== 'win32')
            await waitForProcessGroupExit(child.pid, 5000, this.sockets.get(child));
        })()
          .catch((error: unknown) => {
            this.failures.push(error instanceof Error ? error : new Error(String(error)));
          })
          .finally(() => {
            this.children.delete(child);
            resolve();
          });
      };
      child.once('close', finish);
    });
    this.pending.add(closed);
    void closed.then(() => this.pending.delete(closed));
    if (this.cancelled) this.terminate(child);
  }
  terminate(child: ChildProcess): void {
    if (!child.pid || this.killed.has(child)) return;
    try {
      if (!this.sockets.has(child)) this.sockets.set(child, processGroupSockets(child.pid));
      if (process.platform === 'win32') child.kill('SIGKILL');
      else process.kill(-child.pid, 'SIGKILL');
      this.killed.add(child);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ESRCH') throw error;
    }
  }
  requestTermination(child: ChildProcess): void {
    try {
      this.terminate(child);
    } catch (error) {
      this.failures.push(error instanceof Error ? error : new Error(String(error)));
      // Reap the direct child if the group signal was denied; group verification still guards capacity release.
      try {
        child.kill('SIGKILL');
      } catch {
        /* The recorded failure remains authoritative. */
      }
    }
  }
  cancel(): void {
    if (process.platform === 'win32' && this.children.size > 0) {
      throw new Error('Running process-tree cancellation is unsupported on Windows');
    }
    if (!this.cancelled) this.controller.abort();
    for (const child of this.children) this.requestTermination(child);
  }
  async cleanup(): Promise<void> {
    for (const child of this.children) this.requestTermination(child);
    await Promise.all(this.pending);
    if (this.failures.length) throw this.failures[0];
  }
}

export const jobCancellation = new AsyncLocalStorage<JobCancellation>();
/** Terminal rows win; repeated requests for cancelled jobs are harmless. */
export function cancellationDecision(status: string): 'cancel' | 'unchanged' {
  return status === 'queued' || status === 'running' ? 'cancel' : 'unchanged';
}
