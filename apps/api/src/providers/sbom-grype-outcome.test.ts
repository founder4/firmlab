/**
 * The three ways the CVE half of the SBOM lane does not answer, told apart by a value.
 *
 * `grypeAvailable: false` covered a grype that is not installed, a grype with no vulnerability database, and a
 * grype that ran and threw. W9 sent all three to `remedy: 'install-tool'`, so the only one a coverage campaign
 * could have settled by asking again was reported as a deployment for an operator to go and fix. The sentence in
 * `grypeReason` distinguished them, but `opacidad-remedy.ts` refuses to read a remedy out of English prose.
 *
 * This file drives the real `runSbom` rather than a fixture of its output, because the case that matters is the
 * one where everything IS present: grype on PATH, a valid database on disk, and the invocation failing anyway.
 * Asserting that on a hand-written result would only prove the fixture. `node:child_process` is mocked so no tool
 * is required and no database is ever consulted — the unit suite never needs the real binaries.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { remedyForGrypeOutcome } from '../opacidad-remedy.js';
import type { JobHandle } from './jobs.js';

const { child, toolAvailable } = vi.hoisted(() => ({ child: vi.fn(), toolAvailable: vi.fn() }));

vi.mock('node:child_process', async (importOriginal) => ({
  ...(await importOriginal<typeof import('node:child_process')>()),
  execFile: child,
}));
vi.mock('../tools.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../tools.js')>()),
  isToolAvailable: toolAvailable,
}));

/** grype's own `db status -o json`, as it prints it when a provisioned database is there and valid. */
const DB_PRESENT = JSON.stringify({
  valid: true,
  schemaVersion: '6',
  built: new Date().toISOString(),
  path: '/data/grype-db',
  from: 'https://grype.anchore.io/databases',
});
const SYFT_OK = JSON.stringify({ artifacts: [{ name: 'busybox', version: '1.31.1', type: 'binary' }] });

const handle: JobHandle = { id: 'job', log: () => {} };

type ExecFileCallback = (err: Error | null, out: { stdout: string; stderr: string }) => void;

/**
 * Wire the two child processes this lane spawns. `promisify` wraps the mock callback-style (a plain `vi.fn` carries
 * no `util.promisify.custom`), so the callback hands back the whole `{ stdout }` object the callers destructure.
 */
function withGrype(grype: (args: string[]) => string | Error): void {
  child.mockImplementation((file: string, args: string[], _opts: unknown, cb: ExecFileCallback) => {
    if (file === 'syft') return cb(null, { stdout: SYFT_OK, stderr: '' });
    const out = grype(args);
    return out instanceof Error ? cb(out, { stdout: '', stderr: '' }) : cb(null, { stdout: out, stderr: '' });
  });
}

beforeEach(() => {
  child.mockReset();
  toolAvailable.mockReset();
  vi.resetModules();
});

describe('grype present, database present, execution throws', () => {
  it('records run_failed, and W9 queues it as a retry rather than as a deployment to fix', async () => {
    toolAvailable.mockResolvedValue(true);
    withGrype((args) => (args[0] === 'db' ? DB_PRESENT : new Error('signal: killed')));

    const { runSbom } = await import('./sbom.js');
    const r = await runSbom('img', '/rootfs', handle);

    expect(r.available).toBe(true);
    expect(r.grypeAvailable).toBe(false);
    expect(r.grypeOutcome).toBe('run_failed');
    // The database WAS consulted and WAS there: this is not the missing-database refusal wearing another name.
    expect(child.mock.calls.map((c) => [c[0], (c[1] as string[])[0]])).toContainEqual(['grype', 'db']);
    expect(r.grypeReason).toContain('attempted and failed');
    expect(remedyForGrypeOutcome(r.grypeOutcome)).toBe('retry');
    // The SBOM is unaffected — the whole point of catching the failure rather than failing the job.
    expect(r.packages.map((p) => p.name)).toEqual(['busybox']);
  });
});

describe('the two outcomes that are the deployment, not the run', () => {
  it('keeps a grype that is not installed on install-tool, and never spawns it', async () => {
    toolAvailable.mockImplementation(async (id: string) => id === 'syft');
    withGrype(() => new Error('should not be reached'));

    const { runSbom } = await import('./sbom.js');
    const r = await runSbom('img', '/rootfs', handle);

    expect(r.grypeOutcome).toBe('tool_absent');
    expect(remedyForGrypeOutcome(r.grypeOutcome)).toBe('install-tool');
    expect(child.mock.calls.map((c) => c[0])).toEqual(['syft']);
  });

  it('keeps a grype with no vulnerability database on install-tool, and does not download one', async () => {
    toolAvailable.mockResolvedValue(true);
    withGrype((args) =>
      args[0] === 'db' ? JSON.stringify({ valid: false, error: 'no database found' }) : new Error('never invoked'),
    );

    const { runSbom } = await import('./sbom.js');
    const r = await runSbom('img', '/rootfs', handle);

    expect(r.grypeOutcome).toBe('db_absent');
    expect(remedyForGrypeOutcome(r.grypeOutcome)).toBe('install-tool');
    // grype was asked what database it has and then not run: no scan, and above all no fetch.
    expect(child.mock.calls.filter((c) => c[0] === 'grype').map((c) => (c[1] as string[])[0])).toEqual(['db']);
    expect(r.grypeReason).toContain('never downloads one on its own');
  });
});

describe('grype answered', () => {
  it('reports matched, which is not a degradation at all', async () => {
    toolAvailable.mockResolvedValue(true);
    withGrype((args) =>
      args[0] === 'db'
        ? DB_PRESENT
        : JSON.stringify({
            matches: [
              {
                vulnerability: { id: 'CVE-2021-42374', severity: 'Medium', fix: { versions: ['1.34.0'] } },
                artifact: { name: 'busybox', version: '1.31.1' },
              },
            ],
          }),
    );

    const { runSbom } = await import('./sbom.js');
    const r = await runSbom('img', '/rootfs', handle);

    expect(r.grypeAvailable).toBe(true);
    expect(r.grypeOutcome).toBe('matched');
    expect(remedyForGrypeOutcome(r.grypeOutcome)).toBeUndefined();
    expect(r.vulnerabilities.map((v) => v.id)).toEqual(['CVE-2021-42374']);
  });
});
