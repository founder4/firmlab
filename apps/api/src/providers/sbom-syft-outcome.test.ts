/**
 * The two ways the SBOM half of the lane does not answer, told apart by a value — the twin of
 * `sbom-grype-outcome.test.ts` on the other end of the lane.
 *
 * `available: false` covered a syft that is not installed AND a syft that ran and threw. W9 sent both to
 * `remedy: 'install-tool'` with the hand-written note `'syft/grype not installed'`, false whenever syft was
 * installed and the invocation failed — the one case a coverage campaign could have settled by asking again.
 * `reason` distinguished them, but `opacidad-remedy.ts` refuses to read a remedy out of prose, so the discriminant
 * is `syftOutcome`.
 *
 * Drives the real `runSbom` rather than a fixture of its output: the case that matters is syft ON PATH and the
 * invocation failing anyway, which a hand-written result could not prove. `node:child_process` is mocked so no
 * tool is required.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { remedyForSyftOutcome } from '../opacidad-remedy.js';
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

const SYFT_OK = JSON.stringify({ artifacts: [{ name: 'busybox', version: '1.31.1', type: 'binary' }] });
const handle: JobHandle = { id: 'job', log: () => {} };

type ExecFileCallback = (err: Error | null, out: { stdout: string; stderr: string }) => void;

beforeEach(() => {
  child.mockReset();
  toolAvailable.mockReset();
  vi.resetModules();
});

describe('syft present, execution throws', () => {
  it('records run_failed, and W9 queues it as a retry rather than as a deployment to fix', async () => {
    toolAvailable.mockResolvedValue(true);
    child.mockImplementation((file: string, _args: string[], _opts: unknown, cb: ExecFileCallback) => {
      if (file === 'syft') return cb(new Error('signal: killed'), { stdout: '', stderr: '' });
      return cb(new Error('grype must never be reached — syft failed first'), { stdout: '', stderr: '' });
    });

    const { runSbom } = await import('./sbom.js');
    const r = await runSbom('img', '/rootfs', handle);

    expect(r.available).toBe(false);
    expect(r.syftOutcome).toBe('run_failed');
    expect(r.reason).toContain('syft failed:');
    expect(remedyForSyftOutcome(r.syftOutcome)).toBe('retry');
    // syft failing settles the job before grype is reached: only syft was ever spawned.
    expect(child.mock.calls.map((c) => c[0])).toEqual(['syft']);
  });
});

describe('syft not installed', () => {
  it('keeps install-tool, and never spawns syft', async () => {
    toolAvailable.mockResolvedValue(false);

    const { runSbom } = await import('./sbom.js');
    const r = await runSbom('img', '/rootfs', handle);

    expect(r.available).toBe(false);
    expect(r.syftOutcome).toBe('tool_absent');
    expect(r.reason).toBe('syft not installed');
    expect(remedyForSyftOutcome(r.syftOutcome)).toBe('install-tool');
    expect(child.mock.calls).toHaveLength(0);
  });
});

describe('syft ran', () => {
  it('records ran on an available result', async () => {
    toolAvailable.mockImplementation(async (id: string) => id === 'syft'); // grype absent → syft is the whole answer
    child.mockImplementation((file: string, _args: string[], _opts: unknown, cb: ExecFileCallback) => {
      if (file === 'syft') return cb(null, { stdout: SYFT_OK, stderr: '' });
      return cb(new Error('grype absent'), { stdout: '', stderr: '' });
    });

    const { runSbom } = await import('./sbom.js');
    const r = await runSbom('img', '/rootfs', handle);

    expect(r.available).toBe(true);
    expect(r.syftOutcome).toBe('ran');
    expect(r.packages.map((p) => p.name)).toEqual(['busybox']);
  });
});

describe('remedyForSyftOutcome — pure mapping', () => {
  it('maps recorded failures and absence without inventing a remedy for unknown or successful outcomes', () => {
    expect(remedyForSyftOutcome('run_failed')).toBe('retry');
    expect(remedyForSyftOutcome('tool_absent')).toBe('install-tool');
    expect(remedyForSyftOutcome('ran')).toBeUndefined();
    expect(remedyForSyftOutcome(undefined)).toBeUndefined();
  });
});
