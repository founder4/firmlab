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

/**
 * Wire syft, `grype db status` (answering `dbStatus`) and an empty grype scan, recording the environment each one
 * was spawned with — the network policy lives in those variables, so that is what the assertions read.
 */
interface SpawnEnvs {
  syft: NodeJS.ProcessEnv | undefined;
  status: (NodeJS.ProcessEnv | undefined)[];
  scan: NodeJS.ProcessEnv | undefined;
}

function recordEnvs(dbStatus: string): SpawnEnvs {
  const envs: SpawnEnvs = { syft: undefined, status: [], scan: undefined };
  child.mockImplementation((file: string, args: string[], opts: { env?: NodeJS.ProcessEnv }, cb: ExecFileCallback) => {
    if (file === 'syft') {
      envs.syft = opts.env;
      return cb(null, { stdout: SYFT_OK, stderr: '' });
    }
    if (args[0] === 'db') {
      envs.status.push(opts.env);
      return cb(null, { stdout: dbStatus, stderr: '' });
    }
    envs.scan = opts.env;
    return cb(null, { stdout: JSON.stringify({ matches: [] }), stderr: '' });
  });
  return envs;
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
    // No matches were made, so there is no KEV state at all — not asked, not zero.
    expect(r.grypeKev).toBeUndefined();
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

  // The research lane is on unless stated (2026-10-04), and it is what permits the download — so the refusal is
  // only reachable with research stated off, which is what this case states.
  it('keeps a grype with no vulnerability database on install-tool, and does not download one', async () => {
    vi.stubEnv('FIRMLAB_RESEARCH', '0');
    toolAvailable.mockResolvedValue(true);
    withGrype((args) =>
      args[0] === 'db' ? JSON.stringify({ valid: false, error: 'no database found' }) : new Error('never invoked'),
    );

    try {
      const { runSbom } = await import('./sbom.js');
      const r = await runSbom('img', '/rootfs', handle);

      expect(r.grypeOutcome).toBe('db_absent');
      expect(remedyForGrypeOutcome(r.grypeOutcome)).toBe('install-tool');
      // grype was asked what database it has and then not run: no scan, and above all no fetch.
      expect(child.mock.calls.filter((c) => c[0] === 'grype').map((c) => (c[1] as string[])[0])).toEqual(['db']);
      expect(r.grypeReason).toContain('downloads one only under the research lane');
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it('lets grype fetch its database under the DEFAULT research lane, and says the permission was a default', async () => {
    vi.stubEnv('FIRMLAB_RESEARCH', undefined);
    toolAvailable.mockResolvedValue(true);
    const logged: string[] = [];
    const spy: JobHandle = { id: 'job', log: (line: string) => void logged.push(line) };
    const envs = recordEnvs(JSON.stringify({ valid: false, error: 'no database' }));

    try {
      const { runSbom } = await import('./sbom.js');
      const r = await runSbom('img', '/rootfs', spy);

      // The same lane the Settings panel and the research run report as on does not refuse here.
      expect(r.grypeOutcome).not.toBe('db_absent');
      // The scan alone may fetch; syft and every `db status` reading stay offline.
      expect(envs.scan?.GRYPE_DB_AUTO_UPDATE).toBe('true');
      expect(envs.syft?.GRYPE_DB_AUTO_UPDATE).toBe('false');
      expect(envs.status.length).toBeGreaterThan(0);
      for (const e of envs.status) expect(e?.GRYPE_DB_AUTO_UPDATE).toBe('false');
      expect(logged.some((l) => l.includes('ON by default') && l.includes('FIRMLAB_RESEARCH=0'))).toBe(true);
    } finally {
      vi.unstubAllEnvs();
    }
  });
});

/**
 * A present database is used as it is, research lane or not. The lane used to put `GRYPE_DB_AUTO_UPDATE=true` on
 * every anchore invocation, so a provisioned database was refreshed under a log line saying no request is made.
 */
describe('a present database with the research lane on', () => {
  it.each([
    ['on by default', undefined],
    ['stated on', '1'],
  ])('scans offline with the lane %s, and the log says so truthfully', async (_label, research) => {
    vi.stubEnv('FIRMLAB_RESEARCH', research);
    toolAvailable.mockResolvedValue(true);
    const logged: string[] = [];
    const spy: JobHandle = { id: 'job', log: (line: string) => void logged.push(line) };
    const envs = recordEnvs(DB_PRESENT);

    try {
      const { runSbom } = await import('./sbom.js');
      const r = await runSbom('img', '/rootfs', spy);

      expect(r.grypeOutcome).toBe('matched');
      expect(envs.scan?.GRYPE_DB_AUTO_UPDATE).toBe('false');
      expect(envs.syft?.GRYPE_DB_AUTO_UPDATE).toBe('false');
      for (const e of envs.status) expect(e?.GRYPE_DB_AUTO_UPDATE).toBe('false');
      expect(logged.some((l) => l.includes('No network request is made'))).toBe(true);
      expect(logged.some((l) => l.includes('permitted to download'))).toBe(false);
    } finally {
      vi.unstubAllEnvs();
    }
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
    // No `descriptor.db.providers.kev` in this output: the KEV state is unknown, not a zero.
    expect(r.grypeKev?.state).toBe('no-kev-provider');
  });

  it('carries grype’s offline KEV annotation onto the result, dated by the database’s kev snapshot', async () => {
    toolAvailable.mockResolvedValue(true);
    withGrype((args) =>
      args[0] === 'db'
        ? DB_PRESENT
        : JSON.stringify({
            descriptor: { db: { providers: { kev: { captured: '2026-09-26T00:33:03Z' } } } },
            matches: [
              {
                vulnerability: {
                  id: 'GHSA-jfh8-c2jp-5v3q',
                  severity: 'Critical',
                  knownExploited: [{ cve: 'CVE-2021-44228', dateAdded: '2021-12-10' }],
                },
                artifact: { name: 'log4j-core', version: '2.14.1' },
              },
            ],
          }),
    );

    const { runSbom } = await import('./sbom.js');
    const r = await runSbom('img', '/rootfs', handle);

    expect(r.grypeKev).toMatchObject({ state: 'annotated', captured: '2026-09-26T00:33:03Z' });
    expect(r.grypeKev?.state === 'annotated' && r.grypeKev.matches.map((m) => m.cve)).toEqual(['CVE-2021-44228']);
  });
});

/**
 * A grype that exits 0 without its document. Defaulting a missing `matches` to `[]` turned that into a measured
 * zero — and, with a kev provider in the descriptor, into an annotated KEV zero — for a run that measured nothing.
 */
describe('grype output without a top-level matches array', () => {
  const KEV_DESCRIPTOR = { db: { providers: { kev: { captured: '2026-09-26T00:33:03Z' } } } };

  it.each([
    ['missing', { descriptor: KEV_DESCRIPTOR }],
    ['an object', { descriptor: KEV_DESCRIPTOR, matches: {} }],
    ['null', { descriptor: KEV_DESCRIPTOR, matches: null }],
    ['a whole document of null', null],
  ])('is run_failed with no KEV state when matches is %s', async (_label, out) => {
    toolAvailable.mockResolvedValue(true);
    withGrype((args) => (args[0] === 'db' ? DB_PRESENT : JSON.stringify(out)));

    const { runSbom } = await import('./sbom.js');
    const r = await runSbom('img', '/rootfs', handle);

    expect(r.grypeOutcome).toBe('run_failed');
    expect(r.grypeAvailable).toBe(false);
    expect(r.grypeKev).toBeUndefined();
    expect(r.grypeDb).toBeUndefined();
    expect(r.vulnerabilityTotal).toBe(0);
    expect(r.grypeReason).toContain('no top-level matches array');
    expect(r.packages.map((p) => p.name)).toEqual(['busybox']);
  });

  it('keeps an empty matches array from a kev-bearing database as an annotated, measured zero', async () => {
    toolAvailable.mockResolvedValue(true);
    withGrype((args) => (args[0] === 'db' ? DB_PRESENT : JSON.stringify({ descriptor: KEV_DESCRIPTOR, matches: [] })));

    const { runSbom } = await import('./sbom.js');
    const r = await runSbom('img', '/rootfs', handle);

    expect(r.grypeOutcome).toBe('matched');
    expect(r.vulnerabilityTotal).toBe(0);
    expect(r.grypeKev).toEqual({ state: 'annotated', captured: '2026-09-26T00:33:03Z', matches: [] });
  });

  it('keeps a KEV annotation on a row the VULN_CAP listing cuts, because annotation reads every match', async () => {
    toolAvailable.mockResolvedValue(true);
    const critical = Array.from({ length: 1000 }, (_, i) => ({
      vulnerability: { id: `CVE-2099-${10000 + i}`, severity: 'Critical' },
      artifact: { name: 'pkg', version: '1' },
    }));
    // Low severity ranks it below 1 000 criticals: it is the row the cap drops from the listing.
    const tail = {
      vulnerability: {
        id: 'CVE-2021-44228',
        severity: 'Low',
        knownExploited: [{ cve: 'CVE-2021-44228', dateAdded: '2021-12-10' }],
      },
      artifact: { name: 'log4j-core', version: '2.14.1' },
    };
    withGrype((args) =>
      args[0] === 'db' ? DB_PRESENT : JSON.stringify({ descriptor: KEV_DESCRIPTOR, matches: [...critical, tail] }),
    );

    const { runSbom } = await import('./sbom.js');
    const r = await runSbom('img', '/rootfs', handle);

    expect(r.vulnerabilityTotal).toBe(1001);
    expect(r.vulnerabilities).toHaveLength(1000);
    expect(r.vulnerabilities.map((v) => v.id)).not.toContain('CVE-2021-44228');
    expect(r.grypeKev?.state === 'annotated' && r.grypeKev.matches.map((m) => m.cve)).toEqual(['CVE-2021-44228']);
  });
});
