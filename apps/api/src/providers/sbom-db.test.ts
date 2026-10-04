/**
 * The SBOM lane's no-egress policy, pinned.
 *
 * Every case here is a sentence from `sbom-db.ts`'s module comment turned into an assertion, and the two that
 * matter most are the ones a passing suite would otherwise never visit: the SUCCESS path, where a database is
 * present and the answer is simply "run, offline" (a guard is only as good as the branch where it finds nothing
 * wrong), and the parse of grype's FAILURE output, which arrives on a rejected promise with exit code 1 and the
 * JSON still on stdout.
 */
import { describe, expect, it } from 'vitest';
import { effectiveEnv, setFlagOverrideProvider } from '../flags.js';
import { loadResearchConfig } from '../research/config.js';
import {
  GRYPE_DB_UPDATE_URL,
  type GrypeDbStatus,
  STALE_DB_DAYS,
  anchoreEnv,
  dbAgeDays,
  dbUpdateAllowed,
  decideGrype,
  grypeDatasetFact,
  grypeDbDir,
  grypeScanEnv,
  parseGrypeDbStatus,
  researchLane,
} from './sbom-db.js';

const NOW = new Date('2026-09-16T12:00:00Z');
const DB_DIR = '/data/grype-db';

const present = (built: string): GrypeDbStatus => ({
  present: true,
  schemaVersion: 'v6.1.9',
  built,
  path: `${DB_DIR}/6/vulnerability.db`,
  from: `${GRYPE_DB_UPDATE_URL}/v6/vulnerability-db_v6.1.9.tar.zst`,
  error: null,
});

const absent: GrypeDbStatus = {
  present: false,
  schemaVersion: null,
  built: null,
  path: `${DB_DIR}/6/vulnerability.db`,
  from: null,
  error: 'database does not exist',
};

describe('anchoreEnv — the environment both anchore tools run under', () => {
  it('turns off every network path grype and syft take on their own initiative, whatever the research lane says', () => {
    // Research stated off, stated on, and unstated (on by default since 2026-10-04): the base environment — the
    // one syft, `grype db status` and the capability reading run under — is offline in all three.
    for (const research of [{ FIRMLAB_RESEARCH: '0' }, { FIRMLAB_RESEARCH: '1' }, {}]) {
      const env = anchoreEnv({ FIRMLAB_DATA_DIR: '/data', ...research });
      // The database download that was measured happening with every lane off.
      expect(env.GRYPE_DB_AUTO_UPDATE).toBe('false');
      // …and the release poll both binaries make on every single invocation.
      expect(env.GRYPE_CHECK_FOR_APP_UPDATE).toBe('false');
      expect(env.SYFT_CHECK_FOR_APP_UPDATE).toBe('false');
    }
  });

  it('does not let grype refuse a deliberately-pinned old database', () => {
    // grype's default is to reject a database older than five days outright. A provisioned one must be USED and
    // reported as old; refusing it would turn a stated bound into silence.
    expect(anchoreEnv({}).GRYPE_DB_VALIDATE_AGE).toBe('false');
  });

  it('puts the database under the data root, where a redeploy does not lose it', () => {
    expect(grypeDbDir({ FIRMLAB_DATA_DIR: '/data' })).toBe('/data/grype-db');
    expect(anchoreEnv({ FIRMLAB_DATA_DIR: '/data' }).GRYPE_DB_CACHE_DIR).toBe('/data/grype-db');
    // An operator who set grype's own knob keeps it.
    expect(grypeDbDir({ FIRMLAB_DATA_DIR: '/data', GRYPE_DB_CACHE_DIR: '/mnt/db' })).toBe('/mnt/db');
  });

  it('pins the download destination so a config file on the deployment cannot redirect it', () => {
    expect(anchoreEnv({ GRYPE_DB_UPDATE_URL: 'https://elsewhere.example/db' }).GRYPE_DB_UPDATE_URL).toBe(
      GRYPE_DB_UPDATE_URL,
    );
  });

  /**
   * The gate reads the research lane exactly as `loadResearchConfig` does. It used to read a literal `=== '1'`, so
   * once research became default-on an unstated deployment had a research lane that was ON and an SBOM lane that
   * refused, telling the operator to turn on a lane that already was.
   */
  it('permits the download exactly when the research lane is on — default included, stated 0 excluded', () => {
    expect(dbUpdateAllowed({})).toBe(true);
    expect(dbUpdateAllowed({ FIRMLAB_RESEARCH: '1' })).toBe(true);
    // Any stated value other than 1 is off, as everywhere else.
    for (const v of ['0', 'true', 'yes', '']) {
      expect(dbUpdateAllowed({ FIRMLAB_RESEARCH: v })).toBe(false);
    }
    // Neither the agent nor the capture lane buys network for the SBOM lane, nor overrides a stated research off.
    expect(dbUpdateAllowed({ FIRMLAB_RESEARCH: '0', FIRMLAB_AGENT: '1', FIRMLAB_CAPTURE: '1' })).toBe(false);
  });

  it('agrees with loadResearchConfig on every environment, so the two lanes cannot disagree about one switch', () => {
    for (const e of [{}, { FIRMLAB_RESEARCH: '1' }, { FIRMLAB_RESEARCH: '0' }, { FIRMLAB_RESEARCH: 'on' }]) {
      expect(dbUpdateAllowed(e)).toBe(loadResearchConfig(e) !== null);
    }
  });

  it('honours a stored Settings override over the environment, in both directions', () => {
    try {
      setFlagOverrideProvider(() => ({ FIRMLAB_RESEARCH: '0' }));
      expect(dbUpdateAllowed(effectiveEnv({ FIRMLAB_RESEARCH: '1' }))).toBe(false);
      expect(dbUpdateAllowed()).toBe(false);
      setFlagOverrideProvider(() => ({ FIRMLAB_RESEARCH: '1' }));
      expect(dbUpdateAllowed(effectiveEnv({ FIRMLAB_RESEARCH: '0' }))).toBe(true);
    } finally {
      setFlagOverrideProvider(() => ({}));
    }
  });

  it('reports whether the permission was a default or a statement', () => {
    expect(researchLane({}).byDefault).toBe(true);
    expect(researchLane({ FIRMLAB_RESEARCH: '1' }).byDefault).toBe(false);
  });
});

describe('parseGrypeDbStatus', () => {
  it('reads the success shape grype prints for a provisioned database', () => {
    const s = parseGrypeDbStatus(
      JSON.stringify({
        schemaVersion: 'v6.1.9',
        from: 'https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.9.tar.zst',
        built: '2026-09-16T06:30:57Z',
        path: '/data/grype-db/6/vulnerability.db',
        valid: true,
      }),
    );
    expect(s.present).toBe(true);
    expect(s.built).toBe('2026-09-16T06:30:57Z');
    expect(s.schemaVersion).toBe('v6.1.9');
    expect(s.error).toBeNull();
  });

  it('reads the failure shape — which is what a deployment with no database actually gets', () => {
    // Verbatim from `GRYPE_DB_CACHE_DIR=/tmp/emptydb grype db status -o json` (exit 1), plus the log line grype
    // writes to the same stream.
    const s = parseGrypeDbStatus(
      '{\n "schemaVersion": "",\n "path": "/tmp/emptydb/6/vulnerability.db",\n "valid": false,\n "error": "database does not exist"\n}\n[0000] ERROR database does not exist\n',
    );
    expect(s.present).toBe(false);
    expect(s.error).toBe('database does not exist');
    expect(s.path).toBe('/tmp/emptydb/6/vulnerability.db');
    // An empty string is not a schema version: it is grype declining to state one.
    expect(s.schemaVersion).toBeNull();
  });

  it('says so rather than claiming a database when grype printed nothing parseable', () => {
    expect(parseGrypeDbStatus('').present).toBe(false);
    expect(parseGrypeDbStatus('').error).toMatch(/no JSON/);
    expect(parseGrypeDbStatus('{ not json').error).toMatch(/no JSON|unparseable/);
  });
});

describe('dbAgeDays', () => {
  it('counts whole days, and refuses to invent one', () => {
    expect(dbAgeDays('2026-09-16T06:30:57Z', NOW)).toBe(0);
    expect(dbAgeDays('2026-09-01T12:00:00Z', NOW)).toBe(15);
    expect(dbAgeDays(null, NOW)).toBeNull();
    expect(dbAgeDays('whenever', NOW)).toBeNull();
  });
});

describe('decideGrype', () => {
  it('runs against a provisioned database and says the run contacts nobody — the success path', () => {
    const d = decideGrype(present('2026-09-16T06:30:57Z'), { updateAllowed: false, dbDir: DB_DIR, now: NOW });
    expect(d.run).toBe(true);
    if (!d.run) throw new Error('unreachable');
    expect(d.dbUpdate).toBe(false);
    expect(d.note).toContain('No network request is made');
    expect(d.note).toContain('2026-09-16T06:30:57Z');
    expect(d.note).toContain('v6.1.9');
  });

  it('still runs on an old database, and states that its silence has a date', () => {
    const built = new Date(NOW.getTime() - (STALE_DB_DAYS + 12) * 86_400_000).toISOString();
    const d = decideGrype(present(built), { updateAllowed: false, dbDir: DB_DIR, now: NOW });
    expect(d.run).toBe(true);
    if (!d.run) throw new Error('unreachable');
    expect(d.note).toContain(`${STALE_DB_DAYS + 12} days old`);
    expect(d.note).toContain('cannot appear below');
  });

  it('refuses instead of downloading when there is no database and the research lane was switched off', () => {
    const d = decideGrype(absent, { updateAllowed: false, dbDir: DB_DIR, now: NOW });
    expect(d.run).toBe(false);
    if (d.run) throw new Error('unreachable');
    // A refusal names what is missing, where, and BOTH ways out — the provisioning command and the opt-in.
    expect(d.reason).toContain(DB_DIR);
    expect(d.reason).toContain('grype db update');
    expect(d.reason).toContain('FIRMLAB_RESEARCH=1');
    // Refusal is only reachable with research stated off, and it says that rather than implying an opt-in.
    expect(d.reason).toContain('on by default and has been switched off');
    expect(d.reason).toContain('database does not exist');
    // And it refuses to be read as a clean bill of health.
    expect(d.reason).toContain('says nothing about vulnerabilities');
  });

  it('permits the download only when the operator opted in, and names the host before it happens', () => {
    const d = decideGrype(absent, { updateAllowed: true, dbDir: DB_DIR, now: NOW });
    expect(d.run).toBe(true);
    if (!d.run) throw new Error('unreachable');
    expect(d.dbUpdate).toBe(true);
    expect(d.note).toContain(GRYPE_DB_UPDATE_URL);
    expect(d.note).toContain('FIRMLAB_RESEARCH=1');
    // One-way: the ledger's distinction between "we send names" and "we download a catalogue".
    expect(d.note).toContain('Nothing about this firmware is sent');
  });

  it('says when the download rides on the default rather than a choice, and names the way out', () => {
    const d = decideGrype(absent, { updateAllowed: true, updateByDefault: true, dbDir: DB_DIR, now: NOW });
    expect(d.run).toBe(true);
    if (!d.run) throw new Error('unreachable');
    expect(d.note).toContain('ON by default');
    expect(d.note).toContain('FIRMLAB_RESEARCH=0');
    expect(d.note).not.toContain('(FIRMLAB_RESEARCH=1)');
  });

  it('does not treat a present database as stale-blocked, whatever the opt-in says', () => {
    const fresh = present('2026-09-15T00:00:00Z');
    for (const updateAllowed of [false, true]) {
      const d = decideGrype(fresh, { updateAllowed, dbDir: DB_DIR, now: NOW });
      expect(d.run).toBe(true);
    }
  });

  /**
   * The research lane permits downloading an ABSENT database, nothing more. It used to put
   * `GRYPE_DB_AUTO_UPDATE=true` on every anchore invocation whenever it was on, so a provisioned database was
   * refreshed from the internet under a job log saying "No network request is made".
   */
  it('scans a present database offline with the research lane stated on or on by default — fresh or stale', () => {
    const stale = new Date(NOW.getTime() - (STALE_DB_DAYS + 40) * 86_400_000).toISOString();
    for (const db of [present('2026-09-15T00:00:00Z'), present(stale)]) {
      for (const research of [{}, { FIRMLAB_RESEARCH: '1' }]) {
        const lane = researchLane(research);
        expect(lane.enabled).toBe(true);
        const d = decideGrype(db, {
          updateAllowed: lane.enabled,
          updateByDefault: lane.byDefault,
          dbDir: DB_DIR,
          now: NOW,
        });
        if (!d.run) throw new Error('unreachable');
        expect(d.dbUpdate).toBe(false);
        expect(d.note).toContain('No network request is made');
        expect(grypeScanEnv(anchoreEnv(research), d).GRYPE_DB_AUTO_UPDATE).toBe('false');
      }
    }
  });

  it('enables the fetch for the scan alone when the database is absent and the research lane is on', () => {
    for (const research of [{}, { FIRMLAB_RESEARCH: '1' }]) {
      const lane = researchLane(research);
      const d = decideGrype(absent, {
        updateAllowed: lane.enabled,
        updateByDefault: lane.byDefault,
        dbDir: DB_DIR,
        now: NOW,
      });
      if (!d.run) throw new Error('unreachable');
      const base = anchoreEnv(research);
      // The scan may fetch…
      expect(grypeScanEnv(base, d).GRYPE_DB_AUTO_UPDATE).toBe('true');
      // …and the environment syft and the status probe run under does not.
      expect(base.GRYPE_DB_AUTO_UPDATE).toBe('false');
    }
  });

  it('refuses rather than fetching when the database is absent and the research lane is off — stored override too', () => {
    for (const env of [{ FIRMLAB_RESEARCH: '0' }, { FIRMLAB_RESEARCH: 'yes' }]) {
      expect(decideGrype(absent, { updateAllowed: dbUpdateAllowed(env), dbDir: DB_DIR, now: NOW }).run).toBe(false);
    }
    try {
      setFlagOverrideProvider(() => ({ FIRMLAB_RESEARCH: '0' }));
      const env = effectiveEnv({ FIRMLAB_RESEARCH: '1' });
      expect(decideGrype(absent, { updateAllowed: dbUpdateAllowed(env), dbDir: DB_DIR, now: NOW }).run).toBe(false);
    } finally {
      setFlagOverrideProvider(() => ({}));
    }
  });
});

/**
 * The capabilities table's half of the policy: a tool that RUNS and still cannot answer.
 *
 * The defect these pin was live on the deployed container on 2026-09-19 — `/api/tools` reporting 28 of 28
 * available with grype among them, while `grype db status` said `database does not exist`. The page offered
 * "CVE matching (N-day)" for a lane that was going to refuse it.
 */
describe('grypeDatasetFact', () => {
  it('reports a provisioned database as ready, with the date its silence inherits', () => {
    const built = '2026-09-15T00:00:00Z';
    const f = grypeDatasetFact(present(built), DB_DIR, NOW);
    expect(f.ready).toBe(true);
    expect(f.stale).toBe(false);
    expect(f.built).toBe(built);
    expect(f.ageDays).toBe(dbAgeDays(built, NOW));
    expect(f.error).toBeNull();
  });

  it('reports an absent database as not ready, carrying grype’s own words for why', () => {
    const f = grypeDatasetFact(absent, DB_DIR, NOW);
    expect(f.ready).toBe(false);
    expect(f.dbDir).toBe(DB_DIR);
    // Grype's error text, not this module's assertion about what it must have been.
    expect(f.error).toContain('database does not exist');
    expect(f.built).toBeNull();
    expect(f.ageDays).toBeNull();
  });

  it('marks an old database stale without making it unready — it matches, it is just dated', () => {
    const built = new Date(NOW.getTime() - (STALE_DB_DAYS + 5) * 86_400_000).toISOString();
    const f = grypeDatasetFact(present(built), DB_DIR, NOW);
    expect(f.ready).toBe(true);
    expect(f.stale).toBe(true);
  });

  it('does not let a permitted future download count as a database in hand', () => {
    // `decideGrype` says run — the research lane may fetch one at job time. That is a future event, and the
    // capabilities page must not report it as data this deployment has. The two answers deliberately disagree.
    expect(decideGrype(absent, { updateAllowed: true, dbDir: DB_DIR, now: NOW }).run).toBe(true);
    expect(grypeDatasetFact(absent, DB_DIR, NOW).ready).toBe(false);
  });

  it('states no date rather than guessing one when grype recorded none', () => {
    const undated: GrypeDbStatus = { ...present('2026-09-15T00:00:00Z'), built: null };
    const f = grypeDatasetFact(undated, DB_DIR, NOW);
    expect(f.ready).toBe(true);
    expect(f.ageDays).toBeNull();
    // An unrecorded date must not silently become a fresh one.
    expect(f.stale).toBe(false);
  });
});
