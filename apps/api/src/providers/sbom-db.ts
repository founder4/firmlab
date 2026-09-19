/**
 * The SBOM lane's network policy, and the grype vulnerability database it rests on.
 *
 * `grype` ships with `db.auto-update: true`, so a plain `grype dir:…` opens a socket before it reads a single
 * byte of firmware: it GETs `<update-url>/v6/latest.json` and, when the local copy is missing or older than the
 * listing, downloads a multi-gigabyte database. `db.require-update-check: false` means a failure to do so is a
 * `WARN` nobody reads, so the lane looks identical whether it reached the internet or not. Both anchore binaries
 * additionally poll for a new release of THEMSELVES on every invocation (`check-for-app-update: true`). None of
 * that was gated by anything FirmLab owns.
 *
 * Measured on the deployed container on 2026-09-16: `FIRMLAB_RESEARCH` unset, `FIRMLAB_AGENT` unset,
 * `FIRMLAB_CAPTURE` unset, the container started at 07:27, and `import.json` in grype's cache records a
 * 2 204 512 256-byte database fetched from `grype.anchore.io` at 07:28. *"With every flag off: no network, no
 * cost, deterministic behaviour"* was false, and nothing in the product said so.
 *
 * The policy this module implements, and that `sbom-db.test.ts` pins:
 *
 *  1. **No implicit egress.** Every syft/grype invocation carries `OFFLINE_ANCHORE_ENV` (in `tools.ts`, applied
 *     to the capability probes too), which turns off both the database auto-update and the self-update poll. That
 *     is the default, and it holds with every lane flag off.
 *  2. **The database is provisioned, not acquired.** It never lives in `~/.cache`, where a fresh container layer
 *     silently loses it and grype silently re-downloads it. `grypeDbDir` reads `GRYPE_DB_CACHE_DIR` and falls back
 *     to `FIRMLAB_DATA_DIR/grype-db`, which is the two ways a deployment may supply one, and both are deliberate:
 *     **baked** into `Dockerfile.tools` at `/opt/grype-db` with `GRYPE_DB_CACHE_DIR` pointing at it, so the
 *     database ships with the image and a recreated container is never without one; or **provisioned once**
 *     against the data volume, which survives a redeploy and can be refreshed without a rebuild. The baked one is
 *     what this repository deploys, and its cost is stated where it is paid: the database is then as old as the
 *     image, so rule 4 below is the thing that keeps it honest rather than an afterthought.
 *     `GRYPE_DB_UPDATE_URL` is pinned here so a stray `~/.grype.yaml` cannot redirect where a permitted download
 *     goes.
 *  3. **An absent database is a refusal, never a silent skip and never a download.** `decideGrype` returns the
 *     sentence naming what is missing, where it is missing from, and both ways to supply it; the SBOM is still
 *     returned, with CVE matching declared as not attempted. That is the `available:false` discipline the rest of
 *     the providers already follow — absence of a tool is not absence of a problem.
 *  4. **A database is a date, and an empty CVE list inherits it.** The build date travels into the result and the
 *     job log, because "grype found 0" against a database built eight months ago is not the same claim as "grype
 *     found 0" against today's, and only one of the two is worth anything.
 *  5. **The opt-in is the research lane, not a new flag.** `FIRMLAB_RESEARCH` is documented as the only
 *     internet-touching analysis lane; a database download is an internet-touching act, so it belongs behind that
 *     switch and behind its prose. It gets no flag of its own — the reason `FIRMLAB_HASH_LOOKUP` has one is that
 *     it sends material FROM the firmware to a third party, and a database download sends nothing at all: it is
 *     one-way, exactly like the KEV catalogue the research lane already pulls.
 */
import { execFile } from 'node:child_process';
import path from 'node:path';
import { promisify } from 'node:util';
import { effectiveEnv } from '../flags.js';
import { OFFLINE_ANCHORE_ENV } from '../tools.js';

const execFileAsync = promisify(execFile);

/**
 * grype's own default database host, restated as a constant. Setting it explicitly means the destination of a
 * PERMITTED download is one this repository names, not one a config file on the deployment picked.
 */
export const GRYPE_DB_UPDATE_URL = 'https://grype.anchore.io/databases';

/** Beyond this, the job log and the result say out loud that the database is old. */
export const STALE_DB_DAYS = 30;

/** Where the provisioned database lives. Under the data root, so it is not lost with the container. */
export function grypeDbDir(env: NodeJS.ProcessEnv = effectiveEnv()): string {
  return env.GRYPE_DB_CACHE_DIR || path.join(env.FIRMLAB_DATA_DIR || './data', 'grype-db');
}

/** Is the operator's network opt-in in force? The research lane, and nothing else, permits a database download. */
export function dbUpdateAllowed(env: NodeJS.ProcessEnv = effectiveEnv()): boolean {
  return env.FIRMLAB_RESEARCH === '1';
}

/**
 * The environment every syft/grype child process runs under: offline by default, pointed at the provisioned
 * database, and — only when the research lane is on — permitted to refresh it from the pinned URL.
 */
export function anchoreEnv(env: NodeJS.ProcessEnv = effectiveEnv()): NodeJS.ProcessEnv {
  return {
    ...env,
    ...OFFLINE_ANCHORE_ENV,
    GRYPE_DB_CACHE_DIR: grypeDbDir(env),
    GRYPE_DB_UPDATE_URL,
    ...(dbUpdateAllowed(env) ? { GRYPE_DB_AUTO_UPDATE: 'true' } : {}),
  };
}

/** What `grype db status` reports about the database on disk. Every field optional: grype omits them when absent. */
export interface GrypeDbStatus {
  present: boolean;
  schemaVersion: string | null;
  built: string | null;
  path: string | null;
  from: string | null;
  error: string | null;
}

const ABSENT: GrypeDbStatus = { present: false, schemaVersion: null, built: null, path: null, from: null, error: null };

/**
 * Parse `grype db status -o json`. Pure, and exported because the FAILURE path is the one that matters: grype
 * prints the same JSON shape with `"valid": false` and an `error` when the database is missing — and exits 1, so
 * the caller reads this off the rejection rather than off a resolved promise.
 */
export function parseGrypeDbStatus(stdout: string): GrypeDbStatus {
  const start = stdout.indexOf('{');
  const end = stdout.lastIndexOf('}');
  if (start < 0 || end <= start) return { ...ABSENT, error: 'grype db status printed no JSON object' };
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout.slice(start, end + 1));
  } catch {
    return { ...ABSENT, error: 'grype db status printed unparseable JSON' };
  }
  const o = (parsed ?? {}) as Record<string, unknown>;
  const str = (v: unknown): string | null => (typeof v === 'string' && v.length > 0 ? v : null);
  return {
    present: o.valid === true,
    schemaVersion: str(o.schemaVersion),
    built: str(o.built),
    path: str(o.path),
    from: str(o.from),
    error: str(o.error),
  };
}

/** Whole days between the database's build date and now, or null when grype recorded no date we can read. */
export function dbAgeDays(built: string | null, now: Date = new Date()): number | null {
  if (!built) return null;
  const t = Date.parse(built);
  if (!Number.isFinite(t)) return null;
  return Math.floor((now.getTime() - t) / 86_400_000);
}

export type GrypeDecision =
  /** Run grype. `note` is what the job log and the reader are told the matching was done against. */
  | { run: true; note: string }
  /** Do not run grype, and do not download. `reason` names what is missing and both ways to supply it. */
  | { run: false; reason: string };

/**
 * The decision, given what is on disk and whether the operator opted into the network. Pure — this is the whole
 * policy, and the test exercises both branches INCLUDING the one where nothing is wrong, because a guard is only
 * as good as its success path and that is the path nobody runs.
 */
export function decideGrype(
  db: GrypeDbStatus,
  opts: { updateAllowed: boolean; dbDir: string; now?: Date },
): GrypeDecision {
  if (db.present) {
    const ageDays = dbAgeDays(db.built, opts.now ?? new Date());
    const age =
      ageDays === null
        ? 'of an unrecorded build date'
        : ageDays >= STALE_DB_DAYS
          ? `built ${db.built} — ${ageDays} days old, so a CVE published since then cannot appear below`
          : `built ${db.built} (${ageDays} day(s) old)`;
    return {
      run: true,
      note: `Matching against the provisioned vulnerability database ${age}; schema ${db.schemaVersion ?? '?'}. No network request is made.`,
    };
  }
  if (opts.updateAllowed) {
    return {
      run: true,
      note:
        `No vulnerability database at ${opts.dbDir}. The research lane is ON (FIRMLAB_RESEARCH=1), so grype is ` +
        `permitted to download one from ${GRYPE_DB_UPDATE_URL} (several GB). Nothing about this firmware is sent.`,
    };
  }
  const why = db.error ? ` (grype: ${db.error})` : '';
  return {
    run: false,
    reason: [
      `CVE matching was not attempted: grype is installed but has no vulnerability database at ${opts.dbDir}${why},`,
      'and the SBOM lane never downloads one on its own. Provision it once with',
      `\`GRYPE_DB_CACHE_DIR=${opts.dbDir} grype db update\`, or turn on the research lane (Settings › Privacy, or`,
      `FIRMLAB_RESEARCH=1) to let this job fetch it from ${GRYPE_DB_UPDATE_URL}. The package inventory below is`,
      'complete; it says nothing about vulnerabilities either way.',
    ].join(' '),
  };
}

/**
 * Ask grype what database it has. Thin runner around the pure parser: grype exits 1 when the database is absent
 * and still prints the JSON, so the rejection is read rather than treated as a harness failure — the same mistake
 * `parseGdbOutput` made once already.
 */
export async function readGrypeDbStatus(env: NodeJS.ProcessEnv): Promise<GrypeDbStatus> {
  try {
    const { stdout } = await execFileAsync('grype', ['db', 'status', '-o', 'json'], { env, timeout: 30_000 });
    return parseGrypeDbStatus(stdout);
  } catch (err) {
    const out = String((err as { stdout?: unknown })?.stdout ?? '');
    const parsed = parseGrypeDbStatus(out);
    if (parsed.error && !parsed.error.startsWith('grype db status printed')) return parsed;
    return { ...ABSENT, error: err instanceof Error ? (err.message.split('\n')[0] ?? err.message) : String(err) };
  }
}

/**
 * What the Capabilities page needs to know about the grype database, language-neutral.
 *
 * **Why this exists.** `tools.ts` probes a BINARY: it runs `grype version`, gets an answer and reports
 * `available: true`. That is a true statement about the wrong thing. grype without a database does not match a
 * single CVE — it refuses, by `decideGrype` above — so a capabilities table built from the probe alone promises a
 * question the lane is going to reject. Measured on the deployed container on 2026-09-19: 28 of 28 tools
 * `available`, grype among them, and `grype db status` reporting `database does not exist`.
 *
 * A tool's data dependency is a SECOND axis, not a worse value of the first. Collapsing it into `available: false`
 * would say "this deployment does not have grype", which is the claim `CLAUDE.md` forbids — absence of a tool is
 * not absence of a problem, and here the tool is right there. So the probe keeps its answer and this rides beside
 * it.
 *
 * Neutral on purpose, exactly like `ProbeResult` in `tools.ts`: the fields are what was read off disk, and the
 * sentence is composed per-request in the reader's language. A cache holding prose answers the second request in
 * the wrong one.
 */
export interface GrypeDatasetFact {
  /** Is a database on disk that grype accepted? Read off `grype db status`, never inferred from the binary. */
  ready: boolean;
  /** Where it was looked for — an identifier, printed verbatim in every language. */
  dbDir: string;
  built: string | null;
  /** Whole days old, or null when grype recorded no readable build date. */
  ageDays: number | null;
  /** Past `STALE_DB_DAYS`: the inventory is current, the CVE list is only as current as this. */
  stale: boolean;
  schemaVersion: string | null;
  /** What grype said went wrong, when it said anything. */
  error: string | null;
}

/**
 * Pure: turn a `grype db status` reading into the fact the capabilities table reports. `ready` is the disk fact
 * and nothing else — notably, the research lane being on does NOT make it true. That lane permits a download at
 * job time, which is a future event; reporting it as a database in hand would be the same overstatement this
 * whole module exists to remove, one flag further along.
 */
export function grypeDatasetFact(db: GrypeDbStatus, dbDir: string, now: Date = new Date()): GrypeDatasetFact {
  const ageDays = dbAgeDays(db.built, now);
  return {
    ready: db.present,
    dbDir,
    built: db.built,
    ageDays,
    stale: ageDays !== null && ageDays >= STALE_DB_DAYS,
    schemaVersion: db.schemaVersion,
    error: db.error,
  };
}
