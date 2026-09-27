/**
 * Read-side coverage for the loader-derived key audit stored inside a U-Boot result.
 *
 * The field is optional forever: a result written before the audit existed says nothing about whether it ran. A
 * present empty result is different and only becomes a negative for the bytes it actually examined. This mapper is
 * shared by W9 and the coverage route so the autonomous step and a later dedicated U-Boot run cannot describe the
 * same persisted audit differently.
 *
 * The stored JSON is data written by some build, not a type we own, so it is read strictly: flags must be exact
 * booleans (`"false"` is truthy), counts finite non-negative integers, and the byte bound internally consistent
 * (`bytesRead <= totalBytes`, `complete` exactly when the two are equal). Anything else — a legacy combination, a
 * completed audit with no bound, a string where a number belongs — reads as `unknown`, never as ran or empty. A
 * consistent completed audit over zero bytes examined nothing, so it reads as `no-bytes`: the input was empty or
 * unreadable, which is a not-attempted outcome, not a scoped negative.
 */
import type { OpacidadStep } from '../opacidad-narrative.js';
import type { DegradedRemedy } from '../opacidad-remedy.js';

export const UBOOT_WORKER = 'Static · U-Boot env';

export interface LoaderKeyAuditCoverage {
  attempted: boolean;
  completed: boolean;
  leadsFound: number;
  scan?: { bytesRead: number; totalBytes: number; complete: boolean };
}

export interface UbootCoverageResult {
  found?: boolean;
  varCount?: number;
  findings?: readonly unknown[];
  bootScript?: { roots?: readonly string[]; variants?: readonly unknown[]; reason?: string };
  /** Optional forever: absent means this run did not record loader-key coverage. */
  loaderKeyAudit?: unknown;
}

export interface UbootJobRecord {
  kind: string;
  status: string;
  resultJson?: string | null;
}

/** What a persisted audit actually supports claiming. Only `completed` carries a byte bound, so only it can be empty. */
export type LoaderKeyAuditState =
  | { kind: 'absent' }
  | { kind: 'unknown' }
  | { kind: 'not-attempted' }
  | { kind: 'no-bytes' }
  | { kind: 'incomplete'; leadsFound: number }
  | { kind: 'completed'; leadsFound: number; bytesRead: number; totalBytes: number; complete: boolean };

interface AuditReading {
  summary: string;
  note: string;
  degraded: boolean;
  remedy?: DegradedRemedy;
}

function count(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function readLoaderKeyAudit(value: unknown): LoaderKeyAuditState {
  if (value === undefined) return { kind: 'absent' };
  if (!isRecord(value)) return { kind: 'unknown' };
  const { attempted, completed } = value;
  const leadsFound = count(value.leadsFound);
  if (typeof attempted !== 'boolean' || typeof completed !== 'boolean' || leadsFound === null) {
    return { kind: 'unknown' };
  }
  if (!attempted) return !completed && leadsFound === 0 ? { kind: 'not-attempted' } : { kind: 'unknown' };
  if (!completed) return { kind: 'incomplete', leadsFound };
  const scan = isRecord(value.scan) ? value.scan : null;
  const bytesRead = count(scan?.bytesRead);
  const totalBytes = count(scan?.totalBytes);
  if (bytesRead === null || totalBytes === null || bytesRead > totalBytes) return { kind: 'unknown' };
  if (typeof scan?.complete !== 'boolean' || scan.complete !== (bytesRead === totalBytes)) return { kind: 'unknown' };
  if (totalBytes === 0) return leadsFound === 0 ? { kind: 'no-bytes' } : { kind: 'unknown' };
  return { kind: 'completed', leadsFound, bytesRead, totalBytes, complete: scan.complete };
}

function auditReading(audit: Exclude<LoaderKeyAuditState, { kind: 'absent' }>): AuditReading {
  switch (audit.kind) {
    case 'unknown':
      return {
        summary: 'loader-key audit coverage unknown',
        note: 'The stored loader-derived key audit is malformed or inconsistent, so whether it ran and over which bytes is unknown; no negative result is available.',
        degraded: true,
        remedy: 'retry',
      };
    case 'not-attempted':
      return {
        summary: 'loader-key audit not attempted',
        note: 'The image could not be read, so the loader-derived key audit did not run; no negative result is available.',
        degraded: true,
        remedy: 'reacquire-input',
      };
    case 'no-bytes':
      return {
        summary: 'loader-key audit examined 0 bytes',
        note: 'The loader-derived key audit recorded a scan over 0 bytes: the input was empty or unreadable, so nothing was examined; no negative result is available.',
        degraded: true,
        remedy: 'reacquire-input',
      };
    case 'incomplete':
      return {
        summary: `loader-key audit incomplete; ${audit.leadsFound} lead(s)`,
        note: 'The loader-derived key audit started but did not complete; its empty result, if any, is not a negative.',
        degraded: true,
        remedy: 'retry',
      };
    case 'completed': {
      const bytes = `${audit.bytesRead}/${audit.totalBytes} bytes`;
      const bounded = !audit.complete;
      const note =
        audit.leadsFound === 0
          ? `No loader-derived key lead was found within the recorded ${bytes} scan. This bounded static audit is not proof that the firmware has no derived key.`
          : `${audit.leadsFound} loader-derived key lead(s) came from the recorded ${bytes} scan. A lead requires runtime reproduction; no device behavior is confirmed.`;
      return {
        summary: `loader-key audit completed ${bounded ? 'within' : 'across'} ${bytes}; ${audit.leadsFound} lead(s)`,
        note: bounded ? `${note} Bytes beyond the recorded bound remain unexamined.` : note,
        degraded: bounded,
        ...(bounded ? { remedy: 'raise-bound' as const } : {}),
      };
    }
  }
}

/** Convert a present audit into the exact U-Boot step shape consumed by the coverage report. */
export function ubootCoverageStep(result: UbootCoverageResult): OpacidadStep | null {
  const audit = readLoaderKeyAudit(result.loaderKeyAudit);
  if (audit.kind === 'absent') return null;
  const reading = auditReading(audit);
  const findingCount = Array.isArray(result.findings) ? result.findings.length : undefined;
  const variants = Array.isArray(result.bootScript?.variants) ? result.bootScript.variants.length : 0;
  const roots = Array.isArray(result.bootScript?.roots) ? result.bootScript.roots.join('/') : '';
  const assembledClause = variants ? ` · ${variants} assembled cmdline variant(s)${roots ? ` from ${roots}` : ''}` : '';
  const reason = typeof result.bootScript?.reason === 'string' ? result.bootScript.reason : '';
  const note = [reason, reading.note].filter((item) => !!item).join(' ');
  const countClause = findingCount === undefined ? 'findings not recorded' : `${findingCount} findings`;
  return {
    worker: UBOOT_WORKER,
    status: reading.degraded ? 'degraded' : 'ran',
    summary: `U-Boot / boot posture: ${countClause}${assembledClause} · ${reading.summary}`,
    ...(findingCount === undefined ? {} : { findingCount }),
    ...(reading.degraded && reading.remedy ? { remedy: reading.remedy } : {}),
    ...(note ? { note } : {}),
  };
}

/**
 * Newest dedicated U-Boot result that records the optional audit. `jobs` must be in `listJobs` order — newest
 * `createdAt` first, ties broken by SQLite insertion order (rowid) — which is the store's stable ordering, not an
 * accident of the array. Unparseable rows and rows without the field prove nothing and fall through to older runs.
 */
export function latestUbootCoverageStep(jobs: readonly UbootJobRecord[]): OpacidadStep | null {
  for (const job of jobs) {
    if (job.kind !== 'uboot' || job.status !== 'done' || !job.resultJson) continue;
    try {
      const parsed: unknown = JSON.parse(job.resultJson);
      if (!isRecord(parsed)) continue;
      const step = ubootCoverageStep(parsed as UbootCoverageResult);
      if (step) return step;
    } catch {
      // An unreadable persisted result cannot replace a valid older audit over the same immutable image.
    }
  }
  return null;
}
