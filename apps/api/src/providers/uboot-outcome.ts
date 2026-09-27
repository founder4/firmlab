/**
 * Read-side coverage for the loader-derived key audit stored inside a U-Boot result.
 *
 * The field is optional forever: a result written before the audit existed says nothing about whether it ran. A
 * present empty result is different and only becomes a negative for the bytes it actually examined. This mapper is
 * shared by W9 and the coverage route so the autonomous step and a later dedicated U-Boot run cannot describe the
 * same persisted audit differently.
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
  loaderKeyAudit?: LoaderKeyAuditCoverage;
}

export interface UbootJobRecord {
  kind: string;
  status: string;
  resultJson?: string | null;
}

interface AuditReading {
  summary: string;
  note: string;
  degraded: boolean;
  remedy?: DegradedRemedy;
}

function count(value: unknown): number | null {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : null;
}

function auditReading(audit: LoaderKeyAuditCoverage): AuditReading {
  const leads = count(audit.leadsFound);
  const leadClause = leads === null ? 'lead count not recorded' : `${leads} lead(s)`;
  if (!audit.attempted) {
    return {
      summary: 'loader-key audit not attempted',
      note: 'The image could not be read, so the loader-derived key audit did not run; no negative result is available.',
      degraded: true,
      remedy: 'reacquire-input',
    };
  }
  if (!audit.completed) {
    return {
      summary: `loader-key audit incomplete; ${leadClause}`,
      note: 'The loader-derived key audit started but did not complete; its empty result, if any, is not a negative.',
      degraded: true,
      remedy: 'retry',
    };
  }

  const scan = audit.scan;
  if (!scan || count(scan.bytesRead) === null || count(scan.totalBytes) === null) {
    return {
      summary: `loader-key audit completed; ${leadClause}; byte coverage not recorded`,
      note:
        leads === 0
          ? 'No loader-derived key lead was recorded, but the byte bound is unknown; this is not evidence that the firmware has no derived key.'
          : 'The stored result records loader-derived key leads but not the byte bound; each remains a lead requiring runtime reproduction.',
      degraded: true,
    };
  }

  const bytes = `${scan.bytesRead}/${scan.totalBytes} bytes`;
  const bounded = !scan.complete || scan.bytesRead < scan.totalBytes;
  const note =
    leads === 0
      ? `No loader-derived key lead was found within the recorded ${bytes} scan. This bounded static audit is not proof that the firmware has no derived key.`
      : `${leads ?? 'The recorded'} loader-derived key lead(s) came from the recorded ${bytes} scan. A lead requires runtime reproduction; no device behavior is confirmed.`;
  return {
    summary: `loader-key audit completed ${bounded ? 'within' : 'across'} ${bytes}; ${leadClause}`,
    note: bounded ? `${note} Bytes beyond the recorded bound remain unexamined.` : note,
    degraded: bounded,
    ...(bounded ? { remedy: 'raise-bound' as const } : {}),
  };
}

/** Convert a present audit into the exact U-Boot step shape consumed by the coverage report. */
export function ubootCoverageStep(result: UbootCoverageResult): OpacidadStep | null {
  const audit = result.loaderKeyAudit;
  if (!audit) return null;
  const reading = auditReading(audit);
  const findingCount = Array.isArray(result.findings) ? result.findings.length : (count(audit.leadsFound) ?? 0);
  const variants = Array.isArray(result.bootScript?.variants) ? result.bootScript.variants.length : 0;
  const roots = Array.isArray(result.bootScript?.roots) ? result.bootScript.roots.join('/') : '';
  const assembledClause = variants ? ` · ${variants} assembled cmdline variant(s)${roots ? ` from ${roots}` : ''}` : '';
  const note = [result.bootScript?.reason, reading.note].filter((item): item is string => !!item).join(' ');
  return {
    worker: UBOOT_WORKER,
    status: reading.degraded ? 'degraded' : 'ran',
    summary: `U-Boot / boot posture: ${findingCount} findings${assembledClause} · ${reading.summary}`,
    findingCount,
    ...(reading.degraded && reading.remedy ? { remedy: reading.remedy } : {}),
    ...(note ? { note } : {}),
  };
}

/** Newest dedicated U-Boot result that actually records the optional audit; malformed/legacy rows prove nothing. */
export function latestUbootCoverageStep(jobs: readonly UbootJobRecord[]): OpacidadStep | null {
  for (const job of jobs) {
    if (job.kind !== 'uboot' || job.status !== 'done' || !job.resultJson) continue;
    try {
      const step = ubootCoverageStep(JSON.parse(job.resultJson) as UbootCoverageResult);
      if (step) return step;
    } catch {
      // An unreadable persisted result cannot replace a valid older audit over the same immutable image.
    }
  }
  return null;
}
