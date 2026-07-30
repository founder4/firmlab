/**
 * Per-binary hardening, and the blank that inverts it.
 *
 * `BinaryEntry` carries `nx`, `canary`, `pic`, `bits`, `importsSummary` and `emulationStatus`, and **not one of them
 * had a reader in this app**, while the capability matrix announced `hardening: done` with the label *"Binary
 * hardening (NX / canary / PIC / RELRO)"*.
 *
 * Measured on the real corpus (2026-07-30), the picture is worse than "collected and never shown":
 *
 *   - **2007 binaries. 2 triaged. 2 with `nx` measured.** The fields are populated by radare2 triage, which is
 *     per-binary and on demand, so 2005 of 2007 rows carry `null` for every hardening column. On the DVRF, all 218.
 *   - **RELRO is measured NOWHERE in the API** — no provider, no column, not even the string. The matrix names it in
 *     the technique's own label and reports the technique done.
 *
 * So the load-bearing decision here is not the rendering, it is what `null` means. `nx: 0` is a measurement: the
 * binary has no NX. `nx: null` is the absence of one. A column that renders both as a blank, or worse as an ✗, tells
 * a reader that 2005 binaries are unhardened when nothing has looked at any of them — which does not merely lose a
 * fact, it INVERTS it, and this is the one place in the workbench where the empty value points at the alarming
 * conclusion rather than the reassuring one.
 *
 * Pure and dependency-free.
 */

/** How one hardening flag reads. `not-measured` is a first-class outcome, never a styling of `off`. */
export type HardeningFlag = 'on' | 'off' | 'not-measured';

/**
 * Pure: read one flag.
 *
 * SQLite stores these as INTEGER, so the values that arrive are `1`, `0` or `null`. Anything else — a string from an
 * older build, a float — is `not-measured` rather than coerced: guessing here would manufacture a hardening verdict
 * out of a type error, in the direction that reassures.
 */
export function hardeningFlag(value: unknown): HardeningFlag {
  if (value === 1) return 'on';
  if (value === 0) return 'off';
  return 'not-measured';
}

/** Whether this row has been through triage at all — the prior question behind every flag on it. */
export function isTriaged(binary: { triaged?: unknown }): boolean {
  return binary.triaged === 1 || binary.triaged === true;
}

/**
 * Pure: has ANY hardening flag on this row been measured?
 *
 * Separate from `isTriaged` because the two can disagree, and when they do the row is the evidence rather than the
 * flag: a binary marked triaged whose flags are all null means triage ran and recorded nothing, which is a different
 * fact from triage never having run — and radare2 on a stripped or packed target can legitimately produce it.
 */
export function hasAnyHardening(b: { nx?: unknown; canary?: unknown; pic?: unknown }): boolean {
  return [b.nx, b.canary, b.pic].some((v) => hardeningFlag(v) !== 'not-measured');
}

/** The denominator for one image: how much of its binary set anyone has actually looked at. */
export interface HardeningCoverage {
  total: number;
  /** Rows with at least one hardening flag measured. */
  measured: number;
  /** Rows flagged triaged. Can exceed `measured` when triage ran and read nothing off the binary. */
  triaged: number;
  /**
   * Rows marked triaged whose flags are all absent — triage ran and recorded nothing. Reported apart from
   * `total - measured`, because those two nothings have different causes and different fixes.
   */
  triagedWithoutFlags: number;
}

/** Pure: count the coverage. Takes the rows so this stays testable without a client. */
export function hardeningCoverage(
  binaries: readonly { nx?: unknown; canary?: unknown; pic?: unknown; triaged?: unknown }[],
): HardeningCoverage {
  let measured = 0;
  let triaged = 0;
  let triagedWithoutFlags = 0;
  for (const b of binaries) {
    const any = hasAnyHardening(b);
    const t = isTriaged(b);
    if (any) measured++;
    if (t) triaged++;
    if (t && !any) triagedWithoutFlags++;
  }
  return { total: binaries.length, measured, triaged, triagedWithoutFlags };
}

/**
 * Pure: is the hardening column set worth reading at all for this image?
 *
 * `false` when nothing has been measured, so the caller can lead with WHY rather than draw a table of blanks. A grid
 * of dashes is the shape a reader skims past, and skimming past it is how the inversion above goes unnoticed.
 */
export function hardeningIsInformative(c: HardeningCoverage): boolean {
  return c.measured > 0;
}

/**
 * RELRO, named in the technique matrix's own label and measured by no provider in this deployment.
 *
 * Exported as a constant rather than left as prose so the matrix and this module cannot drift: if a provider ever
 * measures it, this is the single place that has to change.
 */
export const UNMEASURED_HARDENING = ['RELRO'] as const;
