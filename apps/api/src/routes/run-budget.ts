/** A normalized wall-clock budget suitable for both provider options and the durable job ledger. */
export interface RunBudget {
  /** Effective seconds after applying the route's supported range. */
  seconds: number;
  /** Operator-supplied value, or null when the route default was used. */
  requestedSeconds: number | null;
  /** Whether the effective budget differs from the operator's request. */
  secondsClamped: boolean;
}

/**
 * Validate and bound a route's optional `seconds` field. Invalid JSON types/non-finite numbers return null so the
 * handler can reject them; supported numbers retain both requested and effective values for an auditable run.
 */
export function normalizeRunBudget(
  raw: unknown,
  bounds: { defaultSeconds: number; minSeconds: number; maxSeconds: number },
): RunBudget | null {
  if (raw === undefined) {
    return { seconds: bounds.defaultSeconds, requestedSeconds: null, secondsClamped: false };
  }
  if (typeof raw !== 'number' || !Number.isFinite(raw)) return null;
  const seconds = Math.min(bounds.maxSeconds, Math.max(bounds.minSeconds, raw));
  return { seconds, requestedSeconds: raw, secondsClamped: seconds !== raw };
}
