/**
 * Trigger-delivery harness (Phase 4 debt #3) — turns a node-④ candidate into a real dynamic test instead of a
 * generic "did the binary run" probe. It DELIVERS the constructed trigger into the sink through the channel the
 * candidate's source implies (CGI env / stdin / argv), then interprets the run honestly:
 *
 *   - command-injection: the payload appends `;echo <MARKER>;`. If the injected command runs, the unique marker
 *     appears in stdout → the injection is reproduced in the sandbox (confirmed_in_emulation).
 *   - buffer/stack overflow: the payload is an oversized input. If the process dies with SIGSEGV/SIGABRT/SIGBUS,
 *     memory-unsafety is reproduced (confirmed_in_emulation).
 *   - otherwise: it ran without a crash or observable injection → the candidate STANDS, still needs_runtime_reproduction.
 *
 * Confirmation is tied to the specific candidate, and it only ever proves the SANDBOX, never the device. Both
 * functions are pure and unit-tested; the session runs the delivery under the isolation sandbox.
 */

export type DeliveryMode = 'env' | 'stdin' | 'argv';

export interface TriggerDelivery {
  mode: DeliveryMode;
  env?: Record<string, string>;
  input?: string;
  args?: string[];
  /** For command-injection: the unique token to look for in stdout. Null for crash-based classes. */
  marker: string | null;
  vulnClass: string;
}

export function isCommandInjection(vulnClass: string): boolean {
  return /command|injection|os-?command|exec/i.test(vulnClass);
}
export function isOverflow(vulnClass: string): boolean {
  return /overflow|stack|buffer|memory/i.test(vulnClass);
}

/** Pick how to reach the sink from the candidate's source description. */
export function deliveryChannel(source: string): DeliveryMode {
  const s = source.toLowerCase();
  if (/getenv|query_string|content_length|cgi|http_|\benv\b/.test(s)) return 'env';
  if (/stdin|fgets|\bscanf\b|\bfread\b|\bread\b/.test(s)) return 'stdin';
  if (/argv|command.?line|\barg\b/.test(s)) return 'argv';
  if (/recv|recvfrom|socket|network|accept/.test(s)) return 'stdin'; // many CGIs read the request as stdin
  return 'argv';
}

// Large enough to run past a small buffer / off a mapped page on common layouts (32-bit firmware return-address
// smashes hit far sooner; this errs big so the crash is reproducible rather than silently absorbed).
const OVERFLOW_PAYLOAD = 'A'.repeat(8192);

/** Pure: build the delivery for a candidate. `marker` is the caller's unique per-run token. */
export function planDelivery(
  candidate: { vulnClass: string; source: string; trigger: string },
  marker: string,
): TriggerDelivery {
  const mode = deliveryChannel(candidate.source);
  const base = candidate.trigger?.trim() || 'x';
  const payload = isCommandInjection(candidate.vulnClass)
    ? `${base} ;echo ${marker};`
    : isOverflow(candidate.vulnClass)
      ? OVERFLOW_PAYLOAD
      : base;
  const delivery: TriggerDelivery = {
    mode,
    marker: isCommandInjection(candidate.vulnClass) ? marker : null,
    vulnClass: candidate.vulnClass,
  };
  if (mode === 'env') {
    delivery.env = {
      QUERY_STRING: payload,
      CONTENT_LENGTH: String(payload.length),
      REQUEST_METHOD: 'GET',
      HTTP_USER_AGENT: payload,
      TRIGGER: payload,
    };
  } else if (mode === 'stdin') {
    delivery.input = `${payload}\n`;
  } else {
    delivery.args = [payload];
  }
  return delivery;
}

export interface TriggerVerdict {
  confirmed: boolean;
  proofState: string;
  note: string;
}

const CRASH_SIGNALS = new Set(['SIGSEGV', 'SIGABRT', 'SIGBUS', 'SIGILL']);

/** Pure: decide whether the run confirmed the candidate, honestly. */
export function interpretTriggerRun(
  delivery: TriggerDelivery,
  result: { stdout: string; signal: string | null; exitCode: number | null; timedOut: boolean },
): TriggerVerdict {
  if (delivery.marker && result.stdout.includes(delivery.marker)) {
    return {
      confirmed: true,
      proofState: 'confirmed_in_emulation',
      note: 'Injected command executed — the trigger marker appeared in output. Command injection reproduced in the sandbox (not the device).',
    };
  }
  if (result.signal && CRASH_SIGNALS.has(result.signal)) {
    return {
      confirmed: true,
      proofState: 'confirmed_in_emulation',
      note: `Reproduced a crash (${result.signal}) under the trigger — memory-unsafety confirmed in the sandbox (not the device).`,
    };
  }
  return {
    confirmed: false,
    proofState: 'needs_runtime_reproduction',
    note: 'Ran under the delivered trigger with no crash or observable injection — the candidate stands, unproven.',
  };
}
