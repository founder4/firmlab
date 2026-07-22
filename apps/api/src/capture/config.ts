/**
 * Capture-lane config (Phase 6). FirmLab's SECOND network-touching lane (after `FIRMLAB_RESEARCH`), gated by its
 * OWN flag `FIRMLAB_CAPTURE`. With the flag unset, `loadCaptureConfig()` returns null and no capture action ever
 * touches the wire — a default `docker run` does nothing here. The lane exists to acquire firmware from a live
 * device (intercept an OTA update), and this is where its posture is declared.
 *
 * Discovery in Phase 6.0 is passive/observational (host sweep + service discovery); nothing is intercepted until a
 * later phase, and even then only on a human-triggered, time-boxed, single-target session with guaranteed teardown.
 */

export interface CaptureConfig {
  /**
   * The operator has declared that gateway/mirror positioning is in place (design §5a: FirmLab is the target's
   * default route, or a SPAN/port-mirror feeds it). Set via `FIRMLAB_CAPTURE_GATEWAY=1`. Lets the on-path-gateway
   * backend light up — an assertion, confirmed later by actually seeing the target's traffic.
   */
  gatewayDeclared: boolean;
  /** Default subnet (CIDR) to sweep when the operator doesn't pass one; null → auto-detect the primary interface. */
  defaultSubnet: string | null;
  /** Wall-clock bound for a single discovery sweep. */
  discoverTimeoutMs: number;
}

/**
 * Resolve the capture config, or null when the lane is off. Gated by FIRMLAB_CAPTURE so the deterministic,
 * local-only workbench stays the default and nothing reaches onto the LAN unless the operator opts in.
 */
export function loadCaptureConfig(env: NodeJS.ProcessEnv = process.env): CaptureConfig | null {
  if (env.FIRMLAB_CAPTURE !== '1') return null;
  return {
    gatewayDeclared: env.FIRMLAB_CAPTURE_GATEWAY === '1',
    defaultSubnet: env.FIRMLAB_CAPTURE_SUBNET?.trim() || null,
    discoverTimeoutMs: Math.max(5000, Number(env.FIRMLAB_CAPTURE_DISCOVER_TIMEOUT_MS ?? 60_000)),
  };
}
