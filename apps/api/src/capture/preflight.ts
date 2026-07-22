/**
 * Capturability preflight + ladder (Phase 6.3, design §4). Exactly analogous to the emulation preflight
 * (`providers/preflight.ts`): for a chosen target it inspects what's known (the detected backends, the device's
 * type/ports) and ranks the viable capture strategies cheapest-and-most-complete first, then states the honest
 * ACQUISITION proof-state ceiling it can reach — never claiming a capture it can't get, always saying what would
 * unlock more ("declare a gateway", "attach an nRF52840", "run the Frida unpin template on a rooted phone").
 *
 * Pure + unit-tested. The realized ceiling of an in-flight session is computed from its actual flows
 * (`realizedCeiling`), so "pinned" is a fact observed on the wire, not a guess.
 */
import type { CaptureBackendStatus } from './backends.js';

/** Acquisition proof-states — distinct from the analysis proof-states an ingested image later flows through. */
export type AcquisitionState =
  | 'captured_plaintext'
  | 'captured_encrypted'
  | 'metadata_only'
  | 'blocked_by_pinning'
  | 'blocked_needs_hardware';

export interface CaptureStrategy {
  transport: 'http' | 'https' | 'ble-gatt' | 'zigbee-ota';
  /** How the target's traffic reaches us, or null for a radio (the radio IS the position). */
  positioning: 'gateway' | 'spoof' | null;
  viable: boolean;
  ceiling: AcquisitionState;
  reason: string;
}

export interface CapturabilityPlan {
  strategies: CaptureStrategy[];
  /** The best acquisition ceiling reachable right now. */
  ceiling: AcquisitionState;
  reason: string;
  /** What would unlock a better ceiling, or null when nothing more is needed. */
  unlockHint: string | null;
}

interface DeviceHint {
  typeGuess: string | null;
  mdnsIdentity: string | null;
}

function has(backends: CaptureBackendStatus[], id: string): boolean {
  return backends.find((b) => b.id === id)?.available ?? false;
}

/**
 * Pure: rank the viable capture strategies for a target and state the honest ceiling. A network transport needs
 * positioning (gateway or spoof) + the proxy; a radio transport needs its dongle and is its own position.
 */
export function planCapture(device: DeviceHint, backends: CaptureBackendStatus[]): CapturabilityPlan {
  const proxy = has(backends, 'network-proxy');
  const gateway = has(backends, 'on-path-gateway');
  const spoof = has(backends, 'on-path-spoof');
  const ble = has(backends, 'ble');
  const zigbee = has(backends, 'zigbee');
  const positioning: 'gateway' | 'spoof' | null = gateway ? 'gateway' : spoof ? 'spoof' : null;
  const positioned = positioning !== null;

  const strategies: CaptureStrategy[] = [];

  // Network transports (most cheap IoT). HTTP is plaintext; HTTPS depends on whether the device pins.
  const netViable = proxy && positioned;
  const netReason = !proxy
    ? 'install mitmproxy'
    : !positioned
      ? 'no positioning — declare a gateway or enable ARP spoof (NET_ADMIN/NET_RAW)'
      : `proxy + ${positioning} positioning ready`;
  strategies.push({
    transport: 'http',
    positioning,
    viable: netViable,
    ceiling: 'captured_plaintext',
    reason: netViable ? `plaintext HTTP OTA → full blob (${netReason})` : `blocked — ${netReason}`,
  });
  strategies.push({
    transport: 'https',
    positioning,
    viable: netViable,
    // The honest best case; the realized ceiling drops to blocked_by_pinning if the device pins (seen on the wire).
    ceiling: 'captured_plaintext',
    reason: netViable
      ? 'HTTPS via the FirmLab CA → full blob UNLESS the device pins (then metadata only until unpinned)'
      : `blocked — ${netReason}`,
  });

  // Radio transports — only offered when the dongle is present (otherwise it's just "attach hardware", see hint).
  if (ble) {
    strategies.push({
      transport: 'ble-gatt',
      positioning: null,
      viable: true,
      ceiling: 'captured_plaintext',
      reason: 'BLE sniffer present → reassemble the DFU characteristic writes',
    });
  }
  if (zigbee) {
    strategies.push({
      transport: 'zigbee-ota',
      positioning: null,
      viable: true,
      ceiling: 'captured_plaintext',
      reason: 'Zigbee sniffer present → capture the OTA Upgrade cluster (0x0019)',
    });
  }

  // Rank: viable first, then by completeness/cheapness (plaintext HTTP > HTTPS > radio).
  const rank = (s: CaptureStrategy): number => {
    const order: Record<string, number> = { http: 0, https: 1, 'ble-gatt': 2, 'zigbee-ota': 3 };
    return (s.viable ? 0 : 100) + (order[s.transport] ?? 9);
  };
  strategies.sort((a, b) => rank(a) - rank(b));

  const best = strategies.find((s) => s.viable);
  const radioHinted =
    /ble|bluetooth|homekit|zigbee/i.test(device.typeGuess ?? '') || /_hap|zigbee/i.test(device.mdnsIdentity ?? '');

  let ceiling: AcquisitionState;
  let reason: string;
  let unlockHint: string | null;
  if (best) {
    ceiling = best.ceiling;
    reason = `Best path: ${best.transport}${best.positioning ? ` via ${best.positioning}` : ''} → ${ceiling}.`;
    unlockHint =
      best.transport === 'https'
        ? 'If the device pins TLS, run the bundled Frida unpin template on a rooted phone.'
        : null;
  } else if (radioHinted && !ble && !zigbee) {
    ceiling = 'blocked_needs_hardware';
    reason = 'This looks like a BLE/Zigbee device but no radio sniffer is attached.';
    unlockHint = 'Attach an nRF52840 (BLE) or a CC2531/ConBee (Zigbee) to capture over the air.';
  } else {
    ceiling = 'metadata_only';
    reason = 'No viable full-capture path yet — the network transports need the proxy + positioning.';
    unlockHint = !proxy
      ? 'Install mitmproxy.'
      : 'Get on-path: declare a gateway (FIRMLAB_CAPTURE_GATEWAY=1), enable ARP spoof (bettercap + NET_ADMIN/NET_RAW), or run the LAN capture agent.';
  }

  return { strategies, ceiling, reason, unlockHint };
}

interface FlowFacts {
  tlsPosture: string | null;
  carved: number;
  firmwareScore: number;
}

/**
 * Pure: the acquisition ceiling actually realized by a session's observed flows. A carved blob = captured; a
 * pinned TLS flow with nothing carved = blocked_by_pinning; flows but nothing carved = metadata_only; nothing yet.
 */
export function realizedCeiling(flows: FlowFacts[]): AcquisitionState | null {
  if (flows.length === 0) return null;
  if (flows.some((f) => f.carved)) return 'captured_plaintext';
  if (flows.some((f) => f.tlsPosture === 'tls-pinned')) return 'blocked_by_pinning';
  return 'metadata_only';
}
