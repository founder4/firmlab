/**
 * Active on-path positioning via ARP spoof (Phase 6.2, design §5b). Gets FirmLab on-path for ONE target without
 * any router config: bettercap poisons that device's ARP for the gateway so its traffic detours through FirmLab,
 * where the 6.1 proxy intercepts it. Strictly single-target and time-boxed, with GUARANTEED restore — bettercap
 * repairs the ARP tables on exit, and teardown kills it on every path.
 *
 * Availability mirrors the on-path-spoof backend exactly (bettercap on PATH + NET_ADMIN/NET_RAW), so a deployment
 * that can't spoof (no caps / not a Linux host / Docker without --network host) degrades honestly — the session
 * records that positioning is manual, it never pretends to be on-path. The command builder is pure + unit-tested.
 */
import { type ChildProcess, spawn } from 'node:child_process';
import { detectCaptureBackends } from './backends.js';

/**
 * Pure: the bettercap invocation that ARP-spoofs a single target. `arp.spoof.internal false` keeps the poisoning
 * to the target↔gateway path (not the whole subnet). bettercap restores ARP automatically when it exits.
 */
export function buildBettercapArgs(iface: string | null, targetIp: string): string[] {
  const caplet = `set arp.spoof.targets ${targetIp}; set arp.spoof.internal false; arp.spoof on`;
  const args = ['-no-colors', '-eval', caplet];
  if (iface) args.unshift('-iface', iface);
  return args;
}

/** Availability of ARP-spoof positioning — the exact on-path-spoof backend probe (bettercap + NET_ADMIN/NET_RAW). */
export function spoofAvailable(): boolean {
  return detectCaptureBackends().find((b) => b.id === 'on-path-spoof')?.available ?? false;
}

/** Whether the operator has declared clean gateway/mirror positioning — then no spoof is needed. */
export function gatewayDeclared(): boolean {
  return detectCaptureBackends().find((b) => b.id === 'on-path-gateway')?.available ?? false;
}

const spoofs = new Map<string, ChildProcess>();

export interface PositionResult {
  /** 'gateway' (operator-declared) | 'spoof' (active) | 'manual' (neither available). */
  strategy: 'gateway' | 'spoof' | 'manual';
  active: boolean;
  reason: string;
}

/**
 * Choose + arm positioning for a session's target. Gateway (if declared) is cleanest and needs nothing spawned;
 * else ARP-spoof if available + we know the target IP; else honest `manual` (the operator positions the target).
 */
export function armPositioning(sessionId: string, targetIp: string | null): PositionResult {
  if (gatewayDeclared()) {
    return { strategy: 'gateway', active: true, reason: 'Operator-declared gateway/mirror — target already on-path.' };
  }
  if (!spoofAvailable()) {
    return {
      strategy: 'manual',
      active: false,
      reason:
        'No spoof positioning (bettercap + NET_ADMIN/NET_RAW absent) — position the target manually (declare a gateway, or run the LAN capture agent).',
    };
  }
  if (!targetIp) {
    return {
      strategy: 'manual',
      active: false,
      reason: 'Target IP unknown (run discovery first) — cannot scope an ARP spoof; position the target manually.',
    };
  }
  try {
    const iface = process.env.FIRMLAB_CAPTURE_IFACE?.trim() || null;
    const proc = spawn('bettercap', buildBettercapArgs(iface, targetIp), { stdio: 'ignore', detached: false });
    proc.on('error', () => undefined);
    spoofs.set(sessionId, proc);
    return {
      strategy: 'spoof',
      active: true,
      reason: `ARP-spoofing ${targetIp} onto FirmLab (single target). Restored automatically on teardown.`,
    };
  } catch (e) {
    return {
      strategy: 'manual',
      active: false,
      reason: `Could not start bettercap: ${e instanceof Error ? e.message : String(e)}`,
    };
  }
}

/** Guaranteed restore: stop the spoof (bettercap repairs ARP on exit). Idempotent. */
export function stopPositioning(sessionId: string): void {
  const proc = spoofs.get(sessionId);
  if (!proc) return;
  try {
    proc.kill('SIGTERM');
  } catch {}
  spoofs.delete(sessionId);
}
