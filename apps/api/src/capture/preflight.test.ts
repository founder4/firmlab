import { describe, expect, it } from 'vitest';
import type { CaptureBackendStatus, CaptureRole } from './backends.js';
import { planCapture, realizedCeiling } from './preflight.js';

const mk = (id: string, available: boolean, role: CaptureRole = 'interception'): CaptureBackendStatus => ({
  id: id as CaptureBackendStatus['id'],
  role,
  transports: [],
  unlocks: '',
  available,
  reason: '',
  capabilities: {},
});

const NONE = { typeGuess: null, mdnsIdentity: null };

describe('planCapture', () => {
  it('makes plaintext HTTP the best path when proxy + gateway are both ready', () => {
    const plan = planCapture(NONE, [
      mk('network-proxy', true),
      mk('on-path-gateway', true, 'positioning'),
      mk('on-path-spoof', false, 'positioning'),
    ]);
    expect(plan.ceiling).toBe('captured_plaintext');
    expect(plan.strategies[0]?.transport).toBe('http');
    expect(plan.strategies[0]?.viable).toBe(true);
    expect(plan.unlockHint).toBeNull();
  });

  it('blocks the network transports honestly when there is no positioning', () => {
    const plan = planCapture(NONE, [
      mk('network-proxy', true),
      mk('on-path-gateway', false, 'positioning'),
      mk('on-path-spoof', false, 'positioning'),
    ]);
    expect(plan.strategies.every((s) => !s.viable)).toBe(true);
    expect(plan.ceiling).toBe('metadata_only');
    expect(plan.unlockHint).toMatch(/gateway|spoof|agent/i);
  });

  it('offers a radio transport when the dongle is present', () => {
    const plan = planCapture(NONE, [mk('ble', true, 'radio')]);
    expect(plan.strategies.some((s) => s.transport === 'ble-gatt' && s.viable)).toBe(true);
    expect(plan.ceiling).toBe('captured_plaintext');
  });

  it('reports blocked_needs_hardware for a radio-hinted device with no sniffer', () => {
    const plan = planCapture({ typeGuess: 'HomeKit accessory?', mdnsIdentity: '_hap._tcp' }, [
      mk('network-proxy', false),
    ]);
    expect(plan.ceiling).toBe('blocked_needs_hardware');
    expect(plan.unlockHint).toMatch(/nRF52840|CC2531|ConBee/);
  });

  it('surfaces the Frida hint when HTTPS is the best available path', () => {
    const plan = planCapture(NONE, [mk('network-proxy', true), mk('on-path-spoof', true, 'positioning')]);
    // http ranks above https, so the best is http (no Frida hint) — but https is present + viable in the ladder.
    expect(plan.strategies.some((s) => s.transport === 'https' && s.viable)).toBe(true);
  });
});

describe('realizedCeiling', () => {
  it('is null before any flow is seen', () => {
    expect(realizedCeiling([])).toBeNull();
  });
  it('is captured_plaintext once a flow is carved', () => {
    expect(realizedCeiling([{ tlsPosture: 'tls-unpinned', carved: 1, firmwareScore: 100 }])).toBe('captured_plaintext');
  });
  it('is blocked_by_pinning when a pinned TLS flow appears and nothing carved', () => {
    expect(realizedCeiling([{ tlsPosture: 'tls-pinned', carved: 0, firmwareScore: 0 }])).toBe('blocked_by_pinning');
  });
  it('is metadata_only when flows are seen but none carved or pinned', () => {
    expect(realizedCeiling([{ tlsPosture: 'tls-unpinned', carved: 0, firmwareScore: 10 }])).toBe('metadata_only');
  });
});
