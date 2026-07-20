import { describe, expect, it } from 'vitest';
import { deliveryChannel, interpretTriggerRun, planDelivery } from './trigger.js';

describe('deliveryChannel', () => {
  it('routes CGI/env sources to env, stdin sources to stdin, else argv', () => {
    expect(deliveryChannel('getenv(QUERY_STRING)')).toBe('env');
    expect(deliveryChannel('fgets from stdin')).toBe('stdin');
    expect(deliveryChannel('recv on socket')).toBe('stdin');
    expect(deliveryChannel('argv[1]')).toBe('argv');
  });
});

describe('planDelivery', () => {
  it('command-injection: appends an echo-marker payload and keeps the marker to match', () => {
    const d = planDelivery(
      { vulnClass: 'command-injection', source: 'getenv(QUERY_STRING)', trigger: 'a=1' },
      'MARK123',
    );
    expect(d.mode).toBe('env');
    expect(d.marker).toBe('MARK123');
    expect(d.env?.QUERY_STRING).toContain(';echo MARK123;');
  });

  it('overflow: delivers a long input and no marker (crash-based)', () => {
    const d = planDelivery({ vulnClass: 'stack-overflow', source: 'recv', trigger: 'x' }, 'M');
    expect(d.mode).toBe('stdin');
    expect(d.marker).toBeNull();
    expect((d.input ?? '').length).toBeGreaterThan(1000);
  });

  it('argv delivery for an argv source', () => {
    const d = planDelivery({ vulnClass: 'other', source: 'argv[1]', trigger: 'payload' }, 'M');
    expect(d.mode).toBe('argv');
    expect(d.args).toEqual(['payload']);
  });
});

describe('interpretTriggerRun', () => {
  const inj = planDelivery({ vulnClass: 'command-injection', source: 'getenv', trigger: 'x' }, 'MARK123');
  const of = planDelivery({ vulnClass: 'overflow', source: 'recv', trigger: 'x' }, 'M');

  it('confirms command injection when the marker appears in stdout', () => {
    const v = interpretTriggerRun(inj, { stdout: 'ping ...\nMARK123\n', signal: null, exitCode: 0, timedOut: false });
    expect(v.confirmed).toBe(true);
    expect(v.proofState).toBe('confirmed_in_emulation');
  });

  it('confirms memory-unsafety on a crash signal', () => {
    const v = interpretTriggerRun(of, { stdout: '', signal: 'SIGSEGV', exitCode: null, timedOut: false });
    expect(v.confirmed).toBe(true);
    expect(v.note).toMatch(/SIGSEGV/);
  });

  it('does NOT confirm when it ran clean — the candidate stands, unproven', () => {
    const v = interpretTriggerRun(inj, { stdout: 'nothing', signal: null, exitCode: 0, timedOut: false });
    expect(v.confirmed).toBe(false);
    expect(v.proofState).toBe('needs_runtime_reproduction');
  });
});
