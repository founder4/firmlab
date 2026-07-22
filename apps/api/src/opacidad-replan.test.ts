import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { daemonLeads, handlerLeads, resolveDaemonBinary } from './opacidad-leads.js';
import { type Lead, type ScheduleState, replan, scheduleLeads, specKey } from './opacidad-plan.js';
import type { Service } from './providers/servicemap.js';
import type { HandlerAnalysis } from './providers/webtaint.js';

const lead = (target: string): Lead => ({ kind: 'decompile-binary', target, reason: `decompile ${target}` });

describe('replan + specKey', () => {
  it('maps a decompile-binary lead to a W5 spec tagged origin=replan', () => {
    const specs = replan(lead('usr/sbin/httpd'), new Set());
    expect(specs).toHaveLength(1);
    expect(specs[0]).toMatchObject({ provider: 'decompile', target: 'usr/sbin/httpd', origin: 'replan', built: true });
    expect(specs[0]?.worker).toContain('httpd');
  });

  it('drops a lead whose binary is already planned (idempotent)', () => {
    const planned = new Set(['decompile:usr/sbin/httpd']);
    expect(replan(lead('usr/sbin/httpd'), planned)).toHaveLength(0);
  });

  it('keys a decompile spec on its target, other specs on provider/worker', () => {
    expect(
      specKey({ worker: 'x', reason: '', needsRootfs: true, built: true, provider: 'decompile', target: 'a/b' }),
    ).toBe('decompile:a/b');
    expect(specKey({ worker: 'W2', reason: '', needsRootfs: true, built: true, provider: 'sbom' })).toBe('sbom');
  });
});

describe('scheduleLeads', () => {
  it('appends new specs, dedupes, and caps dynamic growth (surfacing the overflow)', () => {
    const state: ScheduleState = { planned: new Set(), dynamicCount: 0, capped: 0 };
    const leads = [lead('a'), lead('b'), lead('a'), lead('c')]; // 'a' twice
    const added = scheduleLeads(leads, state, 2);
    expect(added.map((s) => s.target)).toEqual(['a', 'b']); // 'a' deduped, cap 2 stops before 'c'
    expect(state.dynamicCount).toBe(2);
    expect(state.capped).toBe(1); // 'c' over the cap
  });

  it('does not re-schedule a binary already in the planned set', () => {
    const state: ScheduleState = { planned: new Set(['decompile:a']), dynamicCount: 0, capped: 0 };
    expect(scheduleLeads([lead('a')], state, 8)).toHaveLength(0);
  });
});

describe('lead resolution over a rootfs', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-replan-'));
  afterAll(() => fs.rmSync(root, { recursive: true, force: true }));
  const touch = (rel: string): void => {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, '\x7fELF');
  };
  touch('usr/sbin/dropbear');
  touch('bin/httpd');
  touch('usr/sbin/oui-httpd');

  it('resolves absolute, bare, and missing daemon tokens', () => {
    expect(resolveDaemonBinary(root, '/usr/sbin/dropbear')).toBe('usr/sbin/dropbear');
    expect(resolveDaemonBinary(root, 'httpd')).toBe('bin/httpd');
    expect(resolveDaemonBinary(root, 'nonexistent')).toBeNull();
    expect(resolveDaemonBinary(root, 'internal')).toBeNull();
  });

  it('builds decompile leads only for autostart network daemons that resolve', () => {
    const services: Service[] = [
      { name: 'dropbear', binary: '/usr/sbin/dropbear', source: 'etc/inittab', network: true, autostart: true },
      { name: 'httpd', binary: 'httpd', source: 'etc/rc.local', network: true, autostart: true },
      { name: 'telnet', binary: 'internal', source: 'etc/inetd.conf', network: true, autostart: true },
      { name: 'ntpd', binary: '/usr/sbin/ntpd', source: 'x', network: false, autostart: true },
    ];
    expect(daemonLeads(services, root).map((l) => l.target)).toEqual(['usr/sbin/dropbear', 'bin/httpd']);
  });

  it('builds an httpd decompile lead only when a handler is tainted', () => {
    const base = { sinks: [], sources: [], fromUci: false, runsAsRoot: false };
    const tainted: HandlerAnalysis[] = [{ handler: 'x', object: 'tor', ...base, tainted: true }];
    const clean: HandlerAnalysis[] = [{ handler: 'x', object: 'diag', ...base, tainted: false }];
    expect(handlerLeads(tainted, root).map((l) => l.target)).toEqual(['usr/sbin/oui-httpd']);
    expect(handlerLeads(clean, root)).toHaveLength(0);
  });
});
