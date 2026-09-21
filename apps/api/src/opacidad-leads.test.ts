import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import type { FindingDraft } from './findings-normalize.js';
import { CROSS_TAINT_LEAD_CAP, crossTaintDecompileLeads } from './opacidad-leads.js';

describe('crossTaintDecompileLeads', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'opacidad-leads-'));
  afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }));

  const fakeElf = (): Buffer => Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0, 0, 0, 0]);

  const crossTaintDraft = (consumerPath: string, key = 'foo'): FindingDraft => ({
    kind: 'cross-binary-taint-channel-sink',
    title: `nvram key '${key}'`,
    severity: 'medium',
    proofState: 'needs_runtime_reproduction',
    evidence: { channelKind: 'nvram', key, consumer: { path: consumerPath, snippet: 'nvram get foo', sinks: [] } },
  });

  it('schedules a decompile for a real ELF consumer named by a channel-sink finding', () => {
    const root = path.join(tmp, 'rootfs-elf');
    fs.mkdirSync(path.join(root, 'usr/sbin'), { recursive: true });
    fs.writeFileSync(path.join(root, 'usr/sbin/consumer'), fakeElf());

    const leads = crossTaintDecompileLeads([crossTaintDraft('usr/sbin/consumer')], root);
    expect(leads).toEqual([expect.objectContaining({ kind: 'decompile-binary', target: 'usr/sbin/consumer' })]);
    expect(leads[0]?.reason).toMatch(/cross-binary nvram\/UCI key \('foo'\)/);
  });

  it('skips a script consumer — there is no import table to decompile', () => {
    const root = path.join(tmp, 'rootfs-script');
    fs.mkdirSync(path.join(root, 'etc/init.d'), { recursive: true });
    fs.writeFileSync(path.join(root, 'etc/init.d/consumer'), '#!/bin/sh\nnvram get foo\n');

    expect(crossTaintDecompileLeads([crossTaintDraft('etc/init.d/consumer')], root)).toEqual([]);
  });

  it('ignores findings of other kinds and consumers outside the rootfs', () => {
    const root = path.join(tmp, 'rootfs-empty');
    fs.mkdirSync(root, { recursive: true });
    const other: FindingDraft = {
      kind: 'cross-binary-taint-channel',
      title: 'bare channel',
      severity: 'low',
      proofState: 'needs_runtime_reproduction',
      evidence: { consumer: { path: 'usr/sbin/nope' } },
    };
    expect(crossTaintDecompileLeads([other, crossTaintDraft('usr/sbin/missing')], root)).toEqual([]);
  });

  it('dedupes a consumer named by more than one channel and respects the budget', () => {
    const root = path.join(tmp, 'rootfs-dedupe');
    fs.mkdirSync(path.join(root, 'usr/sbin'), { recursive: true });
    fs.writeFileSync(path.join(root, 'usr/sbin/a'), fakeElf());
    fs.writeFileSync(path.join(root, 'usr/sbin/b'), fakeElf());
    fs.writeFileSync(path.join(root, 'usr/sbin/c'), fakeElf());

    const drafts = [
      crossTaintDraft('usr/sbin/a', 'k1'),
      crossTaintDraft('usr/sbin/a', 'k2'), // same consumer, different key — one lead only
      crossTaintDraft('usr/sbin/b'),
      crossTaintDraft('usr/sbin/c'),
    ];
    const leads = crossTaintDecompileLeads(drafts, root, CROSS_TAINT_LEAD_CAP);
    expect(leads.map((l) => l.target)).toEqual(['usr/sbin/a', 'usr/sbin/b', 'usr/sbin/c']);
    expect(leads).toHaveLength(CROSS_TAINT_LEAD_CAP);
  });

  it('returns nothing at a zero budget', () => {
    const root = path.join(tmp, 'rootfs-budget');
    fs.mkdirSync(path.join(root, 'usr/sbin'), { recursive: true });
    fs.writeFileSync(path.join(root, 'usr/sbin/a'), fakeElf());
    expect(crossTaintDecompileLeads([crossTaintDraft('usr/sbin/a')], root, 0)).toEqual([]);
  });
});
