import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { componentDirPriority, describeComponentScan, runComponentCve } from './component-cve.js';

// The rule table, version ordering, extraction, matching and verdicts are pure and tested in
// `packages/core/test/component-cve.test.ts`; this file covers only the rootfs walk and its budget.

describe('runComponentCve (rootfs walk)', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'compcve-'));
  afterAll(() => fs.rmSync(tmp, { recursive: true, force: true }));

  it('degrades honestly with no rootfs', () => {
    const r = runComponentCve(null);
    expect(r.available).toBe(false);
    expect(r.findings).toEqual([]);
  });

  it('finds a vulnerable pppd binary in a synthetic rootfs and matches its CVE', () => {
    const root = path.join(tmp, 'rootfs');
    fs.mkdirSync(path.join(root, 'usr', 'sbin'), { recursive: true });
    // A binary blob whose printable strings carry the pppd version banner.
    const blob = Buffer.concat([
      Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0, 0, 0]),
      Buffer.from('\x00pppd version 2.4.3\x00some other strings\x00', 'latin1'),
    ]);
    fs.writeFileSync(path.join(root, 'usr', 'sbin', 'pppd'), blob);
    const r = runComponentCve(root);
    expect(r.available).toBe(true);
    expect(r.hits).toEqual([{ component: 'pppd', version: '2.4.3', path: 'usr/sbin/pppd' }]);
    const cve = r.findings.find((f) => f.kind === 'component-cve');
    expect(cve?.title).toContain('CVE-2020-8597');
  });
});
describe('componentDirPriority', () => {
  it('visits the directories these components actually live in before anything else', () => {
    expect(componentDirPriority('usr/lib')).toBeLessThan(componentDirPriority('usr/share/doc'));
    expect(componentDirPriority('usr/lib/libssl.so.1.1')).toBeLessThan(componentDirPriority('var/www'));
    expect(componentDirPriority('lib')).toBeLessThan(componentDirPriority('usr/bin'));
  });

  it('gives every unlisted directory one rank, below all listed ones', () => {
    expect(componentDirPriority('etc')).toBe(componentDirPriority('var/www/html'));
    expect(componentDirPriority('etc')).toBeGreaterThan(componentDirPriority('usr/bin'));
  });

  it('does not mistake a prefix for a directory', () => {
    // `libexec-old` is not under `lib`, and ranking it as if it were would spend the budget in the wrong subtree.
    expect(componentDirPriority('libexec-old')).toBe(componentDirPriority('etc'));
    expect(componentDirPriority('lib/x')).toBeLessThan(componentDirPriority('libexec-old'));
  });

  // The defect this pins was found by RUNNING the walk, not by a fixture: the priority list holds two-segment
  // paths while the walk descends one level at a time, so `usr` matched nothing and ranked last — sending a
  // bounded walk everywhere except where the components are. Measured in-container on a Debian root, a truncated
  // walk found 0 components before this and 1 (`usr/lib/aarch64-linux-gnu/libcrypto.so.3`) after, same budget.
  it('ranks a directory that is on the WAY to a component directory, not just one inside it', () => {
    expect(componentDirPriority('usr')).toBe(componentDirPriority('usr/lib'));
    expect(componentDirPriority('usr')).toBeLessThan(componentDirPriority('etc'));
    // Best-of, not first-match: `usr` leads to `usr/lib` (the top rank) as well as to `usr/bin`.
    expect(componentDirPriority('usr')).toBeLessThan(componentDirPriority('usr/bin'));
  });

  it('still ranks a directory that merely shares a name prefix as unlisted', () => {
    expect(componentDirPriority('usrshare')).toBe(componentDirPriority('etc'));
  });
});

describe('describeComponentScan', () => {
  // The branch that runs on every healthy rootfs: no caveat, because a caveat printed always stops being read.
  it('states the counts plainly when the walk finished', () => {
    const s = describeComponentScan(4, 2, { walked: 900, truncated: false });
    expect(s).toContain('4 bundled component(s) versioned, 2 CVE(s) matched');
    expect(s).not.toContain('FLOOR');
  });

  it('calls both counts a floor when the walk was cut, and says why that matters', () => {
    const s = describeComponentScan(4, 2, { walked: 8000, truncated: true });
    expect(s).toContain('FLOOR');
    expect(s).toContain('8000 entries');
    // The claim the reader must not make from a partial walk.
    expect(s).toContain('indistinguishable here from one that is not present');
  });
});
