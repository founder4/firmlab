import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  COMPONENT_RULES,
  buildComponentFindings,
  compareVersion,
  extractComponentVersion,
  matchCves,
  parseVersion,
  runComponentCve,
  versionInRange,
} from './component-cve.js';

/** Parse or throw — keeps the comparison tests free of non-null assertions. */
function pv(s: string) {
  const v = parseVersion(s);
  if (!v) throw new Error(`unparseable version in test: ${s}`);
  return v;
}
/** Look up a component rule or throw. */
function ruleFor(component: string) {
  const r = COMPONENT_RULES.find((x) => x.component === component);
  if (!r) throw new Error(`no rule for ${component}`);
  return r;
}

describe('version parsing + comparison', () => {
  it('parses dotted versions with an optional trailing letter', () => {
    expect(parseVersion('2.4.3')).toEqual({ nums: [2, 4, 3], letter: '', raw: '2.4.3' });
    expect(parseVersion('1.0.1f')).toEqual({ nums: [1, 0, 1], letter: 'f', raw: '1.0.1f' });
    expect(parseVersion('not-a-version')).toBeNull();
  });

  it('compares numerically, then by trailing letter', () => {
    expect(compareVersion(pv('2.4.3'), pv('2.4.8'))).toBe(-1);
    expect(compareVersion(pv('1.0.1f'), pv('1.0.1'))).toBe(1);
    expect(compareVersion(pv('1.0.1g'), pv('1.0.1f'))).toBe(1);
    expect(compareVersion(pv('2.4.8'), pv('2.4.8'))).toBe(0);
  });

  it('range check is inclusive and letter-aware', () => {
    expect(versionInRange('2.4.3', '2.4.2', '2.4.8')).toBe(true); // pppd CVE-2020-8597
    expect(versionInRange('2.4.9', '2.4.2', '2.4.8')).toBe(false); // fixed
    expect(versionInRange('2.4.1', '2.4.2', '2.4.8')).toBe(false); // pre-vuln
    expect(versionInRange('1.0.1f', '1.0.1', '1.0.1f')).toBe(true); // Heartbleed upper edge
    expect(versionInRange('1.0.1g', '1.0.1', '1.0.1f')).toBe(false); // patched
  });
});

describe('component version extraction', () => {
  const pppdRule = ruleFor('pppd');
  const opensslRule = ruleFor('openssl');

  it('extracts pppd version from its banner string', () => {
    expect(extractComponentVersion('local IP address\npppd version 2.4.3\nRemote message', pppdRule)).toBe('2.4.3');
  });

  it('extracts OpenSSL version from its banner string', () => {
    expect(extractComponentVersion('OpenSSL 1.0.1e 11 Feb 2013\nfoo', opensslRule)).toBe('1.0.1e');
  });

  it('returns null when no version string is present', () => {
    expect(extractComponentVersion('just some unrelated strings', pppdRule)).toBeNull();
  });
});

describe('CVE matching + findings', () => {
  const pppdRule = ruleFor('pppd');

  it('matches CVE-2020-8597 for a vulnerable pppd and not for a fixed one', () => {
    expect(matchCves(pppdRule, '2.4.3').map((c) => c.id)).toEqual(['CVE-2020-8597']);
    expect(matchCves(pppdRule, '2.5.0')).toEqual([]);
  });

  it('builds a critical static_confirmed finding for the pppd CVE', () => {
    const drafts = buildComponentFindings([{ component: 'pppd', version: '2.4.3', path: 'usr/sbin/pppd' }]);
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.kind).toBe('component-cve');
    expect(drafts[0]?.severity).toBe('critical');
    expect(drafts[0]?.proofState).toBe('static_confirmed');
    expect(drafts[0]?.title).toContain('CVE-2020-8597');
    expect((drafts[0]?.evidence as { affected: string }).affected).toBe('2.4.2–2.4.8');
  });

  it('emits an inventory fact (not a vuln) for a component with no CVE match', () => {
    const drafts = buildComponentFindings([{ component: 'pppd', version: '2.5.0', path: 'usr/sbin/pppd' }]);
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.kind).toBe('component-version');
    expect(drafts[0]?.severity).toBe('info');
  });
});

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
