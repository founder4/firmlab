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
    expect(parseVersion('2.4.3')).toEqual({ nums: [2, 4, 3], fields: ['2', '4', '3'], letter: '', raw: '2.4.3' });
    expect(parseVersion('1.0.1f')).toEqual({
      nums: [1, 0, 1],
      fields: ['1', '0', '1'],
      letter: 'f',
      raw: '1.0.1f',
    });
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

  it('extracts pppd version via the marker-gated fallback when the label is a format string (real WR940N shape)', () => {
    // The real pppd binary stores `pppd version %s` and `2.4.3` as SEPARATE strings.
    const realShape = 'lcp_reqci\npppd version %s\nManufacturer\n2.4.3\nremote IP address';
    expect(extractComponentVersion(realShape, pppdRule)).toBe('2.4.3');
  });

  it('does NOT use the bare-version fallback without the pppd marker', () => {
    // A bare 2.4.3 with no `pppd version` label must not be picked up (avoids grabbing an unrelated number).
    expect(extractComponentVersion('some lib 2.4.3 build', pppdRule)).toBeNull();
  });

  // === Patterns read off the real binaries in this corpus, not from what the string ought to look like ===

  it('reads BusyBox out of the banner both corpus builds actually carry', () => {
    // DVRF's bin/busybox and the WR940N's, verbatim.
    const rule = ruleFor('busybox');
    expect(extractComponentVersion('BusyBox v1.7.2 (2016-03-09 22:33:37 CST)\nsh', rule)).toBe('1.7.2');
    expect(extractComponentVersion('BusyBox v1.01 (2026.05.28-02:39+0000) multi-call binary', rule)).toBe('1.01');
  });

  it('reads dropbear from the SSH banner, the one place it is not a format string', () => {
    // Every human-readable mention in the real dropbearmulti is `Dropbear sshd v%s` / `... version %s`; the
    // literal version survives only in the identification banner the daemon puts on the wire.
    const rule = ruleFor('dropbear');
    expect(extractComponentVersion('Dropbear sshd v%s\nSSH-2.0-dropbear_2012.55\n/var/run/dropbear.pid', rule)).toBe(
      '2012.55',
    );
    expect(extractComponentVersion('Dropbear multi-purpose version %s\ndropbear_close', rule)).toBeNull();
  });

  it('reads dnsmasq through the marker gate, where the value sits beside the format string', () => {
    // Verbatim adjacency from DVRF's usr/sbin/dnsmasq: the label, then the bare value on the next string.
    const rule = ruleFor('dnsmasq');
    expect(extractComponentVersion('Usage: dnsmasq [options]\ndnsmasq version %s\n1.10\n-v, --version', rule)).toBe(
      '1.10',
    );
    // A build that embeds the version literally takes the strict pattern instead of the gated fallback.
    expect(extractComponentVersion('/etc/dnsmasq.conf\ndnsmasq-2.78\n', rule)).toBe('2.78');
  });
});

describe('the ranges are the advisories, not the era around them', () => {
  it('claims the udhcpc command injection for both BusyBox builds this corpus ships', () => {
    const rule = ruleFor('busybox');
    // NVD enumerates `busybox:1.01` and `busybox:1.7.2` individually for this CVE — an assertion about these
    // exact versions, which is why it is claimable where an open-below range would not be.
    for (const v of ['1.7.2', '1.01']) {
      expect(matchCves(rule, v).map((c) => c.id)).toEqual(['CVE-2011-2716']);
    }
    expect(matchCves(rule, '1.36.1')).toEqual([]);
  });

  it('does not carry CVE-2016-2148, whose NVD range has no lower bound to stand on', () => {
    const rule = ruleFor('busybox');
    expect(rule.cves.map((c) => c.id)).not.toContain('CVE-2016-2148');
  });

  it('claims the dropbear format-string RCE for the shipped 2012.55 and not for a patched build', () => {
    const rule = ruleFor('dropbear');
    expect(matchCves(rule, '2012.55').map((c) => c.id)).toEqual(['CVE-2016-7406']);
    expect(matchCves(rule, '2016.74')).toEqual([]);
  });

  /**
   * The honesty case, and the reason this table sets its own floors. NVD's CPE match for CVE-2017-14491 is open
   * below, so it "affects" dnsmasq 1.10 — a 2001 codebase — exactly as much as 2.77. Inheriting that would
   * manufacture a critical finding on DVRF out of a modelling artifact. Reported as a version instead.
   */
  it('refuses to claim a 2017 dnsmasq CVE against the 1.x build NVD would happily match', () => {
    const rule = ruleFor('dnsmasq');
    expect(matchCves(rule, '1.10')).toEqual([]);
    expect(matchCves(rule, '2.55').map((c) => c.id)).toEqual(['CVE-2017-14491']);
    expect(matchCves(rule, '2.78')).toEqual([]);

    const drafts = buildComponentFindings([{ component: 'dnsmasq', version: '1.10', path: 'usr/sbin/dnsmasq' }]);
    expect(drafts).toHaveLength(1);
    expect(drafts[0]?.kind).toBe('component-version');
    expect(drafts[0]?.severity).toBe('info');
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

describe('zero-padded versions are different releases, not the same one', () => {
  /**
   * BusyBox 1.01 (2005) and BusyBox 1.1 (2006) both parsed to `[1, 1]`, so the comparator called them equal. The
   * WR940N in this corpus ships exactly `1.01`, so the collapse was live, not theoretical — harmless only because
   * no range boundary happened to fall between the two.
   */
  it('tells 1.01 apart from 1.1, in the order they shipped', () => {
    const a = pv('1.01');
    const b = pv('1.1');
    expect(a.nums).toEqual(b.nums); // the collapse: identical numerically
    expect(compareVersion(a, b)).toBe(-1);
    expect(compareVersion(b, a)).toBe(1);
  });

  it('puts a boundary between them where the collapse used to answer the same for both', () => {
    expect(versionInRange('1.01', '1.0', '1.0.9')).toBe(false);
    expect(versionInRange('1.01', '1.1', '1.20')).toBe(false); // 1.01 predates the 1.1 series
    expect(versionInRange('1.1', '1.1', '1.20')).toBe(true);
  });

  it('does not treat a bare 0 as padding', () => {
    expect(compareVersion(pv('1.0'), pv('1.0'))).toBe(0);
    expect(versionInRange('1.0.0', '1.0.0', '1.24.2')).toBe(true);
  });

  it('leaves the corpus ranges answering as before', () => {
    // Both BusyBox builds still sit inside CVE-2011-2716, and pppd/openssl are unaffected.
    expect(versionInRange('1.01', '1.0.0', '1.19.4')).toBe(true);
    expect(versionInRange('1.7.2', '1.0.0', '1.19.4')).toBe(true);
    expect(versionInRange('2.4.3', '2.4.2', '2.4.8')).toBe(true);
    expect(versionInRange('1.0.1e', '1.0.1', '1.0.1f')).toBe(true);
  });
});
