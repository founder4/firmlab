import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import {
  COMPONENT_RULES,
  buildComponentFindings,
  compareVersion,
  componentDirPriority,
  curatedCveVerdict,
  cveCovers,
  describeComponentScan,
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
    // 1.36.1 is past this CVE's 1.19.4 upper bound. Scoped to the CVE because the awk entries added on
    // 2026-09-19 DO match that version, and a bare `toEqual([])` here would have quietly asserted they must not.
    expect(matchCves(rule, '1.36.1').map((c) => c.id)).not.toContain('CVE-2011-2716');
  });

  it('does not carry CVE-2016-2148, whose NVD range has no lower bound to stand on', () => {
    const rule = ruleFor('busybox');
    expect(rule.cves.map((c) => c.id)).not.toContain('CVE-2016-2148');
    // …and the refusal is recorded as data, because grype matches it from a manifest on the same images.
    expect(rule.rejected?.map((r) => r.id)).toContain('CVE-2016-2148');
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
    expect(matchCves(rule, '2.55').map((c) => c.id)).toContain('CVE-2017-14491');
    // 2.78 is past this CVE's inclusive 2.77 bound. Scoped to the CVE for the same reason as the BusyBox case
    // above: the DNSpooq entries added on 2026-09-19 are floored at the same 2.0 and DO cover 2.78.
    expect(matchCves(rule, '2.78').map((c) => c.id)).not.toContain('CVE-2017-14491');

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

/**
 * The reconciliation between the two lanes. Every case here is the shape of a real grype row: the package name
 * and version come from a manifest, which is a different measurement from the binary string this table reads.
 */
describe('curatedCveVerdict — what this table says about a row the other lane matched', () => {
  it('names the refusal for the CVE this table evaluated and left out', () => {
    // The backlog case verbatim: grype accepts CVE-2016-2148 for BusyBox 1.18.4 from an opkg manifest.
    const v = curatedCveVerdict('busybox', '1.18.4', 'CVE-2016-2148');
    expect(v?.kind).toBe('rejected');
    expect(v?.note).toContain('refuses to claim it');
    expect(v?.note).toContain('no analyst');
  });

  it('refuses the same CVE at every version, because the refusal is about the advisory, not the build', () => {
    for (const version of ['1.01', '1.18.4', '1.36.1', 'not-a-version']) {
      expect(curatedCveVerdict('busybox', version, 'CVE-2016-2148')?.kind).toBe('rejected');
    }
  });

  it('corroborates without upgrading when the curated range covers the manifest version', () => {
    const v = curatedCveVerdict('busybox', '1.18.4', 'CVE-2011-2716');
    expect(v?.kind).toBe('claimed');
    expect(v?.note).toContain('static_confirmed');
  });

  it('disputes a row whose version falls below this table own floor', () => {
    // dnsmasq 1.10 is the floored case: NVD's open-below range matches it, the curated rule starts at 2.0.
    const v = curatedCveVerdict('dnsmasq', '1.10', 'CVE-2017-14491');
    expect(v?.kind).toBe('outside_curated_range');
    expect(v?.note).toContain('2.0–2.77');
  });

  it('says nothing rather than guessing when the manifest version carries a package revision', () => {
    // `1.18.4-1` is an opkg/dpkg revision, not a version this table can compare. Silence, not "out of range".
    const v = curatedCveVerdict('busybox', '1.18.4-1', 'CVE-2011-2716');
    expect(v?.kind).toBe('version_not_comparable');
    expect(v?.note).toContain('neither corroborates nor disputes');
  });

  it('has no opinion on an unmapped component or an unknown CVE', () => {
    expect(curatedCveVerdict('lighttpd', '1.4.35', 'CVE-2015-3200')).toBeNull();
    expect(curatedCveVerdict('busybox', '1.18.4', 'CVE-2021-42374')).toBeNull();
  });
});

/**
 * The 2026-09-19 additions. Each range below was read one CVE at a time from the NVD API, and these cases exist
 * because the shortcut was available and wrong: the nine BusyBox awk entries look like one advisory with one
 * range and they have five different lower bounds.
 */
describe('the BusyBox awk family does not share one range', () => {
  const busybox = COMPONENT_RULES.find((r) => r.component === 'busybox');
  const ids = (version: string) => matchCves(busybox as NonNullable<typeof busybox>, version).map((c) => c.id);

  it('applies each awk CVE only from its OWN lower bound', () => {
    // 1.18.4 is the IMOU camera in this corpus. Above 1.16.0 and 1.18.0, below 1.21.0 / 1.26.0 / 1.28.0.
    const at1184 = ids('1.18.4');
    expect(at1184).toContain('CVE-2021-42378'); // 1.16.0
    expect(at1184).toContain('CVE-2021-42379'); // 1.18.0
    expect(at1184).toContain('CVE-2021-42384'); // 1.18.0
    expect(at1184).not.toContain('CVE-2021-42381'); // 1.21.0
    expect(at1184).not.toContain('CVE-2021-42382'); // 1.26.0
    expect(at1184).not.toContain('CVE-2021-42380'); // 1.28.0
  });

  it('stops the 2021 family at its upper bound and starts the 2023 trio at theirs', () => {
    // 1.36.1 is the GL.iNet BE3600: past 1.33.1, so no 2021 entry — and it is the exact enumerated CPE of the
    // three 2023 ones.
    const at1361 = ids('1.36.1');
    expect(at1361.filter((id) => id.startsWith('CVE-2021-'))).toEqual([]);
    expect(at1361).toEqual(expect.arrayContaining(['CVE-2023-42364', 'CVE-2023-42365', 'CVE-2023-42366']));
    // Those three are pinned to that one version, not to a range around it.
    expect(ids('1.36.0')).not.toContain('CVE-2023-42364');
    expect(ids('1.37.0')).not.toContain('CVE-2023-42364');
  });

  it('leaves the ancient builds out of the awk family entirely', () => {
    // BusyBox 1.01 (WR940N) and 1.7.2 (DVRF) are below every awk lower bound; they keep only the udhcpc entry.
    for (const old of ['1.01', '1.7.2']) {
      expect(ids(old).filter((id) => id.includes('4238') || id.includes('30065'))).toEqual([]);
      expect(ids(old)).toContain('CVE-2011-2716');
    }
  });
});

describe('an exclusive upper bound is carried, not guessed into an inclusive one', () => {
  const curl = COMPONENT_RULES.find((r) => r.component === 'curl');

  it('treats NVD’s "< 8.4.0" as exclusive', () => {
    expect(cveCovers('8.3.0', { low: '7.69.0', high: '8.4.0', highExclusive: true })).toBe(true);
    expect(cveCovers('8.4.0', { low: '7.69.0', high: '8.4.0', highExclusive: true })).toBe(false);
    // Without the flag the same bound would include 8.4.0 — the off-by-one the flag exists to prevent.
    expect(cveCovers('8.4.0', { low: '7.69.0', high: '8.4.0' })).toBe(true);
  });

  it('does not claim the SOCKS5 overflow against the curl this corpus actually ships', () => {
    // The GL.iNet BE3600 ships 8.6.0. A rule firing here would be calling a fixed version vulnerable.
    expect(matchCves(curl as NonNullable<typeof curl>, '8.6.0')).toEqual([]);
    expect(matchCves(curl as NonNullable<typeof curl>, '8.3.0').map((c) => c.id)).toEqual(['CVE-2023-38545']);
  });

  it('reads the version out of both real curl strings, which are different strings', () => {
    const rule = curl as NonNullable<typeof curl>;
    // Verbatim from /usr/bin/curl and /usr/lib/libcurl.so.4.8.0 on the BE3600 rootfs.
    expect(extractComponentVersion('curl 8.6.0 (aarch64-openwrt-linux-gnu) %s', rule)).toBe('8.6.0');
    expect(extractComponentVersion('libcurl/8.6.0 OpenSSL/3.0.13', rule)).toBe('8.6.0');
  });
});

describe('a CVE with a precondition this provider cannot check comes off the strongest rung', () => {
  const dnsmasq = COMPONENT_RULES.find((r) => r.component === 'dnsmasq');
  const drafts = () => buildComponentFindings([{ component: 'dnsmasq', version: '2.78', path: 'usr/sbin/dnsmasq' }]);

  it('keeps DNSSEC-gated DNSpooq entries at needs_runtime_reproduction and names the condition', () => {
    const gated = drafts().find((d) => d.title.includes('CVE-2020-25681'));
    expect(gated?.proofState).toBe('needs_runtime_reproduction');
    expect((gated?.evidence as Record<string, unknown>).precondition).toContain('DNSSEC');
    expect(gated?.rationale).toContain('the vulnerability is NOT');
  });

  it('leaves the ungated cache-poisoning entries at static_confirmed', () => {
    const ungated = drafts().find((d) => d.title.includes('CVE-2020-25685'));
    expect(ungated?.proofState).toBe('static_confirmed');
    expect((ungated?.evidence as Record<string, unknown>).precondition).toBeUndefined();
  });

  it('floors DNSpooq at the 2.x series, so the 1.10 in this corpus is a version and not seven CVEs', () => {
    const rule = dnsmasq as NonNullable<typeof dnsmasq>;
    expect(matchCves(rule, '1.10')).toEqual([]);
    // 2.78 is past CVE-2017-14491's inclusive 2.77 and inside all seven DNSpooq entries.
    expect(
      matchCves(rule, '2.78')
        .map((c) => c.id)
        .sort(),
    ).toEqual([
      'CVE-2020-25681',
      'CVE-2020-25682',
      'CVE-2020-25683',
      'CVE-2020-25684',
      'CVE-2020-25685',
      'CVE-2020-25686',
      'CVE-2020-25687',
    ]);
    // 2.83 is the exclusive bound: the release that FIXED it must not be reported as affected by it.
    expect(matchCves(rule, '2.83').filter((c) => c.id.startsWith('CVE-2020-'))).toEqual([]);
  });
});

/**
 * The floor policy, as an invariant instead of a paragraph.
 *
 * Until 2026-09-19 the difference between a CVE this table claims and one it refuses lived in prose, and the
 * prose contradicted itself: `CVE-2016-2148` is refused for an open-below range with no enumerated CPE, while
 * `CVE-2017-14491` is claimed on exactly that. What settled it was counting — nine of the 26 rules are open
 * below, so the strict reading would also delete `CVE-2016-7406`, which matches the Dropbear 2012.55 in this
 * corpus and is correct. A rule that costs a true positive to satisfy a sentence is not the rule.
 *
 * So the real policy is "an open-below range needs a defensible floor", and these cases make it unskippable.
 */
describe('every curated rule declares what NVD backs it with', () => {
  const allRules = COMPONENT_RULES.flatMap((r) => r.cves.map((c) => ({ component: r.component, cve: c })));

  it('covers every rule, with no shape left unstated', () => {
    expect(allRules.length).toBeGreaterThan(0);
    for (const { component, cve } of allRules) {
      expect(['bounded', 'enumerated', 'open-below'], `${component} ${cve.id}`).toContain(cve.nvdBacking);
    }
  });

  it('REFUSES an open-below rule that does not justify its floor', () => {
    // The invariant. A future entry cannot inherit an unbounded CPE range by saying nothing.
    for (const { component, cve } of allRules) {
      if (cve.nvdBacking !== 'open-below') continue;
      const why = cve.floorRationale ?? '';
      expect(why.length, `${component} ${cve.id} is open-below and must justify its floor`).toBeGreaterThan(80);
      // The justification has to be about THIS rule's floor, not a generic sentence.
      expect(why, `${component} ${cve.id}`).toMatch(/floor/i);
    }
  });

  it('does not let a bounded or enumerated rule carry a floor justification it does not need', () => {
    // A floor rationale on a rule NVD already bounds is a claim nobody is making; it would read as though the
    // lower end were this table's invention when it is NVD's.
    for (const { component, cve } of allRules) {
      if (cve.nvdBacking === 'open-below') continue;
      expect(cve.floorRationale, `${component} ${cve.id}`).toBeUndefined();
    }
  });

  it('keeps the count of each shape where 2026-09-19 measured it', () => {
    // Not a golden-file assertion for its own sake: the nine open-below rules are exactly the population the
    // strict reading would have deleted, and if that number moves the policy decision deserves re-reading.
    const shape = (s: string) => allRules.filter((r) => r.cve.nvdBacking === s).length;
    expect(shape('open-below')).toBe(9);
    expect(shape('bounded') + shape('enumerated') + shape('open-below')).toBe(allRules.length);
  });

  it('puts the floor justification on the finding, not only in the source', () => {
    // Dropbear 2012.55 is the live case: a real corpus version matched by an open-below rule. The reader has
    // to be able to see that the lower bound is this table's and why, without opening the table.
    const drafts = buildComponentFindings([
      { component: 'dropbear', version: '2012.55', path: 'usr/sbin/dropbearmulti' },
    ]);
    const row = drafts.find((d) => d.title.includes('CVE-2016-7406'));
    expect(row?.rationale).toContain('bounds the advisory only from above');
    expect(row?.rationale).toContain('2011.54');
    expect((row?.evidence as Record<string, unknown>).nvdBacking).toBe('open-below');
    expect((row?.evidence as Record<string, unknown>).floorRationale).toBeTruthy();
  });

  it('says on an enumerated row that an analyst asserted the build', () => {
    const drafts = buildComponentFindings([{ component: 'busybox', version: '1.36.1', path: 'bin/busybox' }]);
    const row = drafts.find((d) => d.title.includes('CVE-2023-42364'));
    expect(row?.rationale).toContain('analyst asserted this build');
    expect((row?.evidence as Record<string, unknown>).floorRationale).toBeUndefined();
  });

  it('leaves CVE-2016-2148 refused, because no floor can be written for it', () => {
    const busybox = COMPONENT_RULES.find((r) => r.component === 'busybox');
    expect(busybox?.cves.map((c) => c.id)).not.toContain('CVE-2016-2148');
    expect(busybox?.rejected?.map((r) => r.id)).toContain('CVE-2016-2148');
  });
});
