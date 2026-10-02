import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { type VendorVexDocument, parseVendorVex } from '@firmlab/core';
import { afterEach, describe, expect, it } from 'vitest';
import {
  discoverVendorVex,
  isVexCandidatePath,
  linuxKernelProductMatcher,
  packageProductMatcher,
  productIdentityRefusal,
  selectVexCandidates,
  vendorVexVerdictFor,
} from './vendor-vex-discover.js';

/** An OpenVEX document with the given statements. */
function openvex(statements: { cve: string; products: string[]; status: string; justification?: string }[]): string {
  return JSON.stringify({
    '@context': 'https://openvex.dev/ns/v0.2.0',
    '@id': 'https://vendor.example/vex/1',
    author: 'Vendor PSIRT',
    timestamp: '2026-01-01T00:00:00Z',
    version: 1,
    statements: statements.map((s) => ({
      vulnerability: { name: s.cve },
      products: s.products,
      status: s.status,
      ...(s.justification ? { justification: s.justification } : {}),
    })),
  });
}

function doc(text: string, sourcePath = '/etc/vex/a.openvex.json'): VendorVexDocument {
  const parsed = parseVendorVex(text, sourcePath);
  if (!parsed.ok) throw new Error(`fixture refused: ${parsed.reason}`);
  return parsed;
}

const dirs: string[] = [];
function rootfs(files: Record<string, string | Uint8Array>): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vex-rootfs-'));
  dirs.push(root);
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content);
  }
  return root;
}
afterEach(() => {
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});

describe('isVexCandidatePath — the stated rule', () => {
  it.each([
    ['/usr/share/doc/kernel.openvex.json', true],
    ['/etc/busybox.vex.json', true],
    ['/etc/csaf-2026-001.json', true],
    ['/etc/vendor_CSAF.json', true],
    ['/usr/share/vex/advisory.json', true],
    ['/opt/csaf/2026/one.json', true],
    ['/etc/config.json', false],
    ['/etc/vex/readme.txt', false],
    ['/etc/kernel.openvex.json.bak', false],
    ['/etc/vexfile', false],
  ])('%s → %s', (p, expected) => {
    expect(isVexCandidatePath(p)).toBe(expected);
  });

  it('sorts candidates by path and states what the file cap dropped', () => {
    const r = selectVexCandidates(['/z/c.vex.json', '/a/b.vex.json', '/etc/x.json', '/m/a.vex.json'], 2);
    expect(r).toEqual({ selected: ['/a/b.vex.json', '/m/a.vex.json'], found: 3, dropped: 1 });
  });
});

describe('discoverVendorVex', () => {
  it('reads candidates, keeps refusals with their reason, and leaves other json alone', () => {
    const root = rootfs({
      'usr/share/vex/kernel.openvex.json': openvex([
        { cve: 'CVE-2022-0847', products: ['linux-kernel'], status: 'fixed' },
      ]),
      'etc/vex/notes.json': JSON.stringify({ hello: 'world' }),
      'etc/broken.vex.json': '{ not json',
      'etc/config.json': openvex([{ cve: 'CVE-2022-0847', products: ['linux-kernel'], status: 'affected' }]),
    });
    const r = discoverVendorVex(root);
    expect(r.documents.map((d) => d.sourcePath)).toEqual(['/usr/share/vex/kernel.openvex.json']);
    expect(r.refusals.map((x) => [x.path, x.reason])).toEqual([
      ['/etc/broken.vex.json', 'malformed_json'],
      ['/etc/vex/notes.json', 'non_vex_json'],
    ]);
    expect(r.coverage).toMatchObject({ candidatesFound: 3, examined: 3, parsed: 1, refused: 2, droppedByFileCap: 0 });
    expect(r.coverage.statement).toMatch(/assertion, not a code fact/);
  });

  it('never follows a symbolic link: a linked candidate is refused by name and a linked directory is not walked', () => {
    const outside = rootfs({
      'secret/host.vex.json': openvex([{ cve: 'CVE-2022-0847', products: ['linux-kernel'], status: 'fixed' }]),
    });
    const root = rootfs({ 'etc/placeholder': 'x' });
    fs.symlinkSync(path.join(outside, 'secret/host.vex.json'), path.join(root, 'etc/linked.vex.json'));
    fs.symlinkSync(path.join(outside, 'secret'), path.join(root, 'etc/vex'));
    const r = discoverVendorVex(root);
    expect(r.documents).toEqual([]);
    expect(r.refusals).toEqual([
      expect.objectContaining({ path: '/etc/linked.vex.json', reason: 'symlink_not_followed' }),
    ]);
    expect(r.coverage.symlinksSkipped).toBe(2);
  });

  it('caps files (sorted path order), total bytes and per-document bytes, counting every drop', () => {
    const text = openvex([{ cve: 'CVE-2022-0847', products: ['linux-kernel'], status: 'fixed' }]);
    const root = rootfs({
      'a/1.vex.json': text,
      'a/2.vex.json': text,
      'a/3.vex.json': text,
      'a/4.vex.json': text,
      'b/huge.vex.json': `${text}${' '.repeat(4096)}`,
    });
    const files = discoverVendorVex(root, { maxFiles: 2 });
    expect(files.documents.map((d) => d.sourcePath)).toEqual(['/a/1.vex.json', '/a/2.vex.json']);
    expect(files.coverage.droppedByFileCap).toBe(3);
    expect(files.coverage.statement).toMatch(
      /3 candidate\(s\) beyond the 2-file cap were not read \(sorted path order\)/,
    );

    const bytes = discoverVendorVex(root, { maxTotalBytes: text.length * 2 + 1, maxDocumentBytes: 1024 });
    expect(bytes.documents).toHaveLength(2);
    expect(bytes.coverage.droppedByByteCap).toBe(2);
    expect(bytes.refusals).toEqual([
      expect.objectContaining({ path: '/b/huge.vex.json', reason: 'oversized_document' }),
    ]);
  });

  it('a walk cut by its entry cap says candidates beyond it were never seen', () => {
    const root = rootfs({ 'a/1.vex.json': 'x', 'b/2.vex.json': 'x', 'c/3.vex.json': 'x' });
    const r = discoverVendorVex(root, { maxEntries: 2 });
    expect(r.coverage.walkTruncated).toBe(true);
    expect(r.coverage.statement).toMatch(/walk stopped at 2 entries/);
  });

  it('degrades to "not searched" without a rootfs, and never throws on a missing one', () => {
    const none = discoverVendorVex(null);
    expect(none.documents).toEqual([]);
    expect(none.coverage.statement).toMatch(/No extracted rootfs was available/);
    expect(none.coverage.statement).toMatch(/not a clean result/);
    expect(() => discoverVendorVex(path.join(os.tmpdir(), 'firmlab-no-such-rootfs'))).not.toThrow();
  });
});

describe('product matchers — exact, never a substring', () => {
  const kernel = linuxKernelProductMatcher(['5.10.110', '5.10.110']);
  it.each([
    ['linux-kernel', true],
    ['LINUX-KERNEL', true],
    ['Linux Kernel', false],
    ['pkg:generic/linux', false],
    ['linux_kernel', true],
    ['pkg:generic/linux-kernel', true],
    ['pkg:generic/linux-kernel@5.10.110', true],
    ['pkg:generic/linux-kernel@4.4.0', false],
    ['cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*', true],
    ['cpe:2.3:o:linux:linux_kernel:5.10.110:*:*:*:*:*:*:*', true],
    ['cpe:2.3:o:linux:linux_kernel:4.4:*:*:*:*:*:*:*', false],
    ['cpe:/o:linux:linux_kernel', true],
    ['linux', false],
    ['kernel', false],
    ['linux-kernel-headers', false],
    ['pkg:deb/debian/linux@5.10.110', false],
    ['pkg:generic/vendor/linux-kernel', false],
    ['cpe:2.3:a:linux:linux_kernel:*', false],
  ])('kernel matcher: %s → %s', (id, expected) => {
    expect(kernel(id)).toBe(expected);
  });

  const busybox = packageProductMatcher('busybox', '1.20');
  it.each([
    ['busybox', true],
    ['pkg:apk/alpine/busybox@1.20', true],
    ['pkg:apk/alpine/busybox@1.35', false],
    ['cpe:2.3:a:busybox:busybox:1.20:*', true],
    ['busybox-extras', false],
    ['BusyBox', false],
  ])('package matcher: %s → %s', (id, expected) => {
    expect(busybox(id)).toBe(expected);
  });
});

describe('vendorVexVerdictFor', () => {
  const kernel = linuxKernelProductMatcher(['5.10']);

  it('attaches an explicit fixed statement with source, statement index and the assertion rationale', () => {
    const d = doc(openvex([{ cve: 'CVE-2022-0847', products: ['linux-kernel'], status: 'fixed' }]));
    const v = vendorVexVerdictFor({ documents: [d] }, 'CVE-2022-0847', kernel, 'the Linux kernel');
    expect(v).toMatchObject({
      verdict: 'vendor_states_fixed',
      basis: 'vendor_assertion',
      sourcePath: '/etc/vex/a.openvex.json',
      statementIndex: 0,
    });
    expect(v?.rationale).toMatch(/vendor's assertion, not a code fact; it changes neither the proof state nor/);
  });

  it('carries the justification of a not_affected statement', () => {
    const d = doc(
      openvex([
        {
          cve: 'CVE-2022-0847',
          products: ['linux-kernel'],
          status: 'not_affected',
          justification: 'vulnerable_code_not_present',
        },
      ]),
    );
    const v = vendorVexVerdictFor({ documents: [d] }, 'CVE-2022-0847', kernel, 'the Linux kernel');
    expect(v).toMatchObject({ verdict: 'vendor_states_not_affected', justification: 'vulnerable_code_not_present' });
  });

  it('attaches nothing when the CVE is unmentioned, the product does not match, or there are no documents', () => {
    const d = doc(openvex([{ cve: 'CVE-2022-0847', products: ['linux'], status: 'fixed' }]));
    expect(vendorVexVerdictFor({ documents: [d] }, 'CVE-2022-0847', kernel, 'k')).toBeNull();
    expect(vendorVexVerdictFor({ documents: [d] }, 'CVE-2016-5195', kernel, 'k')).toBeNull();
    expect(vendorVexVerdictFor({ documents: [] }, 'CVE-2022-0847', kernel, 'k')).toBeNull();
    expect(vendorVexVerdictFor(null, 'CVE-2022-0847', kernel, 'k')).toBeNull();
    expect(vendorVexVerdictFor(undefined, 'GHSA-xxxx-yyyy-zzzz', kernel, 'k')).toBeNull();
  });

  it('is conflicting when one document disagrees with itself', () => {
    const d = doc(
      openvex([
        { cve: 'CVE-2022-0847', products: ['linux-kernel'], status: 'fixed' },
        { cve: 'CVE-2022-0847', products: ['pkg:generic/linux-kernel'], status: 'affected' },
      ]),
    );
    const v = vendorVexVerdictFor({ documents: [d] }, 'CVE-2022-0847', kernel, 'the Linux kernel');
    expect(v?.verdict).toBe('conflicting');
    expect(v?.sources.map((s) => s.status)).toEqual(['fixed', 'affected']);
    expect(v?.rationale).toMatch(/not resolved by order/);
  });

  it('is conflicting when two documents disagree, and agreeing documents are listed together', () => {
    const fixed = doc(openvex([{ cve: 'CVE-2022-0847', products: ['linux-kernel'], status: 'fixed' }]), '/a.vex.json');
    const fixed2 = doc(openvex([{ cve: 'CVE-2022-0847', products: ['linux_kernel'], status: 'fixed' }]), '/b.vex.json');
    const notAffected = doc(
      openvex([{ cve: 'CVE-2022-0847', products: ['linux-kernel'], status: 'not_affected' }]),
      '/c.vex.json',
    );
    const conflict = vendorVexVerdictFor({ documents: [fixed, notAffected] }, 'CVE-2022-0847', kernel, 'k');
    expect(conflict?.verdict).toBe('conflicting');
    expect(conflict?.sources.map((s) => s.sourcePath)).toEqual(['/a.vex.json', '/c.vex.json']);
    const agree = vendorVexVerdictFor({ documents: [fixed, fixed2] }, 'CVE-2022-0847', kernel, 'k');
    expect(agree?.verdict).toBe('vendor_states_fixed');
    expect(agree?.sources.map((s) => s.sourcePath)).toEqual(['/a.vex.json', '/b.vex.json']);
  });
});

/** A CSAF VEX document with one product and one vulnerability. */
function csafVex(product: Record<string, unknown>, cve: string, productStatus: Record<string, string[]>): string {
  return JSON.stringify({
    document: { category: 'csaf_vex', publisher: { name: 'Vendor PSIRT' } },
    product_tree: { full_product_names: [product] },
    vulnerabilities: [{ cve, product_status: productStatus }],
  });
}

describe('no firmware-controlled string throws at match time', () => {
  it.each([
    ['kernel', 'pkg:generic/linux-kernel@5.10%', 'CVE-2021-22555'],
    ['package', 'pkg:generic/busy%zzbox', 'CVE-2022-48174'],
  ])('a malformed purl escape (%s) is unmatchable, recorded, and other statements still resolve', (_, bad, cve) => {
    const kernelRow = cve === 'CVE-2021-22555';
    const good = kernelRow ? 'linux-kernel' : 'busybox';
    const d = doc(
      openvex([
        { cve, products: [bad], status: 'affected' },
        { cve, products: [good], status: 'fixed' },
      ]),
    );
    const matcher = kernelRow ? linuxKernelProductMatcher(['5.10']) : packageProductMatcher('busybox', '1.36.1');
    expect(() => matcher(bad)).not.toThrow();
    expect(matcher(bad)).toBe(false);
    expect(productIdentityRefusal(bad)).toMatch(/malformed percent-escape/);
    const v = vendorVexVerdictFor({ documents: [d] }, cve, matcher, good);
    expect(v?.verdict).toBe('vendor_states_fixed');
    expect(v?.omissions).toEqual([{ sourcePath: '/etc/vex/a.openvex.json', reason: 'unmatchable_identity', count: 1 }]);
    expect(v?.rationale).toMatch(/Not a complete reading: .*could not be read/);
  });

  it('a malformed escape alone attaches nothing, and discovery counts it with its reason', () => {
    const root = rootfs({
      'etc/vex/a.openvex.json': openvex([
        { cve: 'CVE-2022-48174', products: ['pkg:generic/busy%zzbox'], status: 'fixed' },
      ]),
    });
    const r = discoverVendorVex(root);
    expect(r.coverage.unmatchableIdentities).toBe(1);
    expect(r.coverage.unmatchableIdentityExamples).toEqual([
      expect.objectContaining({
        sourcePath: '/etc/vex/a.openvex.json',
        statementIndex: 0,
        identity: 'pkg:generic/busy%zzbox',
      }),
    ]);
    expect(r.coverage.statement).toMatch(/1 product identit\(ies\) in parsed documents could not be read/);
    expect(vendorVexVerdictFor(r, 'CVE-2022-48174', packageProductMatcher('busybox', '1.36.1'), 'busybox')).toBeNull();
  });

  it('a caller predicate that throws matches nothing instead of failing the row', () => {
    const d = doc(openvex([{ cve: 'CVE-2022-48174', products: ['busybox'], status: 'fixed' }]));
    const throwing = () => {
      throw new Error('boom');
    };
    expect(vendorVexVerdictFor({ documents: [d] }, 'CVE-2022-48174', throwing, 'busybox')).toBeNull();
  });
});

describe('CSAF version scope survives into the row verdict', () => {
  const busybox130 = csafVex(
    { product_id: 'P1', name: 'busybox', product_identification_helper: { purl: 'pkg:generic/busybox@1.30.1' } },
    'CVE-2022-48174',
    { fixed: ['P1'] },
  );
  const kernel44 = csafVex(
    {
      product_id: 'K',
      name: 'linux-kernel',
      product_identification_helper: { cpe: 'cpe:2.3:o:linux:linux_kernel:4.4.0:*:*:*:*:*:*:*' },
    },
    'CVE-2021-22555',
    { known_not_affected: ['K'] },
  );

  it('a fixed statement scoped to busybox 1.30.1 does not attach to a busybox 1.36.1 row, and does to 1.30.1', () => {
    const docs = { documents: [doc(busybox130, '/etc/csaf.json')] };
    expect(
      vendorVexVerdictFor(docs, 'CVE-2022-48174', packageProductMatcher('busybox', '1.36.1'), 'busybox'),
    ).toBeNull();
    expect(
      vendorVexVerdictFor(docs, 'CVE-2022-48174', packageProductMatcher('busybox', '1.30.1'), 'busybox')?.verdict,
    ).toBe('vendor_states_fixed');
  });

  it('a known_not_affected scoped to kernel 4.4.0 does not attach to 5.10.0, and does to 4.4.0', () => {
    const docs = { documents: [doc(kernel44, '/etc/csaf.json')] };
    expect(vendorVexVerdictFor(docs, 'CVE-2021-22555', linuxKernelProductMatcher(['5.10.0']), 'k')).toBeNull();
    expect(vendorVexVerdictFor(docs, 'CVE-2021-22555', linuxKernelProductMatcher(['4.4.0']), 'k')?.verdict).toBe(
      'vendor_states_not_affected',
    );
  });
});

describe('a row verdict says what may be missing from it', () => {
  it('names a statement cap that dropped anything, so a clean single verdict is not read as complete', () => {
    const text = openvex([
      { cve: 'CVE-2022-48174', products: ['busybox'], status: 'not_affected' },
      { cve: 'CVE-2021-0001', products: ['x'], status: 'fixed' },
      { cve: 'CVE-2022-48174', products: ['busybox'], status: 'affected' },
    ]);
    const capped = parseVendorVex(text, '/etc/vex/a.openvex.json', { maxStatements: 2 });
    if (!capped.ok) throw new Error('fixture refused');
    const v = vendorVexVerdictFor(
      { documents: [capped] },
      'CVE-2022-48174',
      packageProductMatcher('busybox', '1.36.1'),
      'busybox',
    );
    expect(v?.verdict).toBe('vendor_states_not_affected');
    expect(v?.omissions).toEqual([{ sourcePath: '/etc/vex/a.openvex.json', reason: 'statement_cap', count: 1 }]);
    expect(v?.rationale).toMatch(/Not a complete reading: \/etc\/vex\/a\.openvex\.json has 1 statement\(s\) dropped/);

    const whole = vendorVexVerdictFor(
      { documents: [doc(text)] },
      'CVE-2022-48174',
      packageProductMatcher('busybox', '1.36.1'),
      'busybox',
    );
    expect(whole?.verdict).toBe('conflicting');
    expect(whole?.omissions).toBeUndefined();
  });

  it('names a statement on this CVE whose status is not a VEX status, and stays silent about other CVEs', () => {
    const d = doc(
      openvex([
        { cve: 'CVE-2022-48174', products: ['busybox'], status: 'not_affected' },
        { cve: 'CVE-2022-48174', products: ['busybox'], status: 'known_affected' },
        { cve: 'CVE-2021-0001', products: ['busybox'], status: 'fixed' },
      ]),
    );
    const m = packageProductMatcher('busybox', '1.36.1');
    const v = vendorVexVerdictFor({ documents: [d] }, 'CVE-2022-48174', m, 'busybox');
    expect(v?.verdict).toBe('vendor_states_not_affected');
    expect(v?.omissions).toEqual([{ sourcePath: '/etc/vex/a.openvex.json', reason: 'unrecognised_status', count: 1 }]);
    expect(v?.rationale).toMatch(/status that is not a VEX status/);
    expect(vendorVexVerdictFor({ documents: [d] }, 'CVE-2021-0001', m, 'busybox')?.omissions).toBeUndefined();
  });
});

describe('the package matcher respects ecosystem and vendor', () => {
  const busybox = packageProductMatcher('busybox', '1.36.1');
  it.each([
    ['pkg:npm/busybox@1.36.1', false],
    ['pkg:pypi/someone/busybox', false],
    ['pkg:generic/acme/busybox@1.36.1', false],
    ['cpe:2.3:h:acme:busybox:-:*:*:*:*:*:*:*', false],
    ['cpe:2.3:a:acme:busybox:1.36.1:*:*:*:*:*:*:*', false],
    ['cpe:2.3:o:busybox:busybox:1.36.1:*:*:*:*:*:*:*', false],
    ['cpe:2.3:a:*:busybox:1.36.1:*:*:*:*:*:*:*', false],
    ['pkg:generic/busybox@1.36.1', true],
    ['pkg:deb/debian/busybox@1.36.1', true],
    ['pkg:opkg/openwrt/busybox', true],
    ['cpe:2.3:a:busybox:busybox:1.36.1:*:*:*:*:*:*:*', true],
    ['cpe:/a:busybox:busybox:1.36.1', true],
  ])('busybox 1.36.1 row: %s → %s', (id, expected) => {
    expect(busybox(id)).toBe(expected);
  });

  it('accepts the measured NVD identity of a component whose vendor is not its name', () => {
    const dropbear = packageProductMatcher('dropbear', '2020.81');
    expect(dropbear('cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:2020.81:*:*:*:*:*:*:*')).toBe(true);
    expect(dropbear('cpe:2.3:a:acme:dropbear:2020.81:*:*:*:*:*:*:*')).toBe(false);
  });
});

describe('discovery counts what it could not list', () => {
  const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
  it.skipIf(isRoot)('an unreadable directory is counted and named in coverage, never skipped silently', () => {
    const root = rootfs({
      'etc/vex/a.openvex.json': openvex([{ cve: 'CVE-2022-0847', products: ['linux-kernel'], status: 'fixed' }]),
      'opt/vendor/vex/z.openvex.json': openvex([
        { cve: 'CVE-2022-0847', products: ['linux-kernel'], status: 'affected' },
      ]),
    });
    const locked = path.join(root, 'opt/vendor');
    fs.chmodSync(locked, 0o000);
    try {
      const r = discoverVendorVex(root);
      expect(r.documents.map((d) => d.sourcePath)).toEqual(['/etc/vex/a.openvex.json']);
      expect(r.coverage.unreadableDirectories).toBe(1);
      expect(r.coverage.unreadableDirectoryPaths).toEqual(['/opt/vendor']);
      expect(r.coverage.statement).toMatch(/1 director\(ies\) could not be listed \(\/opt\/vendor\)/);
    } finally {
      fs.chmodSync(locked, 0o755);
    }
  });

  it('a readable tree reports zero unreadable directories', () => {
    const root = rootfs({ 'etc/vex/a.openvex.json': openvex([]) });
    expect(discoverVendorVex(root).coverage).toMatchObject({ unreadableDirectories: 0, unreadableDirectoryPaths: [] });
  });
});
