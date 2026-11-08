/**
 * Direct product aliases from pinned OpenVEX v0.2.0 Component Fields/Appendix B. These are literal
 * vendor assertions, not inferred CPE/PURL equivalence or independent claims about nested components.
 */
import { describe, expect, it } from 'vitest';
import {
  MAX_UNREAD_STRUCTURE_EXAMPLES,
  type VendorVexDocument,
  type VendorVexLimits,
  parseVendorVex,
  readOpenVexProductIdentity,
  resolveVendorVex,
} from '../src/vendor-vex.js';

const cve = 'CVE-2026-1234';
const purl = 'pkg:apk/wolfi/product@1.23.0-r1?arch=armv7';
const cpe22 = 'cpe:/a:apache:log4j:2.4';
const cpe23 = 'cpe:2.3:a:apache:log4j:2.4:*:*:*:*:*:*:*';

function text(products: unknown, status = 'fixed', extra: Record<string, unknown> = {}) {
  return JSON.stringify({
    '@context': 'https://openvex.dev/ns/v0.2.0',
    '@id': 'https://example.invalid/vex',
    author: 'Vendor',
    timestamp: '2026-01-01T00:00:00Z',
    version: 1,
    statements: [{ vulnerability: { name: cve }, products, status, ...extra }],
  });
}

function parsed(products: unknown, limits?: VendorVexLimits): VendorVexDocument {
  const result = parseVendorVex(text(products), '/openvex.json', limits);
  if (!result.ok) throw new Error(result.reason);
  return result;
}

const aliases = (document: VendorVexDocument) => document.statements.flatMap((s) => s.products);

describe('direct OpenVEX product identifier aliases', () => {
  it.each([
    ['purl', purl],
    ['cpe22', cpe22],
    ['cpe23', cpe23],
  ])('reads the official identifiers-only component shape for %s', (key, value) => {
    const document = parsed([{ identifiers: { [key]: value } }]);
    expect(aliases(document)).toEqual([value]);
    expect(document.unreadStructureCount).toBe(0);
    expect(resolveVendorVex(document, cve, value).verdict).toBe('vendor_states_fixed');
  });

  it('accepts several explicitly supplied literal aliases without equating their vocabulary or version strings', () => {
    // The spec lists all three keys in one Component. Vendor CPE release vocabulary need not equal a PURL version.
    const identifiers = { cpe23: 'cpe:2.3:a:vendor:product:release_2026:*:*:*:*:*:*:*', purl, cpe22 };
    const document = parsed([{ identifiers }]);
    expect(aliases(document)).toEqual(Object.values(identifiers));
    expect(document.unreadStructureCount).toBe(0);
    for (const value of Object.values(identifiers)) {
      expect(resolveVendorVex(document, cve, value).verdict).toBe('vendor_states_fixed');
    }
    expect(resolveVendorVex(document, cve, 'product').verdict).toBe('unmentioned');
  });

  it('deduplicates an identical @id alias without spending product budget twice', () => {
    const document = parsed([{ '@id': purl, identifiers: { purl } }], { maxProducts: 1 });
    expect(aliases(document)).toEqual([purl]);
    expect(document.droppedProductsCount).toBe(0);
    expect(document.unreadStructureCount).toBe(0);
  });

  it.each(['busybox', 'pkg:generic/busybox', 'https://example.invalid/components/busybox'])(
    'does not retain the unversioned/reference @id %s as an alias for a versioned assertion',
    (id) => {
      const document = parsed([{ '@id': id, identifiers: { purl: 'pkg:generic/busybox@1.36.1' } }]);
      // An explicit unversioned helper-looking ID remains unread; an opaque reference can accompany a valid map.
      if (id.startsWith('pkg:')) {
        expect(aliases(document)).toEqual([]);
        expect(document.unreadStructureCount).toBe(1);
      } else {
        expect(aliases(document)).toEqual(['pkg:generic/busybox@1.36.1']);
        expect(document.unreadStructureCount).toBe(0);
      }
      expect(resolveVendorVex(document, cve, 'busybox').verdict).toBe('unmentioned');
    },
  );

  it('retains a versioned @id in another explicitly supplied scheme as a literal alias', () => {
    const document = parsed([{ '@id': cpe23, identifiers: { purl } }]);
    expect(aliases(document)).toEqual([purl, cpe23]);
    expect(document.unreadStructureCount).toBe(0);
  });

  it.each([
    { '@id': 'pkg:apk/wolfi/product@1.22.0?arch=armv7', identifiers: { purl } },
    { '@id': 'pkg:apk/other/product@1.23.0-r1?arch=armv7', identifiers: { purl } },
    { '@id': purl, id: 'another-id', identifiers: { purl } },
    { '@id': 'pkg:generic/product@%zz', identifiers: { purl } },
    { '@id': null, identifiers: { purl } },
    { '@id': '', identifiers: { purl } },
    { '@id': 'cpe:/a:apache:log4j:2.3', identifiers: { cpe22 } },
  ])('refuses a conflicting or malformed explicit ID instead of choosing an alias: %j', (product) => {
    const document = parsed([product]);
    expect(aliases(document)).toEqual([]);
    expect(document.unreadStructureCount).toBe(1);
  });

  it.each([
    null,
    [],
    '',
    {},
    'busybox',
    { purl: null },
    { purl: [] },
    { purl: { id: purl } },
    { purl: '' },
    { purl: 'pkg:generic/busybox' },
    { purl: 'pkg:generic/busybox@*' },
    { purl: 'pkg:generic/busybox@%zz' },
    { purl: ` ${purl}` },
    { purl: 'pkg:generic/busybox@1?arch=x&arch=y' },
    { purl: 'pkg:generic/busybox@1#../bin' },
    { cpe23: cpe22 },
    { cpe22: cpe23 },
    { cpe23: 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*' },
    { cpe22: 'cpe:/a:apache:log4j' },
    { cpe23: 'cpe:2.3:a:apache:log4j:2.4' },
    { purl, unknown: 'other-product' },
    { PURL: purl },
    { purl, cpe23: 'broken' },
    { purl, cpe22: 'cpe:/a:apache:log4j' },
  ])('keeps the whole identity unread for an empty/malformed/unsupported identifier map: %j', (identifiers) => {
    const document = parsed([{ '@id': 'product', identifiers }]);
    expect(aliases(document)).toEqual([]);
    expect(document.unreadStructureCount).toBe(1);
    expect(document.unreadStructureExamples).toEqual([
      { vulnerabilityId: cve, kind: 'openvex_product_identifiers', reference: 'product' },
    ]);
  });

  it('preserves literal case and every PURL component through the core resolver', () => {
    const exact = 'pkg:npm/%40Acme/Tool@1.2.3?arch=arm64#dist/bin';
    const document = parsed([{ identifiers: { purl: exact } }]);
    expect(aliases(document)).toEqual([exact]);
    expect(resolveVendorVex(document, cve, exact).verdict).toBe('vendor_states_fixed');
    for (const other of [
      exact.replace('Acme', 'acme'),
      exact.replace('1.2.3', '1.2.2'),
      exact.replace('npm', 'pypi'),
      exact.replace('Acme', 'Other'),
      exact.replace('arm64', 'amd64'),
      exact.replace('#dist/bin', ''),
    ])
      expect(resolveVendorVex(document, cve, other).verdict).toBe('unmentioned');
  });

  it.each(['fixed', 'not_affected', 'affected', 'under_investigation'])(
    'retains status %s through an alias',
    (status) => {
      const document = parseVendorVex(text([{ identifiers: { purl } }], status), '/openvex.json');
      expect(resolveVendorVex(document, cve, purl).matchedStatements?.[0]?.status).toBe(status);
    },
  );

  it('does not let unread identities silently remove a possible disagreement', () => {
    const root = JSON.parse(text([{ identifiers: { purl } }], 'not_affected'));
    root.statements.push({
      vulnerability: { name: cve },
      products: [{ '@id': purl, identifiers: { purl, cpe23: 42 } }],
      status: 'affected',
    });
    const document = parseVendorVex(JSON.stringify(root), '/openvex.json');
    expect(document.ok && document.unreadStructureCount).toBe(1);
    expect(document.ok && document.statements[1]?.products).toEqual([]);
    root.statements[1].products = [{ identifiers: { purl } }];
    expect(resolveVendorVex(parseVendorVex(JSON.stringify(root), '/openvex.json'), cve, purl).verdict).toBe(
      'conflicting',
    );
  });

  it('keeps nested products contextual and counts the group without traversing deeper identities', () => {
    const document = parsed([
      { identifiers: { purl }, subcomponents: [{ identifiers: { cpe23 }, subcomponents: [{ '@id': 'busybox' }] }] },
    ]);
    expect(aliases(document)).toEqual([purl]);
    expect(document.unreadStructureCount).toBe(1);
    expect(document.unreadStructureExamples?.[0]?.kind).toBe('openvex_nested_subcomponents');
    expect(resolveVendorVex(document, cve, cpe23).verdict).toBe('unmentioned');
  });

  it('does not broaden the legacy statement-level subcomponent path to identifier maps', () => {
    const document = parseVendorVex(
      text(['parent'], 'fixed', { subcomponents: [{ '@id': 'legacy' }, { identifiers: { purl } }] }),
      '/openvex.json',
    );
    expect(document.ok && aliases(document)).toEqual(['parent', 'legacy']);
    expect(document.ok && document.unreadStructureCount).toBe(1);
  });

  it('reads the exported pure decision without mutating a product or canonicalizing an alias', () => {
    const identifiers = Object.freeze({ purl });
    const product = Object.freeze({ '@id': 'local-reference', identifiers });
    expect(readOpenVexProductIdentity(product)).toEqual({
      products: [purl],
      unread: false,
      reference: 'local-reference',
    });
    expect(product.identifiers).toBe(identifiers);
  });

  it('keeps the pinned official Go sample subcomponents contextual under their OCI parent', () => {
    // go-vex 579e3014, pkg/vex/testdata/v0.2.0.json (first product); not a new component-level claim.
    const parent = 'pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126';
    const child = 'pkg:apk/alpine/libssl3@3.0.8-r3';
    const document = parsed([
      { '@id': parent, subcomponents: [{ '@id': child }, { '@id': 'pkg:apk/alpine/libcrypto3@3.0.8-r3' }] },
    ]);
    expect(aliases(document)).toEqual([parent]);
    expect(document.unreadStructureCount).toBe(1);
    expect(resolveVendorVex(document, cve, child).verdict).toBe('unmentioned');
  });

  it('reads the current pinned spec product shape while leaving hashes and children uninterpreted', () => {
    const document = parsed([
      {
        '@id': purl,
        identifiers: { purl },
        hashes: { 'sha-256': '402fa523b96591d4450ace90e32d9f779fcfd938903e1c5bf9d3701860b8f856' },
        subcomponents: [{ '@id': 'pkg:maven/org.apache.logging.log4j/log4j-core@2.4', identifiers: { cpe22, cpe23 } }],
      },
    ]);
    expect(aliases(document)).toEqual([purl]);
    expect(document.unreadStructureCount).toBe(1);
    expect(document.unreadStructureExamples?.[0]?.kind).toBe('openvex_nested_subcomponents');
  });

  it('does not traverse a wide or deep contextual group or charge each child as a standalone omission', () => {
    let deep: unknown = { identifiers: { purl } };
    for (let i = 0; i < 64; i++) deep = { subcomponents: [deep] };
    const document = parsed([
      {
        identifiers: { purl },
        subcomponents: [deep, ...Array.from({ length: 10_001 }, () => ({ identifiers: { cpe23 } }))],
      },
    ]);
    expect(aliases(document)).toEqual([purl]);
    expect(document.unreadStructureCount).toBe(1);
  });

  it.each([null, {}, 'broken'])('counts a malformed nested group once without flattening it: %j', (subcomponents) => {
    const document = parsed([{ identifiers: { purl }, subcomponents }]);
    expect(aliases(document)).toEqual([purl]);
    expect(document.unreadStructureCount).toBe(1);
    expect(document.unreadStructureExamples?.[0]?.kind).toBe('openvex_nested_subcomponents');
  });

  it('applies the existing document byte bound before reading any direct identifiers', () => {
    const input = text([{ identifiers: { purl } }]);
    const bytes = Buffer.byteLength(input, 'utf8');
    const accepted = parseVendorVex(input, '/openvex.json', { maxDocumentBytes: bytes });
    expect(accepted.ok && accepted.statements[0]?.products).toEqual([purl]);
    expect(parseVendorVex(input, '/openvex.json', { maxDocumentBytes: bytes - 1 })).toMatchObject({
      ok: false,
      reason: 'oversized_document',
      bytesExamined: bytes,
    });
  });

  it('retains legacy @id/id-only products when no identifiers field is supplied', () => {
    expect(aliases(parsed([{ '@id': ' BusyBox ' }, { id: 'Other' }, 'plain']))).toEqual(['BusyBox', 'Other', 'plain']);
  });

  it.each([null, false, 42, '', {}, [], { hashes: { 'sha-256': 'a'.repeat(64) } }])(
    'counts a malformed or unread product node once: %j',
    (node) => {
      const document = parsed([node]);
      expect(aliases(document)).toEqual([]);
      expect(document.unreadStructureCount).toBe(1);
    },
  );

  it.each([null, {}, 'broken', []])('counts an unread product collection once: %j', (collection) => {
    expect(parsed(collection).unreadStructureCount).toBe(1);
  });

  it('counts omissions before statement/product caps and bounds examples deterministically', () => {
    const products = Array.from({ length: MAX_UNREAD_STRUCTURE_EXAMPLES + 3 }, (_, i) => ({
      '@id': `P-${i}`,
      identifiers: { purl, cpe23: false },
    }));
    const full = parsed(products);
    const capped = parsed(products, { maxStatements: 0, maxProducts: 0 });
    expect(full.unreadStructureCount).toBe(products.length);
    expect(capped.unreadStructureCount).toBe(products.length);
    expect(capped.unreadStructureExamples).toEqual(full.unreadStructureExamples);
    expect(full.unreadStructureExamples).toHaveLength(MAX_UNREAD_STRUCTURE_EXAMPLES);
    expect(full.unreadStructureExamples?.[0]?.reference).toBe('P-0');
    expect(capped.droppedStatementsCount).toBe(1);
  });

  it('uses the existing product cap for distinct aliases and preserves omissions and old optional fields in JSON', () => {
    const document = parsed([{ identifiers: { purl, cpe22, cpe23 } }, { identifiers: { unknown: 'x' } }], {
      maxProducts: 1,
    });
    expect(aliases(document)).toEqual([purl]);
    expect(document.droppedProductsCount).toBe(2);
    expect(document.unreadStructureCount).toBe(1);
    const roundtrip: VendorVexDocument = JSON.parse(JSON.stringify(document));
    expect(roundtrip).toEqual(document);
    const { unreadStructureCount: _c, unreadStructureExamples: _e, unreadStructureRule: _r, ...legacy } = document;
    const old: VendorVexDocument = JSON.parse(JSON.stringify(legacy));
    expect(old.unreadStructureCount).toBeUndefined();
    expect(resolveVendorVex(old, cve, purl).verdict).toBe('vendor_states_fixed');
  });
});
