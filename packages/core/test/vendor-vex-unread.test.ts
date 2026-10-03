import { describe, expect, it } from 'vitest';
import {
  MAX_CSAF_TREE_DEPTH,
  MAX_UNREAD_STRUCTURE_EXAMPLES,
  type VendorVexDocument,
  isVendorVexDocument,
  parseVendorVex,
} from '../src/vendor-vex.js';

function csaf(productTree: unknown, status: Record<string, string[]>, cve = 'CVE-2023-0001'): string {
  return JSON.stringify({
    document: { category: 'csaf_vex', csaf_version: '2.0', publisher: { name: 'Vendor' }, tracking: { id: 'T-1' } },
    product_tree: productTree,
    vulnerabilities: [{ cve, product_status: status }],
  });
}

function parsed(text: string): VendorVexDocument {
  const doc = parseVendorVex(text, '/etc/vex/a.json');
  if (!isVendorVexDocument(doc)) throw new Error(`expected a document, got ${JSON.stringify(doc)}`);
  return doc;
}

describe('CSAF product ids defined outside full_product_names', () => {
  const branchTree = {
    branches: [
      {
        category: 'vendor',
        name: 'Vendor',
        branches: [
          {
            category: 'product_version',
            name: '1.30.1',
            product: {
              product_id: 'BB-1301',
              name: 'busybox 1.30.1',
              product_identification_helper: { purl: 'pkg:generic/busybox@1.30.1' },
            },
          },
        ],
      },
    ],
  };

  it('counts a reference to a branch-only product and never matches it by its raw id', () => {
    const doc = parsed(csaf(branchTree, { fixed: ['BB-1301'] }));
    expect(doc.statements).toEqual([]);
    expect(doc.unreadStructureCount).toBe(1);
    expect(doc.unreadStructureExamples).toEqual([
      { vulnerabilityId: 'CVE-2023-0001', kind: 'csaf_unindexed_product', reference: 'BB-1301' },
    ]);
    expect(doc.unreadStructureRule).toMatch(/never matched by its raw id/);
  });

  it('does not let a raw id that looks like a component bypass a versioned branch helper', () => {
    const tree = {
      branches: [
        {
          name: 'v',
          product: { product_id: 'busybox', product_identification_helper: { purl: 'pkg:generic/busybox@1.30.1' } },
        },
      ],
    };
    const doc = parsed(csaf(tree, { known_not_affected: ['busybox'] }));
    expect(doc.statements.flatMap((s) => s.products)).not.toContain('busybox');
    expect(doc.unreadStructureCount).toBe(1);
  });

  it('counts relationship full_product_name references the same way', () => {
    const tree = {
      full_product_names: [{ product_id: 'FW-1', name: 'gateway firmware 2.0' }],
      relationships: [
        {
          category: 'default_component_of',
          product_reference: 'BB-1301',
          relates_to_product_reference: 'FW-1',
          full_product_name: { product_id: 'BB-1301:FW-1', name: 'busybox in gateway firmware 2.0' },
        },
      ],
    };
    const doc = parsed(csaf(tree, { known_affected: ['BB-1301:FW-1', 'FW-1'] }));
    expect(doc.statements).toHaveLength(1);
    expect(doc.statements[0]?.products).toEqual(['FW-1', 'gateway firmware 2.0']);
    expect(doc.unreadStructureExamples?.[0]).toMatchObject({
      kind: 'csaf_unindexed_product',
      reference: 'BB-1301:FW-1',
    });
  });

  it('a full_product_names definition still wins over a duplicate id elsewhere', () => {
    const tree = {
      full_product_names: [
        { product_id: 'P', name: 'dropbear', product_identification_helper: { purl: 'pkg:generic/dropbear@2020.81' } },
      ],
      branches: [{ name: 'x', product: { product_id: 'P', name: 'dropbear other' } }],
    };
    const doc = parsed(csaf(tree, { fixed: ['P'] }));
    expect(doc.statements[0]?.products).toEqual(['pkg:generic/dropbear@2020.81']);
    expect(doc.unreadStructureCount).toBe(0);
  });

  it('keeps the existing raw-id fallback for an id defined nowhere', () => {
    const doc = parsed(csaf({ full_product_names: [] }, { fixed: ['pkg:generic/zlib@1.2.11'] }));
    expect(doc.statements[0]?.products).toEqual(['pkg:generic/zlib@1.2.11']);
    expect(doc.unreadStructureCount).toBe(0);
  });

  it('bounds the walk: past the depth cap unresolved references are counted, not matched', () => {
    let node: Record<string, unknown> = { name: 'leaf', product: { product_id: 'DEEP' } };
    for (let i = 0; i < MAX_CSAF_TREE_DEPTH + 5; i++) node = { name: `b${i}`, branches: [node] };
    const doc = parsed(csaf({ branches: [node] }, { fixed: ['DEEP', 'pkg:generic/zlib@1.2.11'] }));
    expect(doc.statements).toEqual([]);
    expect(doc.unreadStructureExamples?.map((e) => e.kind)).toEqual([
      'csaf_product_tree_truncated',
      'csaf_product_tree_truncated',
    ]);
  });

  it('malformed trees neither throw nor manufacture matches', () => {
    for (const tree of [
      null,
      'x',
      { branches: 'x' },
      { branches: [null, 1, { branches: null }] },
      { relationships: [null, {}] },
    ]) {
      const doc = parsed(csaf(tree, { fixed: ['A'] }));
      expect(doc.statements[0]?.products).toEqual(['A']);
      expect(doc.unreadStructureCount).toBe(0);
    }
  });

  it('keeps the count exact while bounding examples', () => {
    const ids = Array.from({ length: MAX_UNREAD_STRUCTURE_EXAMPLES + 4 }, (_, i) => `B-${i}`);
    const tree = { branches: ids.map((id) => ({ name: id, product: { product_id: id } })) };
    const doc = parsed(csaf(tree, { fixed: ids }));
    expect(doc.unreadStructureCount).toBe(ids.length);
    expect(doc.unreadStructureExamples).toHaveLength(MAX_UNREAD_STRUCTURE_EXAMPLES);
  });
});

describe('OpenVEX product identifiers and nested subcomponents', () => {
  const openvex = (products: unknown, subcomponents?: unknown) =>
    JSON.stringify({
      '@context': 'https://openvex.dev/ns/v0.2.0',
      '@id': 'https://example.invalid/vex',
      author: 'Vendor',
      timestamp: '2026-01-01T00:00:00Z',
      version: 1,
      statements: [
        {
          vulnerability: { name: 'CVE-2024-0002' },
          products,
          ...(subcomponents ? { subcomponents } : {}),
          status: 'fixed',
        },
      ],
    });

  it('reads the @id, counts identifiers and nested subcomponents it does not interpret', () => {
    const doc = parsed(
      openvex([
        {
          '@id': 'pkg:generic/gateway@2.0',
          identifiers: { purl: 'pkg:deb/vendor/gateway@2.0' },
          subcomponents: [{ '@id': 'pkg:generic/busybox@1.30.1' }],
        },
      ]),
    );
    expect(doc.statements[0]?.products).toEqual(['pkg:generic/gateway@2.0']);
    expect(doc.unreadStructureExamples).toEqual([
      { vulnerabilityId: 'CVE-2024-0002', kind: 'openvex_product_identifiers', reference: 'pkg:generic/gateway@2.0' },
      { vulnerabilityId: 'CVE-2024-0002', kind: 'openvex_nested_subcomponents', reference: 'pkg:generic/gateway@2.0' },
    ]);
  });

  it('an identifiers-only product contributes no match and is counted with an empty reference', () => {
    const doc = parsed(
      openvex([{ identifiers: { cpe23: 'cpe:2.3:a:busybox:busybox:1.30.1:*:*:*:*:*:*:*' } }, 'busybox']),
    );
    expect(doc.statements[0]?.products).toEqual(['busybox']);
    expect(doc.unreadStructureExamples).toEqual([
      { vulnerabilityId: 'CVE-2024-0002', kind: 'openvex_product_identifiers', reference: '' },
    ]);
  });

  it('statement-level subcomponents stay read, and empty structures count nothing', () => {
    const doc = parsed(openvex([{ '@id': 'a', identifiers: {}, subcomponents: [] }], [{ '@id': 'b' }]));
    expect(doc.statements[0]?.products).toEqual(['a', 'b']);
    expect(doc.unreadStructureCount).toBe(0);
  });
});
