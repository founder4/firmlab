/** Exact CSAF branch identities: fixtures follow CSAF 2.0 sections 3.1.2/3.1.3, never branch-label inference. */
import { describe, expect, it } from 'vitest';
import {
  MAX_CSAF_TREE_DEPTH,
  MAX_CSAF_TREE_NODES,
  type VendorVexLimits,
  parseVendorVex,
  resolveVendorVex,
} from '../src/vendor-vex.js';

const cve = 'CVE-2026-1234';
const purl = 'pkg:generic/busybox@1.30.1';
const cpe = 'cpe:2.3:a:busybox:busybox:1.30.1:*:*:*:*:*:*:*';
function product(id = 'P', helper: unknown = { purl }) {
  return { name: 'BusyBox 1.30.1', product_id: id, product_identification_helper: helper };
}
function branch(value: unknown = product()) {
  return { category: 'product_version', name: 'misleading free label 9.99', product: value };
}
function parse(tree: unknown, status: Record<string, string[]> = { fixed: ['P'] }, limits?: VendorVexLimits) {
  const doc = parseVendorVex(
    JSON.stringify({
      document: { category: 'csaf_vex', csaf_version: '2.0' },
      product_tree: tree,
      vulnerabilities: [{ cve, product_status: status }],
    }),
    '/csaf.json',
    limits,
  );
  if (!doc.ok) throw new Error(doc.reason);
  return doc;
}
function nested(depth: number, leaf = branch()): unknown {
  let node: unknown = leaf;
  for (let i = 1; i < depth; i++) node = { category: 'vendor', name: `label ${i}`, branches: [node] };
  return node;
}

describe('CSAF exact branch full product names', () => {
  it.each([purl, cpe, 'cpe:/a:busybox:busybox:1.30.1'])(
    'reads nested versioned helper %s without id/name aliases',
    (id) => {
      const helper = id.startsWith('pkg:') ? { purl: id } : { cpe: id };
      const doc = parse({ branches: [nested(3, branch(product('busybox', helper)))] }, { fixed: ['busybox'] });
      expect(doc.statements[0]?.products).toEqual([id]);
      expect(doc.unreadStructureCount).toBe(0);
      expect(resolveVendorVex(doc, cve, [id]).verdict).toBe('vendor_states_fixed');
      for (const wrong of [
        'busybox',
        'BusyBox 1.30.1',
        id.replace('1.30.1', '1.36.1'),
        id.replace('generic', 'npm'),
        id.replace('/busybox@', '/vendor/busybox@'),
      ].filter((v) => v !== id)) {
        expect(resolveVendorVex(doc, cve, [wrong]).verdict).toBe('unmentioned');
      }
    },
  );

  it('reads the explicit branch CPE from the pinned OASIS rhsa-2022_0011 example', () => {
    const id = 'cpe:/o:redhat:rhel_aus:7.6::server';
    const value = {
      name: 'Red Hat Enterprise Linux Server AUS (v. 7.6)',
      product_id: '7Server-7.6.AUS',
      product_identification_helper: { cpe: id },
    };
    const doc = parse({ branches: [nested(3, branch(value))] }, { fixed: ['7Server-7.6.AUS'] });
    expect(doc.statements[0]?.products).toEqual([id]);
    expect(doc.unreadStructureCount).toBe(0);
  });

  it('keeps both exact helpers together and does not reintroduce bare aliases', () => {
    const doc = parse({ branches: [branch(product('busybox', { purl, cpe }))] }, { fixed: ['busybox'] });
    expect(doc.statements[0]?.products).toEqual([purl, cpe]);
    expect(resolveVendorVex(doc, cve, ['busybox']).verdict).toBe('unmentioned');
  });

  it.each([
    undefined,
    {},
    { purl: 'pkg:generic/busybox' },
    { cpe: 'cpe:/a:busybox:busybox' },
    { purl: 'busybox' },
    { purl: 'pkg:generic/busybox@%zz' },
    { purl: 'pkg:generic/busybox@1?arch=%zz' },
    { purl: 'pkg:generic/busybox@1#../src' },
    { purl: 'pkg:generic/busybox@1?x=a&x=b' },
    { purl: 'pkg:generic/busybox@*' },
    { purl: 'pkg:generic/busybox@%2A' },
    { cpe: 'cpe:2.3:a:busybox:busybox:1.30.1' },
    { cpe: 'cpe:/a:busybox:busybox:1*' },
    { cpe: 'cpe:/a:busybox:busybox:%zz' },
    { purl, cpe: 'plain' },
    { purl: 42 },
  ])('refuses an unreadable/unversioned helper without plain alias fallback: %j', (helper) => {
    const value = {
      name: 'busybox',
      product_id: 'busybox',
      ...(helper === undefined ? {} : { product_identification_helper: helper }),
    };
    const doc = parse({ branches: [branch(value)] }, { fixed: ['busybox'] });
    expect(doc.statements).toEqual([]);
    expect(doc.unreadStructureCount).toBe(1);
    expect(resolveVendorVex(doc, cve, () => true).verdict).toBe('unmentioned');
  });

  it('requires an explicit full product name, never filling it from branch labels', () => {
    const doc = parse({ branches: [branch({ product_id: 'P', product_identification_helper: { purl } })] });
    expect(doc.statements).toEqual([]);
    expect(doc.unreadStructureCount).toBe(1);
  });

  it.each(['branch', 'top', 'relationship'])(
    'refuses duplicate ids against %s definitions in either order',
    (where) => {
      const other = product('P', { purl: purl.replace('1.30.1', '1.36.1') });
      for (const reverse of [false, true]) {
        const pair = reverse ? [other, product()] : [product(), other];
        const tree =
          where === 'branch'
            ? { branches: pair.map(branch) }
            : where === 'top'
              ? { full_product_names: [pair[0]], branches: [branch(pair[1])] }
              : { branches: [branch(pair[0])], relationships: [{ full_product_name: pair[1] }] };
        const doc = parse(tree);
        expect(doc.statements).toEqual([]);
        expect(doc.unreadStructureCount).toBe(1);
        expect(doc.unreadStructureExamples?.[0]?.kind).toBe('csaf_ambiguous_product');
      }
    },
  );

  it('refuses duplicate top-level ids and even repeated identical definitions', () => {
    for (const tree of [{ full_product_names: [product(), product()] }, { branches: [branch(), branch()] }]) {
      expect(parse(tree).statements).toEqual([]);
      expect(parse(tree).unreadStructureCount).toBe(1);
    }
  });

  it('keeps valid legacy top-level unversioned aliases, but refuses explicit malformed helpers', () => {
    expect(parse({ full_product_names: [{ product_id: 'P', name: 'busybox' }] }).statements[0]?.products).toEqual([
      'P',
      'busybox',
    ]);
    const doc = parse({ full_product_names: [product('P', { purl: 'busybox' })] });
    expect(doc.statements).toEqual([]);
    expect(doc.unreadStructureCount).toBe(1);
  });

  it('never interprets unknown ids or relationships as raw package identities', () => {
    const doc = parse(
      { branches: [branch()], relationships: [{ full_product_name: product('R') }] },
      { fixed: ['R', 'busybox', purl] },
    );
    expect(doc.statements).toEqual([]);
    expect(doc.unreadStructureCount).toBe(3);
  });

  it('does not infer a product from a version/range branch label', () => {
    const doc = parse({
      branches: [
        {
          category: 'product_version_range',
          name: 'busybox >=1.0',
          branches: [{ category: 'product_version', name: '1.30.1', product: { product_id: 'P', name: 'busybox' } }],
        },
      ],
    });
    expect(doc.statements).toEqual([]);
    expect(doc.unreadStructureCount).toBe(1);
  });

  it('counts each unread reference once per status group and preserves mixed readable assertions', () => {
    const doc = parse(
      { branches: [branch(), branch(product('U', {}))] },
      { fixed: ['P', 'U', 'U'], known_affected: ['U'] },
    );
    expect(doc.statements).toHaveLength(1);
    expect(doc.statements[0]?.products).toEqual([purl]);
    expect(doc.unreadStructureCount).toBe(2);
  });
});

describe('bounded deterministic CSAF tree reading', () => {
  it('accepts exactly depth 32, refuses depth 33 including previously read definitions', () => {
    expect(parse({ branches: [nested(MAX_CSAF_TREE_DEPTH)] }).statements[0]?.products).toEqual([purl]);
    const doc = parse({ full_product_names: [product()], branches: [nested(MAX_CSAF_TREE_DEPTH + 1)] });
    expect(doc.statements).toEqual([]);
    expect(doc.unreadStructureExamples?.[0]?.kind).toBe('csaf_product_tree_truncated');
  });

  it('accepts exactly 10000 nodes, refuses 10001 including ids defined before the cap', () => {
    const branches = Array.from({ length: MAX_CSAF_TREE_NODES }, (_, i) => branch(product(`P${i}`)));
    const doc = parse({ branches }, { fixed: ['P0', `P${MAX_CSAF_TREE_NODES - 1}`] });
    expect(doc.statements[0]?.products).toEqual([purl]);
    expect(doc.unreadStructureCount).toBe(0);
    branches.push(branch(product('P0', {})));
    const capped = parse({ branches }, { fixed: ['P0', 'unknown'] });
    expect(capped.statements).toEqual([]);
    expect(capped.unreadStructureCount).toBe(2);
    expect(capped.unreadStructureExamples?.every((e) => e.kind === 'csaf_product_tree_truncated')).toBe(true);
  });

  it('uses tiny tree budgets without trusting already-read ids or unknown references', () => {
    for (const limits of [{ maxCsafTreeNodes: 1 }, { maxCsafTreeDepth: 1 }]) {
      const tree = { full_product_names: [product()], branches: [nested(2)] };
      const doc = parse(tree, { fixed: ['P', 'unknown'] }, limits);
      expect(doc.statements).toEqual([]);
      expect(doc.unreadStructureCount).toBe(2);
      expect(doc.unreadStructureExamples?.map((e) => e.reference)).toEqual(['P', 'unknown']);
      expect(doc.unreadStructureExamples?.every((e) => e.kind === 'csaf_product_tree_truncated')).toBe(true);
      expect(doc.unreadStructureRule).toContain(limits.maxCsafTreeNodes ? '1 nodes' : 'depth 1,');
    }
  });

  it('cannot widen hard tree ceilings with supplied limits', () => {
    const doc = parse(
      { branches: [nested(MAX_CSAF_TREE_DEPTH + 1)] },
      { fixed: ['P'] },
      { maxCsafTreeDepth: 999, maxCsafTreeNodes: Number.POSITIVE_INFINITY },
    );
    expect(doc.statements).toEqual([]);
    expect(doc.unreadStructureRule).toContain('Effective tree limits: depth 32, 10000 nodes');
  });

  it('keeps statement/product caps and omission counting independent', () => {
    const doc = parse(
      { branches: [branch(), branch(product('U', {}))] },
      { fixed: ['P', 'U'], known_affected: ['P'] },
      { maxStatements: 1, maxProducts: 0 },
    );
    expect(doc.droppedStatementsCount).toBe(1);
    expect(doc.droppedProductsCount).toBe(1);
    expect(doc.unreadStructureCount).toBe(1);
  });
});
