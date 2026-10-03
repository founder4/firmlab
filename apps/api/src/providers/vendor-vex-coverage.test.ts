import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { summarizeVendorVexSearch, vendorVexNotAttempted } from './vendor-vex-coverage.js';
import { discoverVendorVex } from './vendor-vex-discover.js';

const dirs: string[] = [];
function rootfs(files: Record<string, string>): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vexcov-'));
  dirs.push(root);
  for (const [rel, body] of Object.entries(files)) {
    const at = path.join(root, rel);
    fs.mkdirSync(path.dirname(at), { recursive: true });
    fs.writeFileSync(at, body);
  }
  return root;
}
afterEach(() => {
  for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});

const OPENVEX = JSON.stringify({
  '@context': 'https://openvex.dev/ns/v0.2.0',
  '@id': 'https://example.invalid/vex/1',
  author: 'Vendor',
  timestamp: '2026-01-01T00:00:00Z',
  version: 1,
  statements: [
    { vulnerability: { name: 'CVE-2020-0001' }, products: [{ '@id': 'pkg:generic/busybox@1.30.1' }], status: 'fixed' },
  ],
});

describe('summarizeVendorVexSearch', () => {
  it('records an attempted search that found no document at all', () => {
    const s = summarizeVendorVexSearch(discoverVendorVex(rootfs({ 'etc/passwd': 'root:x:0:0\n' })));
    expect(s.attempted).toBe(true);
    if (!s.attempted) return;
    expect(s.candidatesFound).toBe(0);
    expect(s.documents).toEqual([]);
    expect(s.refusals).toEqual([]);
    expect(typeof s.statement).toBe('string');
    expect(s.caps.maxFiles).toBeGreaterThan(0);
  });

  it('keeps refusals and document summaries without the statements themselves', () => {
    const s = summarizeVendorVexSearch(
      discoverVendorVex(rootfs({ 'etc/vex/a.openvex.json': OPENVEX, 'etc/vex/b.openvex.json': '{not json' })),
    );
    if (!s.attempted) throw new Error('expected attempted');
    expect(s.documents).toHaveLength(1);
    expect(s.documents[0]).toMatchObject({ path: '/etc/vex/a.openvex.json', format: 'openvex', statements: 1 });
    expect(s.documents[0]).toHaveProperty('droppedStatementsCount', 0);
    expect(s.documents[0]).not.toHaveProperty('ok');
    expect(s.refusals.map((r) => r.reason)).toEqual(['malformed_json']);
    expect(JSON.parse(JSON.stringify(s))).toEqual(s);
  });

  it('carries parser omission counters into the persisted summary without listing them here', () => {
    const csaf = JSON.stringify({
      document: { category: 'csaf_vex', csaf_version: '2.0', publisher: { name: 'V' }, tracking: { id: 'T' } },
      product_tree: { branches: [{ name: 'v', product: { product_id: 'BB' } }] },
      vulnerabilities: [{ cve: 'CVE-2023-0001', product_status: { fixed: ['BB'] } }],
    });
    const s = summarizeVendorVexSearch(discoverVendorVex(rootfs({ 'etc/vex/b.csaf.json': csaf })));
    if (!s.attempted) throw new Error('expected attempted');
    expect(s.documents[0]).toMatchObject({
      statements: 0,
      unreadStructureCount: 1,
      unreadStructureExamples: [{ vulnerabilityId: 'CVE-2023-0001', kind: 'csaf_unindexed_product', reference: 'BB' }],
    });
    expect(typeof s.documents[0]?.unreadStructureRule).toBe('string');
  });

  it('a positive non-attempt is distinct from an attempted empty search', () => {
    expect(vendorVexNotAttempted('no rootfs')).toEqual({ attempted: false, notAttemptedReason: 'no rootfs' });
  });
});
