/** Synthetic discoveries shared by the offline call-site persistence tests; no tool, store or rootfs access. */
import { parseVendorVex } from '@firmlab/core';
import type { SbomResult } from './sbom.js';
import type { VendorVexDiscovery } from './vendor-vex-discover.js';

function discovery(over: Partial<VendorVexDiscovery['coverage']> = {}): VendorVexDiscovery {
  return {
    documents: [],
    refusals: [],
    coverage: {
      rule: 'synthetic candidate rule',
      selectionRule: 'synthetic ranked selection',
      candidatesFound: 0,
      examined: 0,
      parsed: 0,
      refused: 0,
      droppedByFileCap: 0,
      droppedByByteCap: 0,
      symlinksSkipped: 0,
      entriesVisited: 5,
      walkTruncated: false,
      bytesRead: 0,
      caps: { maxFiles: 2, maxTotalBytes: 4096, maxDocumentBytes: 2048, maxEntries: 10 },
      statement: 'Synthetic search coverage, independent of CVE findings.',
      ...over,
    },
  };
}

function documentDiscovery(empty: boolean): VendorVexDiscovery {
  const doc = parseVendorVex(
    JSON.stringify({
      '@context': 'https://openvex.dev/ns/v0.2.0',
      author: 'Fixture vendor',
      statements: empty
        ? []
        : [
            {
              vulnerability: { name: 'CVE-2020-0001' },
              products: [{ '@id': 'pkg:generic/unrelated-product@9.0' }],
              status: 'fixed',
            },
          ],
    }),
    '/vendor.openvex.json',
  );
  if (!doc.ok) throw new Error(doc.message);
  return { ...discovery({ candidatesFound: 1, examined: 1, parsed: 1, bytesRead: 250 }), documents: [doc] };
}

export function vexPersistenceCases(): { name: string; discovery: VendorVexDiscovery }[] {
  return [
    { name: 'zero candidates', discovery: discovery() },
    { name: 'document with zero statements', discovery: documentDiscovery(true) },
    { name: 'no matching products', discovery: documentDiscovery(false) },
    {
      name: 'only refusals',
      discovery: {
        ...discovery({ candidatesFound: 1, examined: 1, refused: 1 }),
        refusals: [{ path: '/bad.vex.json', reason: 'malformed_json', message: 'Invalid JSON fixture.' }],
      },
    },
    { name: 'file cap', discovery: discovery({ candidatesFound: 3, droppedByFileCap: 1 }) },
    { name: 'byte cap', discovery: discovery({ candidatesFound: 2, droppedByByteCap: 2 }) },
    { name: 'walk cap', discovery: discovery({ entriesVisited: 10, walkTruncated: true }) },
    {
      name: 'unreadable directories and unmatchable identities',
      discovery: discovery({
        unreadableDirectories: 1,
        unreadableDirectoryPaths: ['/locked'],
        unmatchableIdentities: 1,
        unmatchableIdentityExamples: [
          { sourcePath: '/bad-id.vex.json', statementIndex: 0, identity: 'pkg:generic/%xx', reason: 'invalid escape' },
        ],
      }),
    },
  ];
}

export function emptySbom(over: Partial<SbomResult> = {}): SbomResult {
  return {
    available: true,
    target: '/synthetic-rootfs',
    packageCount: 0,
    packages: [],
    grypeAvailable: true,
    vulnerabilities: [],
    counts: { Critical: 0, High: 0, Medium: 0, Low: 0, Negligible: 0, Unknown: 0 },
    ...over,
  };
}
