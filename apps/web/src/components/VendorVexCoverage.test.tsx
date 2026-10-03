import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import type { VendorVexSearchSummary } from '../api';
import { setLocale } from '../i18n';
import { en } from '../locales/en';
import { es } from '../locales/es';
import { VendorVexCoverage, vendorVexSearchState } from './VendorVexCoverage';

beforeEach(() => setLocale('en'));
const k = en.kernelPosture.vendorVex;
const empty: VendorVexSearchSummary = {
  attempted: true,
  candidatesFound: 0,
  examined: 0,
  parsed: 0,
  refused: 0,
  entriesVisited: 140,
  bytesRead: 0,
  documents: [],
  refusals: [],
};

describe('VendorVexCoverage', () => {
  it('shows documents, parser omissions, bounded status examples and future counters', () => {
    render(
      <VendorVexCoverage
        vex={{
          ...empty,
          candidatesFound: 1,
          examined: 1,
          parsed: 1,
          documents: [
            {
              path: 'etc/vex.json',
              format: 'openvex',
              statements: 2,
              droppedStatementsCount: 3,
              droppedProductsCount: 4,
              ignoredNonCveCount: 5,
              unrecognisedStatusCount: 6,
              futureOmissionCount: 7,
              unrecognisedStatusExamples: [{ vulnerabilityId: 'CVE-2026-1234', status: 'unknown_status' }],
              boundsRule: 'bounded parser rule',
              author: 'Synthetic vendor',
              timestamp: '2026-10-03',
            },
          ],
        }}
      />,
    );
    expect(screen.getByText(k.counts(1, 1, 1, 0))).toBeInTheDocument();
    expect(screen.getByText(k.document('etc/vex.json', 'openvex', 2))).toBeInTheDocument();
    for (const [label, n] of [
      [k.droppedStatements, 3],
      [k.droppedProducts, 4],
      [k.ignoredNonCve, 5],
      [k.unrecognisedStatus, 6],
      [k.otherCounter('futureOmissionCount'), 7],
    ]) {
      expect(screen.getByText(`${label}: ${n}`)).toBeInTheDocument();
    }
    expect(screen.getByText(/CVE-2026-1234 — unknown_status/)).toBeInTheDocument();
    expect(screen.getByText(`${k.documentBounds}: bounded parser rule`)).toBeInTheDocument();
    expect(screen.getByText(k.assertion)).toBeInTheDocument();
  });

  it('shows unread product structures with their examples and rule', () => {
    render(
      <VendorVexCoverage
        vex={{
          ...empty,
          documents: [
            {
              path: 'etc/csaf.json',
              format: 'csaf_vex',
              statements: 0,
              unreadStructureCount: 2,
              unreadStructureExamples: [
                { vulnerabilityId: 'CVE-2026-0001', kind: 'csaf_unindexed_product', reference: 'BB-1301' },
                { vulnerabilityId: 'CVE-2026-0002', kind: 'openvex_product_identifiers', reference: '' },
              ],
              unreadStructureRule: 'synthetic unread rule',
            },
          ],
        }}
      />,
    );
    expect(screen.getByText(`${k.unreadStructures}: 2`)).toBeInTheDocument();
    expect(screen.getByText('CVE-2026-0001 — csaf_unindexed_product — BB-1301')).toBeInTheDocument();
    expect(screen.getByText('CVE-2026-0002 — openvex_product_identifiers')).toBeInTheDocument();
    expect(screen.getByText(`${k.unreadStructureRule}: synthetic unread rule`)).toBeInTheDocument();
  });

  it('keeps an attempted-empty search distinct from a clean finding result', () => {
    render(<VendorVexCoverage vex={empty} />);
    expect(screen.getByText(k.counts(0, 0, 0, 0))).toBeInTheDocument();
    expect(screen.getByText(k.noneMatchedFirmware)).toBeInTheDocument();
    expect(screen.getByText(k.walk(140, 0))).toBeInTheDocument();
    expect(screen.queryByText(k.notRecorded)).toBeNull();
  });

  it('shows only-refusals even when candidate counts were not recorded', () => {
    render(
      <VendorVexCoverage
        vex={{
          attempted: true,
          refusals: [{ path: 'bad.json', reason: 'malformed_json', message: 'Synthetic parse error' }],
        }}
      />,
    );
    expect(screen.getByText('malformed_json')).toBeInTheDocument();
    expect(screen.getByText(/Synthetic parse error/)).toBeInTheDocument();
    expect(screen.getByText(k.counts(k.unknown, k.unknown, k.unknown, k.unknown))).toBeInTheDocument();
    expect(screen.queryByText(k.noneMatchedFirmware)).toBeNull();
  });

  it('records truncated walks, caps, unreadable directories and unmatchable identities', () => {
    render(
      <VendorVexCoverage
        vex={{
          ...empty,
          droppedByFileCap: 4,
          droppedByByteCap: 2,
          walkTruncated: true,
          symlinksSkipped: 1,
          caps: { maxFiles: 8, maxTotalBytes: 1000, maxDocumentBytes: 400, maxEntries: 140 },
          rule: 'candidate rule',
          selectionRule: 'rank then path',
          unreadableDirectories: 1,
          unreadableDirectoryPaths: ['private/vex'],
          unmatchableIdentities: 1,
          unmatchableIdentityExamples: [
            { sourcePath: 'vex.json', identity: 'pkg:broken/%xx', reason: 'malformed escape' },
          ],
        }}
      />,
    );
    for (const line of [
      k.droppedFiles(4, 8),
      k.droppedBytes(2),
      k.walkTruncated(140),
      k.symlinks(1),
      k.caps(8, 1000, 400, 140),
      k.unreadable(1),
      k.unmatchable(1),
    ]) {
      expect(screen.getByText(line)).toBeInTheDocument();
    }
    expect(screen.getByText('private/vex')).toBeInTheDocument();
    expect(screen.getByText(/malformed escape/)).toBeInTheDocument();
    expect(screen.getByText(`${k.selectionRule}: rank then path`)).toBeInTheDocument();
  });

  it('reports a positive not-attempted reason without counts', () => {
    render(<VendorVexCoverage vex={{ attempted: false, notAttemptedReason: 'No extracted rootfs' }} />);
    expect(screen.getByText(k.notAttempted('No extracted rootfs'))).toBeInTheDocument();
    expect(screen.queryByText(/candidate files/)).toBeNull();
  });

  it('reports legacy absence quietly, without claiming no search or zero counts', () => {
    const { container } = render(<VendorVexCoverage />);
    expect(container.textContent).toBe(k.notRecorded);
    expect(screen.queryByRole('region')).toBeNull();
  });

  it('tolerates malformed and partial nested records without inventing zeros', () => {
    const partial = {
      attempted: true,
      candidatesFound: 'bad',
      parsed: -1,
      examined: {},
      refused: Number.NaN,
      documents: [null, { path: {}, statements: [], droppedProductsCount: 'bad', unrecognisedStatusExamples: [null] }],
      refusals: [null, { reason: {} }],
      caps: 'bad',
      unreadableDirectoryPaths: {},
      unmatchableIdentityExamples: [null],
    };
    const { container } = render(<VendorVexCoverage vex={partial as unknown as VendorVexSearchSummary} />);
    expect(screen.getByText(k.counts(k.unknown, k.unknown, k.unknown, k.unknown))).toBeInTheDocument();
    expect(container.textContent).not.toMatch(/undefined|NaN|\[object Object\]|0 statements/);
    expect(screen.queryByText(k.nothingRead)).toBeNull();
  });

  it.each([null, [], 'bad', {}, { attempted: 'false' }])(
    'classifies malformed attempt markers as unknown: %j',
    (value) => {
      expect(vendorVexSearchState(value)).toBe('not-recorded');
      const { container } = render(<VendorVexCoverage vex={value as VendorVexSearchSummary} />);
      expect(container.textContent).toBe(k.notRecorded);
    },
  );

  it('localises coverage in Spanish without translating provider evidence', () => {
    setLocale('es');
    render(<VendorVexCoverage vex={{ ...empty, statement: 'Synthetic provider evidence' }} />);
    expect(screen.getByText(es.kernelPosture.vendorVex.heading)).toBeInTheDocument();
    expect(screen.getByText(es.kernelPosture.vendorVex.noneMatchedFirmware)).toBeInTheDocument();
    expect(screen.getByText('Synthetic provider evidence')).toBeInTheDocument();
  });
});
