/**
 * What a vendor-VEX search covered, as a compact value that can be persisted on a result whether or not any finding
 * came out of it.
 *
 * The verdicts `vendor-vex-discover.ts` produces ride ON finding rows, so an image with zero CVE rows, or whose rows
 * no document mentions, kept no trace that a search ever happened: the SBOM route, the W9 SBOM step and research all
 * discovered, normalised, and then returned a result without the discovery. "No vendor statement attached" then read
 * the same as "nobody looked". This module is the one projection those callers persist, so all three say the same
 * thing about the same search.
 *
 * Three states, never conflated:
 *
 *  - `attempted: true` — a search ran. The discovery's coverage is spread in (so a coverage field added later
 *    survives without touching this file), plus per-document summaries and the refusals. An attempted search that
 *    found nothing is still a record of what was walked, capped and refused.
 *  - `attempted: false` — this run positively did not search, and `notAttemptedReason` says why (no rootfs; research
 *    had no kernel answer to correlate). That is a gap, not a negative.
 *  - field absent — a result written before this existed. "Not recorded", never "not attempted" and never zero.
 *
 * Pure: no store, no filesystem. The document summary drops only the statements themselves (the verdicts already
 * ride on the rows); every other document field is kept by spread, so omission counters a parser adds later reach
 * the persisted summary. Such fields must stay bounded in core, because this projection does not cap them again.
 */
import type { VendorVexDocument } from '@firmlab/core';
import type {
  VendorVexDiscovery,
  VendorVexDiscoveryCoverage,
  VendorVexDiscoveryRefusal,
} from './vendor-vex-discover.js';

export type VendorVexDocumentSummary = Omit<VendorVexDocument, 'ok' | 'sourcePath' | 'statements'> & {
  path: string;
  /** Statements kept by the parser (after its own caps, which the document's dropped counters report). */
  statements: number;
};

export type VendorVexSearchSummary =
  | (VendorVexDiscoveryCoverage & {
      attempted: true;
      documents: VendorVexDocumentSummary[];
      refusals: VendorVexDiscoveryRefusal[];
    })
  | {
      attempted: false;
      notAttemptedReason: string;
    };

export function summarizeVendorVexDocument(doc: VendorVexDocument): VendorVexDocumentSummary {
  const { ok: _ok, sourcePath, statements, ...rest } = doc;
  return { ...rest, path: sourcePath, statements: statements.length };
}

/** The persisted record of one search that ran, including one that found no document at all. */
export function summarizeVendorVexSearch(discovery: VendorVexDiscovery): VendorVexSearchSummary {
  return {
    ...discovery.coverage,
    attempted: true,
    documents: discovery.documents.map(summarizeVendorVexDocument),
    refusals: [...discovery.refusals],
  };
}

/** The persisted record of a run that positively did not search, and why. */
export function vendorVexNotAttempted(reason: string): VendorVexSearchSummary {
  return { attempted: false, notAttemptedReason: reason };
}
