/**
 * Egress ledger (Phase 5) — the honest "what leaves this machine" record. Before any external-intelligence run,
 * FirmLab states exactly which hosts it will contact and which DERIVED data will be sent, and — just as important
 * — enumerates what is NEVER sent. This is the transparency that makes an internet-touching feature acceptable in
 * a local-only tool. Pure, so it can be shown as a preview and re-shown in the result.
 */
import type { ProvenanceFingerprint } from '../providers/provenance.js';

export interface EgressLedger {
  destinations: { host: string; sends: string; count: number }[];
  neverSent: string[];
}

/**
 * Compute the ledger for a run over these components + provenance. Only names/versions and coarse provenance hints
 * leave; raw bytes, secret values and keys never do.
 */
export function buildEgressLedger(
  components: { name: string; version: string }[],
  provenance: ProvenanceFingerprint,
): EgressLedger {
  const destinations: EgressLedger['destinations'] = [];
  if (components.length > 0) {
    destinations.push({
      host: 'api.osv.dev',
      sends: 'SBOM component names + versions + ecosystem (no bytes)',
      count: components.length,
    });
  }
  return {
    destinations,
    neverSent: [
      'raw firmware bytes / the image file',
      'extracted filesystem contents',
      'secret values, private keys, credentials',
      `provenance strings are used locally only (${provenance.vendors.length} vendor hints, ${provenance.domains.length} domains)`,
    ],
  };
}
