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
  opts: { nvdCandidates?: number; hashLookup?: { enabled: boolean; unsaltedCount: number } } = {},
): EgressLedger {
  const destinations: EgressLedger['destinations'] = [];
  if (components.length > 0) {
    destinations.push({
      host: 'api.osv.dev',
      sends: 'SBOM component names + versions + ecosystem (no bytes)',
      count: components.length,
    });
  }
  if (opts.nvdCandidates && opts.nvdCandidates > 0) {
    destinations.push({
      host: 'services.nvd.nist.gov',
      sends: 'component name + version as a keyword, for the components OSV could not map (no bytes)',
      count: opts.nvdCandidates,
    });
  }
  // KEV is a one-way download: the public catalog comes IN, nothing about the firmware goes OUT.
  destinations.push({
    host: 'www.cisa.gov',
    sends: 'nothing about your firmware — downloads the public KEV catalog; CVEs are cross-referenced locally',
    count: 0,
  });
  const neverSent = [
    'raw firmware bytes / the image file',
    'extracted filesystem contents',
    'secret values, private keys, recovered plaintext credentials',
    `provenance strings are used locally only (${provenance.vendors.length} vendor hints, ${provenance.domains.length} domains)`,
  ];

  // Online hash lookup (opt-in on top of the track): only UNSALTED digests leave, and only to be reversed against
  // public tables. Salted crypt hashes never leave, and a recovered plaintext stays on-box (masked in results).
  if (opts.hashLookup?.enabled) {
    if (opts.hashLookup.unsaltedCount > 0) {
      destinations.push({
        host: 'www.nitrxgen.net, weakpass.com',
        sends:
          'unsalted password hash digests (MD5/SHA1/SHA256/NTLM) for reverse-lookup — never the plaintext, ' +
          'never salted crypt hashes, never bytes',
        count: opts.hashLookup.unsaltedCount,
      });
    }
    neverSent.push('salted password hashes ($1$/$5$/$6$/bcrypt/yescrypt/DES) — a miss on them would prove nothing');
    neverSent.push('any recovered plaintext password — kept local and masked in results');
  }

  return { destinations, neverSent };
}
