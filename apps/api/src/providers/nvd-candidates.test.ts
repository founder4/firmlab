import { describe, expect, it } from 'vitest';
import { mergeNvdCandidates } from '../providers/nvd.js';

/**
 * The wiring this pins is the one the WR940N exposed: syft catalogues ONE package on that image while it ships
 * pppd 2.4.3, BusyBox 1.01 and Dropbear 2012.55, so the NVD keyword search — whose whole purpose is components
 * OSV cannot map — was being handed almost nothing to ask about.
 */
describe('mergeNvdCandidates — what actually leaves, counted before it leaves', () => {
  const manifest = [{ name: 'lua', version: '5.1.5' }];
  const fingerprinted = [
    { name: 'pppd', version: '2.4.3' },
    { name: 'busybox', version: '1.01' },
    { name: 'dropbear', version: '2012.55' },
  ];

  it('adds the fingerprinted components the manifest never had', () => {
    const { candidates, fingerprintedOnly } = mergeNvdCandidates(manifest, fingerprinted);
    expect(candidates).toHaveLength(4);
    expect(fingerprintedOnly).toHaveLength(3);
  });

  it('does not send a component twice because both sources found it', () => {
    const { candidates, fingerprintedOnly } = mergeNvdCandidates([{ name: 'busybox', version: '1.01' }], fingerprinted);
    expect(candidates.filter((c) => c.name === 'busybox')).toHaveLength(1);
    expect(fingerprintedOnly.map((c) => c.name)).toEqual(['pppd', 'dropbear']);
  });

  it('drops a nameless or versionless hit rather than sending a useless keyword', () => {
    const { fingerprintedOnly } = mergeNvdCandidates([], [{ name: 'ghost', version: '' }, ...fingerprinted]);
    expect(fingerprintedOnly.map((c) => c.name)).toEqual(['pppd', 'busybox', 'dropbear']);
  });

  it('is the same count the ledger promises — the merge, not the batch query, decides it', () => {
    const { candidates } = mergeNvdCandidates(manifest, [...fingerprinted, ...fingerprinted]);
    expect(candidates).toHaveLength(4);
  });
});
