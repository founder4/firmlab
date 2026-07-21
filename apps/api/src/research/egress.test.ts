import { describe, expect, it } from 'vitest';
import type { ProvenanceFingerprint } from '../providers/provenance.js';
import { buildEgressLedger } from './egress.js';

const provenance: ProvenanceFingerprint = {
  identity: { firmwareClass: 'embedded-linux', arch: 'mips', bootloader: null },
  vendors: ['netgear'],
  models: [],
  versions: [],
  urls: [],
  domains: ['netgear.com'],
  certCNs: [],
  banners: [],
};

describe('buildEgressLedger', () => {
  it('declares api.osv.dev as the destination for component names+versions', () => {
    const l = buildEgressLedger(
      [
        { name: 'busybox', version: '1.35' },
        { name: 'openssl', version: '3.0.2' },
      ],
      provenance,
    );
    const osv = l.destinations.find((d) => d.host === 'api.osv.dev');
    expect(osv?.count).toBe(2);
    expect(osv?.sends).toMatch(/no bytes/i);
  });

  it('declares NVD only for the OSV-unmapped candidates, and KEV as a firmware-free download', () => {
    const l = buildEgressLedger([{ name: 'busybox', version: '1.35' }], provenance, { nvdCandidates: 3 });
    const nvd = l.destinations.find((d) => d.host === 'services.nvd.nist.gov');
    expect(nvd?.count).toBe(3);
    expect(nvd?.sends).toMatch(/no bytes/i);
    const kev = l.destinations.find((d) => d.host === 'www.cisa.gov');
    expect(kev?.count).toBe(0); // a one-way download: nothing about the firmware leaves
    expect(kev?.sends).toMatch(/nothing about your firmware/i);
  });

  it('always enumerates what is NEVER sent (bytes, secrets, keys); KEV download is the only always-on destination', () => {
    const l = buildEgressLedger([], provenance);
    // No components → no OSV/NVD egress, but KEV still downloads the public catalog (count 0, firmware-free).
    expect(l.destinations.map((d) => d.host)).toEqual(['www.cisa.gov']);
    expect(l.neverSent.join(' ')).toMatch(/firmware bytes/i);
    expect(l.neverSent.join(' ')).toMatch(/secret|key|credential/i);
  });
});
