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

  it('always enumerates what is NEVER sent (bytes, secrets, keys)', () => {
    const l = buildEgressLedger([], provenance);
    expect(l.destinations).toHaveLength(0); // nothing to query → no destinations
    expect(l.neverSent.join(' ')).toMatch(/firmware bytes/i);
    expect(l.neverSent.join(' ')).toMatch(/secret|key|credential/i);
  });
});
