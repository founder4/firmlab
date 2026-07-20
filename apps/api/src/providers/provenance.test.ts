import type { ImageIdentity } from '@firmlab/core';
import { describe, expect, it } from 'vitest';
import { buildProvenanceFingerprint } from './provenance.js';

const identity: ImageIdentity = {
  firmwareClass: 'embedded-linux',
  arch: 'mips',
  endianness: 'big',
  filesystems: ['squashfs'],
  bootloader: 'U-Boot 2016.05',
};

describe('buildProvenanceFingerprint', () => {
  it('extracts urls, domains, versions, cert CNs and banners from strings', () => {
    const fp = buildProvenanceFingerprint(
      [
        'https://www.netgear.com/support/download',
        'Firmware version 1.2.3 build 42',
        'U-Boot 2016.05 (Aug 01 2018)',
        'Subject: CN=RG-EW1200G, O=Ruijie',
        'Copyright (c) 2018 Acme Networks Inc.',
      ],
      identity,
    );
    expect(fp.urls).toContain('https://www.netgear.com/support/download');
    expect(fp.domains).toContain('www.netgear.com');
    expect(fp.versions).toContain('1.2.3');
    expect(fp.certCNs.some((c) => c.includes('RG-EW1200G'))).toBe(true);
    expect(fp.banners.some((b) => b.includes('U-Boot'))).toBe(true);
    // vendor hints come from copyright + the domain's second level
    expect(fp.vendors).toContain('netgear');
    expect(fp.vendors.some((v) => /Acme/i.test(v))).toBe(true);
  });

  it('carries the deterministic identity through', () => {
    const fp = buildProvenanceFingerprint([], identity);
    expect(fp.identity).toEqual({ firmwareClass: 'embedded-linux', arch: 'mips', bootloader: 'U-Boot 2016.05' });
  });

  it('empty strings yield empty signal lists, never a guess', () => {
    const fp = buildProvenanceFingerprint([''], identity);
    expect(fp.urls).toHaveLength(0);
    expect(fp.vendors).toHaveLength(0);
  });
});
