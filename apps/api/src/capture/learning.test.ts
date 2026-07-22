import { describe, expect, it } from 'vitest';
import { type EnrichedProvenance, buildLearningSurface, familyKey, hostOf } from './learning.js';

const row = (o: Partial<EnrichedProvenance>): EnrichedProvenance => ({
  imageId: 'img',
  capturedAt: 0,
  endpoint: null,
  transport: null,
  tlsPosture: null,
  vendor: null,
  filename: 'fw.bin',
  size: 0,
  firmwareClass: null,
  ...o,
});

describe('hostOf / familyKey', () => {
  it('extracts the endpoint host', () => {
    expect(hostOf('https://cdn.acme.com/ota/fw.bin')).toBe('cdn.acme.com');
    expect(hostOf('not a url')).toBeNull();
  });
  it('keys a family by vendor, falling back to the endpoint host, then unknown', () => {
    expect(familyKey(row({ vendor: 'Tuya Smart', endpoint: 'https://x/y' }))).toBe('Tuya Smart');
    expect(familyKey(row({ vendor: null, endpoint: 'https://cdn.x/y' }))).toBe('cdn.x');
    expect(familyKey(row({ vendor: null, endpoint: null }))).toBe('unknown');
  });
});

describe('buildLearningSurface', () => {
  it('builds a per-family OTA timeline ordered oldest→newest', () => {
    const s = buildLearningSurface([
      row({ imageId: 'v2', vendor: 'Acme', capturedAt: 200, filename: 'fw-1.3.bin' }),
      row({ imageId: 'v1', vendor: 'Acme', capturedAt: 100, filename: 'fw-1.2.bin' }),
    ]);
    expect(s.families).toHaveLength(1);
    expect(s.families[0]?.captures.map((c) => c.imageId)).toEqual(['v1', 'v2']);
  });

  it('learns per-vendor priors: a vendor seen only over http ships plaintext-http', () => {
    const s = buildLearningSurface([
      row({ vendor: 'Acme', transport: 'http', endpoint: 'http://cdn.acme.com/a' }),
      row({ vendor: 'Acme', transport: 'http', endpoint: 'http://cdn.acme.com/b' }),
    ]);
    const prior = s.vendorPriors.find((p) => p.vendor === 'Acme');
    expect(prior?.ships).toBe('plaintext-http');
    expect(prior?.cdns).toEqual(['cdn.acme.com']);
    expect(prior?.captureCount).toBe(2);
  });

  it('marks a vendor mixed when it ships over both http and https', () => {
    const s = buildLearningSurface([
      row({ vendor: 'Beta', transport: 'http' }),
      row({ vendor: 'Beta', transport: 'https' }),
    ]);
    expect(s.vendorPriors.find((p) => p.vendor === 'Beta')?.ships).toBe('mixed');
  });

  it('builds a CDN→families graph', () => {
    const s = buildLearningSurface([
      row({ vendor: 'Acme', endpoint: 'https://cdn.shared.com/a' }),
      row({ vendor: 'Beta', endpoint: 'https://cdn.shared.com/b' }),
    ]);
    const edge = s.cdnGraph.find((e) => e.host === 'cdn.shared.com');
    expect(edge?.families.sort()).toEqual(['Acme', 'Beta']);
  });
});
