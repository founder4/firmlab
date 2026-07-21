import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { buildFccLinks, extractFccIds, fccFindings, isPlausibleFccId, runFccLookup } from './fcc.js';

describe('extractFccIds', () => {
  it('extracts only the real labeled IDs and ignores non-IDs', () => {
    const strings = ['FCC ID: 2AABC-XYZ123', 'FCCID:XYZ-ABC', 'FCC part 15', '1234567'];
    expect(extractFccIds(strings)).toEqual(['2AABC-XYZ123', 'XYZ-ABC']);
  });

  it('upper-cases and dedupes, preserving insertion order', () => {
    const strings = ['fcc id: 2xyz-abc', 'FCC ID: 2XYZ-ABC', 'FCCID: node1-a'];
    expect(extractFccIds(strings)).toEqual(['2XYZ-ABC', 'NODE1-A']);
  });

  it('accepts a strict upper-case token adjacent to a bare FCC, but not prose', () => {
    expect(extractFccIds(['Certified FCC A3LSMG970 device'])).toEqual(['A3LSMG970']);
    expect(extractFccIds(['see FCC part 15 subpart b'])).toEqual([]);
  });

  it('returns nothing for strings with no FCC ID', () => {
    expect(extractFccIds(['just some firmware bytes', 'v1.2.3', ''])).toEqual([]);
  });
});

describe('isPlausibleFccId', () => {
  it('accepts real FCC-ID shapes', () => {
    expect(isPlausibleFccId('2AABC-XYZ123')).toBe(true);
    expect(isPlausibleFccId('XYZ-ABC')).toBe(true);
    expect(isPlausibleFccId('A3LSMG970')).toBe(true);
  });

  it('rejects all-digit tokens, too-short and too-long strings', () => {
    expect(isPlausibleFccId('1234567')).toBe(false); // no grantee letter
    expect(isPlausibleFccId('AB')).toBe(false); // too short
    expect(isPlausibleFccId(`A${'B'.repeat(25)}`)).toBe(false); // too long
  });
});

describe('buildFccLinks', () => {
  it('returns the fccid.io mirror and the FCC OET search, both carrying the ID', () => {
    const links = buildFccLinks('2AABC-XYZ123');
    expect(links.fccid).toBe('https://fccid.io/2AABC-XYZ123');
    expect(links.fccReport).toBe('https://www.fcc.gov/oet/ea/fccid?fccid=2AABC-XYZ123');
    expect(links.fccid).toContain('2AABC-XYZ123');
    expect(links.fccReport).toContain('2AABC-XYZ123');
  });
});

describe('fccFindings', () => {
  it('emits one info/static_confirmed finding per id', () => {
    const findings = fccFindings(['2AABC-XYZ123', 'XYZ-ABC']);
    expect(findings).toHaveLength(2);
    for (const f of findings) {
      expect(f.kind).toBe('fcc-id');
      expect(f.severity).toBe('info');
      expect(f.proofState).toBe('static_confirmed');
    }
    expect(findings[0]?.title).toContain('2AABC-XYZ123');
    expect((findings[0]?.evidence as { id: string }).id).toBe('2AABC-XYZ123');
    expect((findings[0]?.evidence as { links: { fccid: string } }).links.fccid).toContain('2AABC-XYZ123');
  });
});

describe('runFccLookup', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-fcc-'));
  afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));

  it('is available with no ids when the firmware has no FCC ID', () => {
    const file = path.join(dir, 'no-id.bin');
    fs.writeFileSync(file, 'nothing to see here, just some firmware bytes\0\0v1.0.0');
    const res = runFccLookup(file, null);
    expect(res.available).toBe(true);
    expect(res.ids).toEqual([]);
    expect(res.links).toEqual([]);
    expect(res.findings).toEqual([]);
    expect(res.reason).toMatch(/no fcc id/i);
  });

  it('extracts an FCC ID present in the raw image bytes and builds links + findings', () => {
    const file = path.join(dir, 'with-id.bin');
    fs.writeFileSync(file, Buffer.from('\x00\x00label FCC ID: 2AABC-XYZ123 end\x00\x00', 'latin1'));
    const res = runFccLookup(file, null);
    expect(res.available).toBe(true);
    expect(res.ids).toEqual(['2AABC-XYZ123']);
    expect(res.links[0]?.fccid).toBe('https://fccid.io/2AABC-XYZ123');
    expect(res.findings).toHaveLength(1);
    expect(res.findings[0]?.proofState).toBe('static_confirmed');
  });

  it('also gathers strings from the cached static analysis (secrets + signatures)', () => {
    const file = path.join(dir, 'empty.bin');
    fs.writeFileSync(file, '');
    const analysisJson = JSON.stringify({
      secrets: [{ offset: 0, value: 'contact label FCC ID: XYZ-ABC printed on case' }],
      signatures: [
        { offset: 0, id: 's', description: 'FCCID:2AABC-XYZ123 sticker', category: 'other', confidence: 'low' },
      ],
    });
    const res = runFccLookup(file, analysisJson);
    expect(res.ids).toEqual(['XYZ-ABC', '2AABC-XYZ123']);
  });
});
