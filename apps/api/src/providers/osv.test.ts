import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it, vi } from 'vitest';
import type { ResearchConfig } from '../research/config.js';
import { buildOsvQuery, osvCacheKey, osvEcosystem, parseOsvResponse, queryOsv } from './osv.js';

describe('osvEcosystem', () => {
  it('maps syft package types to OSV ecosystems', () => {
    expect(osvEcosystem('deb')).toBe('Debian');
    expect(osvEcosystem('apk')).toBe('Alpine');
    expect(osvEcosystem('python')).toBe('PyPI');
    expect(osvEcosystem('npm')).toBe('npm');
  });
  it('returns null for unmapped types (honest: not queryable)', () => {
    expect(osvEcosystem('binary')).toBeNull();
    expect(osvEcosystem('unknown')).toBeNull();
  });
});

describe('buildOsvQuery', () => {
  it('builds the /v1/query package+version body', () => {
    expect(buildOsvQuery('busybox', '1.35.0', 'Debian')).toEqual({
      package: { name: 'busybox', ecosystem: 'Debian' },
      version: '1.35.0',
    });
  });
});

describe('osvCacheKey', () => {
  it('is the question, so the same component asked twice is asked of OSV once', () => {
    expect(osvCacheKey('busybox', '1.01', 'Debian')).toBe(osvCacheKey('busybox', '1.01', 'Debian'));
    expect(osvCacheKey('busybox', '1.01', 'Debian')).toContain('busybox');
  });

  it('separates a different version, name or ecosystem — never reuses the answer to another question', () => {
    const key = osvCacheKey('busybox', '1.01', 'Debian');
    expect(osvCacheKey('busybox', '1.02', 'Debian')).not.toBe(key);
    expect(osvCacheKey('busybox', '1.01', 'Alpine')).not.toBe(key);
    expect(osvCacheKey('dropbear', '1.01', 'Debian')).not.toBe(key);
  });
});

describe('parseOsvResponse', () => {
  it('extracts id, aliases, summary, severity and references', () => {
    const adv = parseOsvResponse({
      vulns: [
        {
          id: 'DSA-1234',
          aliases: ['CVE-2023-1111'],
          summary: 'heap overflow in busybox',
          database_specific: { severity: 'HIGH' },
          references: [{ url: 'https://example.org/adv' }, { type: 'WEB' }],
        },
      ],
    });
    expect(adv).toHaveLength(1);
    expect(adv[0]?.id).toBe('DSA-1234');
    expect(adv[0]?.aliases).toEqual(['CVE-2023-1111']);
    expect(adv[0]?.severity).toBe('HIGH');
    expect(adv[0]?.references).toEqual(['https://example.org/adv']);
  });

  it('falls back to CVSS score for severity and details for summary', () => {
    const adv = parseOsvResponse({
      vulns: [{ id: 'X', details: 'long details', severity: [{ type: 'CVSS_V3', score: '9.8' }] }],
    });
    expect(adv[0]?.severity).toBe('9.8');
    expect(adv[0]?.summary).toBe('long details');
  });

  it('an empty/absent vulns list is no advisories, never an error', () => {
    expect(parseOsvResponse({})).toEqual([]);
    expect(parseOsvResponse({ vulns: [] })).toEqual([]);
  });
});

/**
 * The wiring, exercised end to end with a stubbed global fetch — no socket is ever opened, and a second call that
 * reached the stub would fail the test. This is the part unit-testing the pure pieces cannot cover: that the
 * provider actually READS the cache before asking, WRITES what it got, and refuses to store a failure.
 */
describe('queryOsv reads through the cache', () => {
  const HOUR = 60 * 60 * 1000;
  const T0 = 1_700_000_000_000;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'firmlab-osv-cache-'));
  const cfg: ResearchConfig = { allowlist: ['api.osv.dev'], timeoutMs: 1000, hashLookup: false };
  afterAll(() => {
    vi.unstubAllGlobals();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('asks OSV once, then answers the same question from disk with the age of the answer', async () => {
    let calls = 0;
    vi.stubGlobal('fetch', async () => {
      calls += 1;
      return new Response(
        JSON.stringify({ vulns: [{ id: 'CVE-2021-44228', database_specific: { severity: 'HIGH' } }] }),
      );
    });
    const component = { name: 'log4j-core', version: '2.14.1', type: 'java-archive' };

    const first = await queryOsv(component, cfg, { dir, ttlMs: 24 * HOUR, now: T0 });
    expect(calls).toBe(1);
    expect(first.advisories[0]?.id).toBe('CVE-2021-44228');
    expect(first.freshness).toEqual({ origin: 'network', fetchedAt: new Date(T0).toISOString(), ageMs: 0 });

    const second = await queryOsv(component, cfg, { dir, ttlMs: 24 * HOUR, now: T0 + 2 * HOUR });
    expect(calls).toBe(1);
    expect(second.advisories[0]?.severity).toBe('HIGH');
    expect(second.freshness).toEqual({ origin: 'cache', fetchedAt: new Date(T0).toISOString(), ageMs: 2 * HOUR });
  });

  it('re-asks past the TTL instead of serving an advisory list that may have moved on', async () => {
    let calls = 0;
    vi.stubGlobal('fetch', async () => {
      calls += 1;
      return new Response(JSON.stringify({ vulns: [{ id: `OSV-${calls}` }] }));
    });
    const component = { name: 'busybox', version: '1.01', type: 'deb' };
    await queryOsv(component, cfg, { dir, ttlMs: HOUR, now: T0 });
    const later = await queryOsv(component, cfg, { dir, ttlMs: HOUR, now: T0 + 50 * HOUR });
    expect(calls).toBe(2);
    expect(later.advisories[0]?.id).toBe('OSV-2');
    expect(later.freshness?.origin).toBe('network');
  });

  it('does not cache an HTTP error — a bad afternoon at OSV must not become a durable "no advisories"', async () => {
    let calls = 0;
    vi.stubGlobal('fetch', async () => {
      calls += 1;
      return new Response('nope', { status: 503 });
    });
    const component = { name: 'dropbear', version: '2012.55', type: 'deb' };
    const failed = await queryOsv(component, cfg, { dir, now: T0 });
    expect(failed.queryable).toBe(true);
    expect(failed.advisories).toEqual([]);
    expect(failed.freshness).toBeNull();
    await queryOsv(component, cfg, { dir, now: T0 });
    expect(calls).toBe(2);
  });

  it('never touches the network or the cache for a component OSV cannot map', async () => {
    vi.stubGlobal('fetch', async () => {
      throw new Error('an unmapped component must not reach the network');
    });
    const r = await queryOsv({ name: 'vendor-httpd', version: '1.0', type: 'binary' }, cfg, { dir, now: T0 });
    expect(r.queryable).toBe(false);
    expect(r.freshness).toBeNull();
  });
});
