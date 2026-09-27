import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { NVD_MAX_ADVISORIES, NVD_MAX_PAGES } from '@firmlab/core';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { queryNvdBatch } from './nvd.js';

const tempDirs: string[] = [];

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe('queryNvdBatch pagination', () => {
  const cfg = {
    allowlist: ['services.nvd.nist.gov'],
    timeoutMs: 1_000,
    hashLookup: false,
  };

  function cacheOptions() {
    const dir = mkdtempSync(join(tmpdir(), 'firmlab-nvd-pages-'));
    tempDirs.push(dir);
    return { dir, now: 1_000, ttlMs: 60_000 };
  }

  function payload(start: number, count: number, totalResults: number) {
    return {
      totalResults,
      vulnerabilities: Array.from({ length: count }, (_, i) => ({
        cve: { id: `CVE-2026-${String(start + i).padStart(4, '0')}` },
      })),
    };
  }

  it('retrieves successive offsets, rate-limits network pages, and reuses every page from cache', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(1_000);
    const requestTimes: number[] = [];
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      requestTimes.push(Date.now());
      const start = Number(new URL(String(input)).searchParams.get('startIndex') ?? 0);
      const count = start === 0 ? 50 : 5;
      return new Response(JSON.stringify(payload(start, count, 55)), { status: 200 });
    });
    vi.stubGlobal('fetch', fetchMock);
    const cache = cacheOptions();

    const firstPromise = queryNvdBatch([{ name: 'linux-kernel', version: '6.1' }], cfg, {
      delayMs: 100,
      cache,
    });
    await vi.runAllTimersAsync();
    const first = await firstPromise;
    expect(requestTimes).toEqual([1_000, 1_100]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(first.components[0]?.advisories).toHaveLength(55);
    expect(first.components[0]?.pageCoverage).toMatchObject({
      attemptedOffsets: [0, 50],
      completedOffsets: [0, 50],
      totalMatching: 55,
      complete: true,
      truncated: false,
      stopReason: 'complete',
    });
    expect(first.cache).toMatchObject({ hits: 0, misses: 2 });

    const cached = await queryNvdBatch([{ name: 'linux-kernel', version: '6.1' }], cfg, {
      delayMs: 100,
      cache,
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(cached.cache).toMatchObject({ hits: 2, misses: 0 });
    expect(cached.completed).toBe(1);
    expect(cached.incomplete).toBe(0);
  });

  it('stops at the advisory bound and reports the retained prefix rather than calling it complete', async () => {
    const urls: URL[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL | Request) => {
        const url = new URL(String(input));
        urls.push(url);
        const start = Number(url.searchParams.get('startIndex') ?? 0);
        const count = Number(url.searchParams.get('resultsPerPage'));
        return new Response(JSON.stringify(payload(start, count, 120)), { status: 200 });
      }),
    );

    const result = await queryNvdBatch([{ name: 'linux-kernel', version: '6.1' }], cfg, {
      delayMs: 0,
      cache: cacheOptions(),
      maxPages: 4,
      maxAdvisories: 70,
    });
    expect(urls.map((url) => url.searchParams.get('startIndex'))).toEqual([null, '50']);
    expect(urls.map((url) => url.searchParams.get('resultsPerPage'))).toEqual(['50', '20']);
    expect(result.totalAdvisories).toBe(70);
    expect(result.pageCoverage?.[0]).toMatchObject({
      attemptedOffsets: [0, 50],
      completedOffsets: [0, 50],
      totalMatching: 120,
      complete: false,
      truncated: true,
      stopReason: 'advisory-cap',
    });
    expect(result.truncated).toEqual([{ name: 'linux-kernel', version: '6.1', shown: 70, total: 120 }]);
    expect(result.completed).toBe(0);
    expect(result.incomplete).toBe(1);
  });

  it('measures and reports entries returned beyond the requested page bound', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL | Request) => {
        const url = new URL(String(input));
        const requested = Number(url.searchParams.get('resultsPerPage'));
        return new Response(JSON.stringify(payload(0, requested + 2, 60)), { status: 200 });
      }),
    );

    const result = await queryNvdBatch([{ name: 'linux-kernel', version: '6.1' }], cfg, {
      delayMs: 0,
      cache: cacheOptions(),
    });

    expect(result.components[0]?.advisories).toHaveLength(50);
    expect(result.pageCoverage?.[0]).toMatchObject({
      totalMatching: 60,
      complete: false,
      truncated: true,
      stopReason: 'oversized-page',
      droppedByPageBounds: 2,
    });
    expect(result.truncated).toEqual([{ name: 'linux-kernel', version: '6.1', shown: 50, total: 60 }]);
  });

  it('enforces the production page ceiling even when the batch requests more pages and advisories', async () => {
    const starts: (string | null)[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL | Request) => {
        const url = new URL(String(input));
        const start = Number(url.searchParams.get('startIndex') ?? 0);
        starts.push(url.searchParams.get('startIndex'));
        return new Response(JSON.stringify(payload(start, 50, 300)), { status: 200 });
      }),
    );

    const result = await queryNvdBatch([{ name: 'linux-kernel', version: '6.1' }], cfg, {
      delayMs: 0,
      cache: cacheOptions(),
      maxPages: 999,
      maxAdvisories: 999_999,
    });

    expect(starts).toEqual([null, '50', '100', '150']);
    expect(result.components[0]?.advisories).toHaveLength(NVD_MAX_ADVISORIES);
    expect(result.pageCoverage?.[0]).toMatchObject({
      maxPages: NVD_MAX_PAGES,
      maxAdvisories: NVD_MAX_ADVISORIES,
      complete: false,
      truncated: true,
      stopReason: 'page-cap',
    });
    expect(result.incomplete).toBe(1);
  });

  it('keeps completed pages but marks a later-page failure as partial', async () => {
    let calls = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        calls += 1;
        return calls === 1
          ? new Response(JSON.stringify(payload(0, 50, 60)), { status: 200 })
          : new Response(null, { status: 503 });
      }),
    );

    const result = await queryNvdBatch([{ name: 'linux-kernel', version: '6.1' }], cfg, {
      delayMs: 0,
      cache: cacheOptions(),
    });
    expect(result.components[0]?.advisories).toHaveLength(50);
    expect(result.pageCoverage?.[0]).toMatchObject({
      attemptedOffsets: [0, 50],
      completedOffsets: [0],
      totalMatching: 60,
      complete: false,
      truncated: true,
      stopReason: 'request-failed',
    });
    expect(result.truncated).toEqual([{ name: 'linux-kernel', version: '6.1', shown: 50, total: 60 }]);
  });

  it('does not call pages with changing NVD totals a complete set', async () => {
    let calls = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: string | URL | Request) => {
        const start = Number(new URL(String(input)).searchParams.get('startIndex') ?? 0);
        calls += 1;
        return new Response(JSON.stringify(payload(start, start === 0 ? 50 : 5, calls === 1 ? 55 : 56)), {
          status: 200,
        });
      }),
    );

    const result = await queryNvdBatch([{ name: 'linux-kernel', version: '6.1' }], cfg, {
      delayMs: 0,
      cache: cacheOptions(),
    });

    expect(result.components[0]?.advisories).toHaveLength(55);
    expect(result.pageCoverage?.[0]).toMatchObject({
      attemptedOffsets: [0, 50],
      completedOffsets: [0, 50],
      totalMatching: 55,
      complete: false,
      truncated: null,
      stopReason: 'total-changed',
    });
    expect(result.completed).toBe(0);
    expect(result.incomplete).toBe(1);
  });

  it('reports a first-page failure as unknown, not as an empty CPE answer', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(null, { status: 503 })),
    );
    const result = await queryNvdBatch([{ name: 'dropbear', version: '2012.55' }], cfg, {
      delayMs: 0,
      cache: cacheOptions(),
    });
    expect(result.components).toEqual([]);
    expect(result.uncheckedIdentities).toEqual([]);
    expect(result.truncated).toEqual([]);
    expect(result.pageCoverage?.[0]).toMatchObject({
      attemptedOffsets: [0],
      completedOffsets: [],
      totalMatching: null,
      complete: false,
      truncated: null,
      stopReason: 'request-failed',
    });
    expect(result.completed).toBe(0);
    expect(result.incomplete).toBe(1);
  });
});
