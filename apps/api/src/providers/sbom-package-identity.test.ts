/** The actual runSbom JSON mapping feeds normalizeSbom; no fixture of a persisted result can prove that boundary. */
import { parseVendorVex } from '@firmlab/core';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { normalizeSbom } from '../findings-normalize.js';
import type { JobHandle } from './jobs.js';
import { grypeMatchVulnerability, runSbom } from './sbom.js';

const { child, toolAvailable } = vi.hoisted(() => ({ child: vi.fn(), toolAvailable: vi.fn() }));
vi.mock('node:child_process', async (original) => ({
  ...(await original<typeof import('node:child_process')>()),
  execFile: child,
}));
vi.mock('../tools.js', async (original) => ({
  ...(await original<typeof import('../tools.js')>()),
  isToolAvailable: toolAvailable,
}));

const cve = 'CVE-2099-1234';
const handle: JobHandle = { id: 'identity-test', log: () => {} };
const db = JSON.stringify({ valid: true, schemaVersion: '6', built: '2026-11-08T00:00:00Z' });
type Callback = (err: Error | null, out: { stdout: string; stderr: string }) => void;

function scan(artifact: { name: string; version: string; purl?: unknown }) {
  child.mockImplementation((file: string, args: string[], _opts: unknown, cb: Callback) => {
    const stdout =
      file === 'syft'
        ? JSON.stringify({ artifacts: [{ ...artifact, type: 'npm' }] })
        : args[0] === 'db'
          ? db
          : JSON.stringify({ matches: [{ vulnerability: { id: cve, severity: 'High' }, artifact }] });
    cb(null, { stdout, stderr: '' });
  });
}

function vex(product: string, status: string) {
  const parsed = parseVendorVex(
    JSON.stringify({
      '@context': 'https://openvex.dev/ns/v0.2.0',
      '@id': 'https://vendor.example/vex/1',
      author: 'Vendor',
      timestamp: '2026-11-08T00:00:00Z',
      version: 1,
      statements: [{ vulnerability: { name: cve }, products: [product], status }],
    }),
    '/etc/vendor.openvex.json',
  );
  if (!parsed.ok) throw new Error(parsed.reason);
  return { documents: [parsed] };
}

beforeEach(() => {
  child.mockReset();
  toolAvailable.mockReset().mockResolvedValue(true);
});

describe('Grype artifact identity through parser and normalizer', () => {
  it.each([
    ['unscoped npm', 'busybox', 'pkg:npm/busybox@1.20', 'pkg:npm/busybox@1.20', true],
    ['scoped npm', '@acme/busybox', 'pkg:npm/%40acme/busybox@1.20', 'pkg:npm/%40acme/busybox@1.20', true],
    ['PyPI', 'Friendly_Bard', 'pkg:pypi/friendly-bard@1.20', 'pkg:pypi/FRIENDLY.bard@1.20', true],
    ['different ecosystem', 'busybox', 'pkg:npm/busybox@1.20', 'pkg:pypi/busybox@1.20', false],
    ['different scope', '@acme/busybox', 'pkg:npm/%40acme/busybox@1.20', 'pkg:npm/%40other/busybox@1.20', false],
    ['different version', 'busybox', 'pkg:npm/busybox@1.20', 'pkg:npm/busybox@1.21', false],
    ['missing assertion version', 'busybox', 'pkg:npm/busybox@1.20', 'pkg:npm/busybox', false],
    ['conflicting artifact name', 'busybox', 'pkg:npm/another@1.20', 'pkg:npm/another@1.20', false],
    ['conflicting artifact version', 'busybox', 'pkg:npm/busybox@1.21', 'pkg:npm/busybox@1.21', false],
    ['malformed artifact', 'busybox', 'pkg:npm/busy%zzbox@1.20', 'busybox', false],
    ['malformed assertion', 'busybox', 'pkg:npm/busybox@1.20', 'pkg:npm/busybox@1.20?x=%zz', false],
    ['plain cannot broaden npm', 'busybox', 'pkg:npm/busybox@1.20', 'busybox', false],
    ['CPE cannot broaden npm', 'busybox', 'pkg:npm/busybox@1.20', 'cpe:2.3:a:busybox:busybox:1.20:*', false],
    ['distro cannot broaden npm', 'busybox', 'pkg:npm/busybox@1.20', 'pkg:deb/debian/busybox@1.20', false],
    ['distro cannot broaden PyPI', 'busybox', 'pkg:pypi/busybox@1.20', 'pkg:apk/alpine/busybox@1.20', false],
    ['plain cannot broaden PyPI', 'busybox', 'pkg:pypi/busybox@1.20', 'busybox', false],
    ['CPE cannot broaden PyPI', 'busybox', 'pkg:pypi/busybox@1.20', 'cpe:/a:busybox:busybox:1.20', false],
  ])(
    '%s: annotation only, with identical rows/proof/severity/channel',
    async (_label, name, purl, product, matches) => {
      scan({ name, version: '1.20', purl });
      const result = await runSbom('fixture', '/synthetic-rootfs', handle);
      expect(result.grypeOutcome).toBe('matched');
      expect(result.vulnerabilities[0]?.packagePurl).toBe(purl);
      expect(result.vulnerabilityTotal).toBe(1);
      expect(result.counts.High).toBe(1);
      expect(child.mock.calls.map(([file, args]) => [file, args[0]])).toEqual([
        ['syft', 'scan'],
        ['grype', 'db'],
        ['grype', 'dir:/synthetic-rootfs'],
      ]);
      for (const status of ['fixed', 'not_affected', 'affected', 'under_investigation']) {
        const without = normalizeSbom(result);
        // Persisted identity survives a JSON round trip, exactly as an old/new job result does.
        const rows = normalizeSbom(JSON.parse(JSON.stringify(result)), undefined, vex(product, status));
        expect(rows).toHaveLength(1);
        expect(rows.map(({ rationale: _rationale, evidence: _evidence, ...row }) => row)).toEqual(
          without.map(({ rationale: _rationale, evidence: _evidence, ...row }) => row),
        );
        expect(rows[0]).toMatchObject({
          kind: 'cve',
          severity: 'high',
          proofState: 'needs_runtime_reproduction',
          evidenceChannel: 'external_advisory',
        });
        expect(rows[0]?.evidence?.packagePurl).toBe(purl);
        expect(rows[0]?.evidence?.vendorVex).toEqual(
          matches
            ? expect.objectContaining({
                basis: 'vendor_assertion',
                verdict: status === 'under_investigation' ? 'vendor_under_investigation' : `vendor_states_${status}`,
              })
            : undefined,
        );
        if (!matches) expect(rows).toEqual(without);
      }
    },
  );

  it.each([undefined, ''])('keeps legacy behavior when Grype supplies no identity (%j)', async (purl) => {
    scan({ name: 'busybox', version: '1.20', ...(purl !== undefined ? { purl } : {}) });
    const result = await runSbom('fixture', '/synthetic-rootfs', handle);
    expect(result.vulnerabilities[0]).not.toHaveProperty('packagePurl');
    for (const product of ['busybox', 'pkg:apk/alpine/busybox@1.20', 'cpe:/a:busybox:busybox:1.20']) {
      expect(normalizeSbom(result, undefined, vex(product, 'fixed'))[0]?.evidence?.vendorVex).toBeDefined();
    }
    expect(normalizeSbom(result, undefined, vex('pkg:npm/busybox@1.20', 'fixed'))).toEqual(normalizeSbom(result));
  });

  it.each([null, 42, {}, ['pkg:npm/busybox@1.20']])(
    'retains invalid non-string purls as a refusal (%j)',
    async (purl) => {
      scan({ name: 'busybox', version: '1.20', purl });
      const result = await runSbom('fixture', '/synthetic-rootfs', handle);
      expect(result.vulnerabilities[0]?.packagePurl).toBeNull();
      expect(normalizeSbom(result, undefined, vex('busybox', 'fixed'))).toEqual(normalizeSbom(result));
    },
  );

  it('exports a pure Grype mapper and retains raw malformed identity for fail-closed matching', () => {
    expect(grypeMatchVulnerability({ artifact: { name: 'x', version: '1', purl: 'pkg:npm/x@%zz' } })).toEqual({
      id: '?',
      severity: 'Unknown',
      packageName: 'x',
      packageVersion: '1',
      packagePurl: 'pkg:npm/x@%zz',
      fixedIn: null,
    });
  });
});
