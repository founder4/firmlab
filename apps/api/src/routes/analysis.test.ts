import type { Finding } from '@firmlab/core';
import Fastify from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  getImage: vi.fn(),
  listFindings: vi.fn(),
  listImages: vi.fn(),
  listJobs: vi.fn(),
  rowToFinding: vi.fn(),
  updateImageAnalysis: vi.fn(),
}));

vi.mock('../analysis.js', () => ({ analyzeImageBuffer: vi.fn() }));
vi.mock('../findings.js', () => ({ rowToFinding: mocks.rowToFinding }));
vi.mock('../store.js', () => ({
  getImage: mocks.getImage,
  listFindings: mocks.listFindings,
  listImages: mocks.listImages,
  listJobs: mocks.listJobs,
  updateImageAnalysis: mocks.updateImageAnalysis,
}));

import { analysisRoutes } from './analysis.js';

const finding: Finding = {
  id: 'finding-1',
  imageId: 'image-1',
  source: 'kernel',
  kind: 'kernel-cve-candidate',
  title: 'CVE-2026-43286 — Linux kernel 6.18',
  severity: 'high',
  proofState: 'needs_runtime_reproduction',
  evidence: { id: 'CVE-2026-43286' },
  createdAt: 1,
};

function backportEvidence() {
  return {
    cveId: 'CVE-2026-43286',
    artifactBinding: 'unverified',
    repoPath: '/srv/linux',
    repoHead: 'a'.repeat(40),
    shallow: false,
    filesExamined: ['mm/hugetlb.c'],
    commitsExamined: 1,
    matches: [],
    coverage: 'complete',
    limits: { maxCommits: 1, timeoutMs: 1000, maxPatchBytes: 65_536 },
    reason: 'source evidence only',
  };
}

describe('analysis findings backport enrichment', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getImage.mockReturnValue({ id: 'image-1' });
    mocks.listFindings.mockReturnValue([{ id: 'row-1' }]);
    mocks.rowToFinding.mockReturnValue(finding);
    mocks.listImages.mockReturnValue([]);
  });

  async function getFindings() {
    const app = Fastify();
    await app.register(analysisRoutes, { prefix: '/api' });
    const response = await app.inject({ method: 'GET', url: '/api/images/image-1/findings' });
    await app.close();
    return response;
  }

  it('attaches the latest durable source-tree evidence without promoting proof state', async () => {
    mocks.listJobs.mockReturnValue([
      { kind: 'kernel-backport', status: 'done', resultJson: JSON.stringify(backportEvidence()) },
    ]);
    const response = await getFindings();
    expect(response.statusCode).toBe(200);
    expect(response.json().findings[0]).toMatchObject({
      proofState: 'needs_runtime_reproduction',
      evidence: {
        id: 'CVE-2026-43286',
        backportEvidence: { cveId: 'CVE-2026-43286', artifactBinding: 'unverified' },
      },
    });
  });

  it('returns the original findings when a persisted result is malformed', async () => {
    mocks.listJobs.mockReturnValue([{ kind: 'kernel-backport', status: 'done', resultJson: '{broken' }]);
    const response = await getFindings();
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ findings: [finding] });
  });
});
