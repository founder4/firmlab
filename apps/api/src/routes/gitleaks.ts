/**
 * Deep secret-scan intake. POST runs gitleaks over the latest extracted rootfs as a job; GET returns the most
 * recent completed result. Like SBOM and emulation, this depends on a prior successful extraction for a rootfs.
 */
import type { FastifyInstance } from 'fastify';
import type { ExtractResult } from '../providers/extract.js';
import { type GitleaksResult, runGitleaks } from '../providers/gitleaks.js';
import { startJob } from '../providers/jobs.js';
import { getImage, listJobs } from '../store.js';

/** Find the most recent successful extraction's rootfs path for an image, if any. */
function latestRootfs(imageId: string): string | null {
  const done = listJobs(imageId).find((j) => j.kind === 'extract' && j.status === 'done' && j.resultJson);
  if (!done?.resultJson) return null;
  return (JSON.parse(done.resultJson) as ExtractResult).rootfsPath;
}

function latestGitleaks(imageId: string): GitleaksResult | null {
  const done = listJobs(imageId).find((j) => j.kind === 'gitleaks' && j.status === 'done' && j.resultJson);
  if (!done?.resultJson) return null;
  return JSON.parse(done.resultJson) as GitleaksResult;
}

export async function gitleaksRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/gitleaks', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const rootfsPath = latestRootfs(id);
    if (!rootfsPath) {
      return reply.status(400).send({ error: 'Run extraction first — the deep scan needs an extracted rootfs' });
    }
    const jobId = startJob(id, 'gitleaks', {}, (handle) => runGitleaks(rootfsPath, handle));
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/gitleaks', async (req) => {
    const { id } = req.params as { id: string };
    return { result: latestGitleaks(id) };
  });
}
