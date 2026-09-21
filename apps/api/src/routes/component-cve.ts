/**
 * Curated component-CVE route. The provider fingerprints bundled component versions in the latest extracted
 * rootfs and applies only its hand-verified version ranges. A missing rootfs is passed through as `null` so the
 * provider records its own honest unavailable result instead of the route inventing a negative answer.
 */
import type { FastifyInstance } from 'fastify';
import { syncFindings } from '../findings.js';
import { runComponentCve } from '../providers/component-cve.js';
import type { ExtractResult } from '../providers/extract.js';
import { startJob } from '../providers/jobs.js';
import { getImage, listJobs } from '../store.js';

function latestRootfs(imageId: string): string | null {
  const done = listJobs(imageId).find((job) => job.kind === 'extract' && job.status === 'done' && job.resultJson);
  if (!done?.resultJson) return null;
  try {
    return (JSON.parse(done.resultJson) as ExtractResult).rootfsPath ?? null;
  } catch {
    return null;
  }
}

export async function componentCveRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/component-cve', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });

    const rootfsPath = latestRootfs(id);
    const jobId = startJob(id, 'component-cve', {}, async () => {
      const result = runComponentCve(rootfsPath);
      syncFindings(id, 'component-cve', result.findings);
      return result;
    });
    return reply.status(202).send({ jobId });
  });
}
