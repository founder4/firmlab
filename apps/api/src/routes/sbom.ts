/**
 * SBOM + CVE intake. POST runs syft (+grype) over the latest extracted rootfs as a job; GET returns the most
 * recent completed SBOM result. Like emulation, this depends on a prior successful extraction for a rootfs.
 */
import type { FastifyInstance } from 'fastify';
import type { ExtractResult } from '../providers/extract.js';
import { startJob } from '../providers/jobs.js';
import { type SbomResult, runSbom } from '../providers/sbom.js';
import { getImage, listJobs } from '../store.js';

/** Find the most recent successful extraction result for an image, if any. */
function latestRootfs(imageId: string): string | null {
  const done = listJobs(imageId).find((j) => j.kind === 'extract' && j.status === 'done' && j.resultJson);
  if (!done?.resultJson) return null;
  return (JSON.parse(done.resultJson) as ExtractResult).rootfsPath;
}

function latestSbom(imageId: string): SbomResult | null {
  const done = listJobs(imageId).find((j) => j.kind === 'sbom' && j.status === 'done' && j.resultJson);
  if (!done?.resultJson) return null;
  return JSON.parse(done.resultJson) as SbomResult;
}

export async function sbomRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/sbom', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const rootfsPath = latestRootfs(id);
    if (!rootfsPath) {
      return reply.status(400).send({ error: 'Run extraction first — SBOM scanning needs an extracted rootfs' });
    }
    const jobId = startJob(id, 'sbom', {}, (handle) => runSbom(id, rootfsPath, handle));
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/sbom', async (req) => {
    const { id } = req.params as { id: string };
    return { result: latestSbom(id) };
  });
}
