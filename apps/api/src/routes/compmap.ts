/**
 * Component dependency-map routes. Assembles a link-dependency graph (binaries → DT_NEEDED shared libraries)
 * over the latest extracted rootfs, as a background job. radare2's rabin2 is an opt-in layer — with it absent
 * the job returns available:false honestly. The primary output is the graph; the one optional finding is an
 * INFO/static_confirmed inventory.
 */
import type { FastifyInstance } from 'fastify';
import { syncFindings } from '../findings.js';
import { runComponentMap } from '../providers/compmap.js';
import type { ExtractResult } from '../providers/extract.js';
import { startJob } from '../providers/jobs.js';
import { getImage, listJobs } from '../store.js';

function latestRootfs(imageId: string): string | null {
  const job = listJobs(imageId).find((j) => j.kind === 'extract' && j.status === 'done' && j.resultJson);
  return job?.resultJson ? ((JSON.parse(job.resultJson) as ExtractResult).rootfsPath ?? null) : null;
}

export async function compmapRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/compmap', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const rootfs = latestRootfs(id);
    if (!rootfs) {
      return reply.status(400).send({ error: 'Run extraction first — the component map needs an extracted rootfs' });
    }
    const jobId = startJob(id, 'compmap', {}, async () => {
      const result = await runComponentMap(rootfs);
      syncFindings(id, 'compmap', result.findings);
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/compmap', async (req) => {
    const { id } = req.params as { id: string };
    const done = listJobs(id).find((j) => j.kind === 'compmap' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });
}
