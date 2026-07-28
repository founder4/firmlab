/**
 * Kernel-posture routes — the security properties of the kernel the rest of the analysis runs on top of. POST starts
 * a job that locates the kernel (shipped config → module set → carved blob → raw image), answers the posture
 * questions in three states, and syncs its findings under the stable `kernel` source; GET returns the latest
 * completed result.
 *
 * Unlike the rootfs-bound stages, this route does NOT refuse a request when extraction has not run: the raw image
 * alone frequently carries a kernel banner, and a rootfs-less answer (version known, posture undetermined and
 * saying so) is strictly more information than a 400. When the rootfs IS available the provider gets it, because
 * `lib/modules/<version>/` and the shipped module signatures are the strongest evidence a firmware offers.
 */
import type { FastifyInstance } from 'fastify';
import { syncFindings } from '../findings.js';
import type { ExtractResult } from '../providers/extract.js';
import { startJob } from '../providers/jobs.js';
import { runKernelPosture } from '../providers/kernelposture.js';
import { getImage, listJobs } from '../store.js';

/** The latest extraction's rootfs and output dir, when one has run — both optional inputs to the provider. */
function latestExtraction(imageId: string): { rootfsPath: string | null; outputDir: string | null } {
  const job = listJobs(imageId).find((j) => j.kind === 'extract' && j.status === 'done' && j.resultJson);
  if (!job?.resultJson) return { rootfsPath: null, outputDir: null };
  const r = JSON.parse(job.resultJson) as ExtractResult;
  return { rootfsPath: r.rootfsPath ?? null, outputDir: r.outputDir ?? null };
}

export async function kernelRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/kernel', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = getImage(id);
    if (!row) return reply.status(404).send({ error: 'Image not found' });
    const { rootfsPath, outputDir } = latestExtraction(id);
    const jobId = startJob(id, 'kernel', {}, async () => {
      const result = runKernelPosture(row.path, rootfsPath, outputDir);
      syncFindings(id, 'kernel', result.findings);
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/kernel', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const done = listJobs(id).find((j) => j.kind === 'kernel' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });
}
