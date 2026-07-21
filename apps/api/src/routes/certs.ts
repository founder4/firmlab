/**
 * Certificate routes — the embedded X.509 trust-anchor track. No external tool is required (Node's built-in
 * `X509Certificate` does the parsing), so the job always runs; it scans the latest extracted rootfs (when present)
 * plus a bounded prefix of the raw image, and syncs the resulting `static_confirmed` certificate findings (expired,
 * weak RSA, test/self-signed, embedded CA) into the ledger. Mirrors the fuzz route's `latestRootfs` helper.
 */
import type { FastifyInstance } from 'fastify';
import { syncFindings } from '../findings.js';
import { runCertAnalysis } from '../providers/certs.js';
import type { ExtractResult } from '../providers/extract.js';
import { startJob } from '../providers/jobs.js';
import { getImage, listJobs } from '../store.js';

function latestRootfs(imageId: string): string | null {
  const job = listJobs(imageId).find((j) => j.kind === 'extract' && j.status === 'done' && j.resultJson);
  return job?.resultJson ? ((JSON.parse(job.resultJson) as ExtractResult).rootfsPath ?? null) : null;
}

export async function certsRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/certs', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = getImage(id);
    if (!row) return reply.status(404).send({ error: 'Image not found' });
    const rootfs = latestRootfs(id);
    const jobId = startJob(id, 'certs', {}, async () => {
      const result = runCertAnalysis(rootfs, row.path);
      syncFindings(id, 'certs', result.findings);
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/certs', async (req) => {
    const { id } = req.params as { id: string };
    const done = listJobs(id).find((j) => j.kind === 'certs' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });
}
