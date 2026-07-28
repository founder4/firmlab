/**
 * Device-tree routes. POST starts a job that reads every flattened device tree the image carries — through the
 * FIT/UBI carve chain first, then the extraction output, then a validated raw scan — and syncs its findings (board
 * identity, the declared flash map, an enabled debug UART, the `/chosen` kernel command line) into the ledger under
 * a stable `devicetree` source; GET returns the latest completed result.
 *
 * Honest at the edges: an image with no readable device tree returns `found:false` with the list of places that
 * were searched, and an FDT header that validated but whose tree could not be walked to completion comes back in
 * `rejected` with the reason rather than as a tree. The route never decides any of that — the provider does.
 */
import type { FastifyInstance } from 'fastify';
import { syncFindings } from '../findings.js';
import { runDeviceTreeAnalysis } from '../providers/devicetree.js';
import type { ExtractResult } from '../providers/extract.js';
import { startJob } from '../providers/jobs.js';
import { getImage, listJobs } from '../store.js';

/** The latest extraction output dir, when one exists — where a `*.dtb` file would have landed. */
function latestExtractDir(imageId: string): string | null {
  const job = listJobs(imageId).find((j) => j.kind === 'extract' && j.status === 'done' && j.resultJson);
  return job?.resultJson ? ((JSON.parse(job.resultJson) as ExtractResult).outputDir ?? null) : null;
}

export async function devicetreeRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/devicetree', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = getImage(id);
    if (!row) return reply.status(404).send({ error: 'Image not found' });
    const extractDir = latestExtractDir(id);
    const jobId = startJob(id, 'devicetree', {}, async () => {
      const result = runDeviceTreeAnalysis(row.path, extractDir);
      syncFindings(id, 'devicetree', result.findings);
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/devicetree', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const done = listJobs(id).find((j) => j.kind === 'devicetree' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });
}
