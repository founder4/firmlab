/**
 * NVRAM-store routes — the flash key-value store, scanned from the RAW upload.
 *
 * Every other secret-hunting route here takes an extracted rootfs and 400s until extraction has run. This one
 * deliberately does not, and that is the whole point: an nvram partition lives in the image's flash layout,
 * outside any filesystem, so a rootfs walk can never reach it however well it works. Nine of the sixteen images
 * in the corpus carry one — including two whose extraction recovers no rootfs at all, where this is the only
 * stage that has anything to say.
 */
import type { FastifyInstance } from 'fastify';
import { syncFindings } from '../findings.js';
import { startJob } from '../providers/jobs.js';
import { runNvramScan } from '../providers/nvram.js';
import { getImage, listJobs } from '../store.js';

export async function nvramRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/nvram', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = getImage(id);
    if (!row) return reply.status(404).send({ error: 'Image not found' });
    const jobId = startJob(id, 'nvram', {}, async (handle) => {
      const result = runNvramScan(row.path);
      handle.log(result.reason);
      for (const store of result.stores) {
        handle.log(
          `store @0x${store.offset.toString(16)}: ${store.recordCount} record(s), ${store.confidence}${store.capped ? ` — bounded: ${store.capped}` : ''}`,
        );
      }
      syncFindings(id, 'nvram', result.findings);
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/nvram', async (req) => {
    const { id } = req.params as { id: string };
    const done = listJobs(id).find((j) => j.kind === 'nvram' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });
}
