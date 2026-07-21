/**
 * servicemap routes — the static network-service-enumeration over an extracted rootfs. It maps the daemons the
 * firmware is configured to START (inittab, inetd, rc scripts, systemd units) — the boot-time attack surface —
 * WITHOUT booting anything. Needs a rootfs, so it 400s until extraction has run; its findings (a service inventory
 * plus one lead per exposed autostart network daemon) are synced into the findings ledger.
 */
import type { FastifyInstance } from 'fastify';
import { syncFindings } from '../findings.js';
import type { ExtractResult } from '../providers/extract.js';
import { startJob } from '../providers/jobs.js';
import { runServiceMap } from '../providers/servicemap.js';
import { getImage, listJobs } from '../store.js';

function latestRootfs(imageId: string): string | null {
  const job = listJobs(imageId).find((j) => j.kind === 'extract' && j.status === 'done' && j.resultJson);
  return job?.resultJson ? ((JSON.parse(job.resultJson) as ExtractResult).rootfsPath ?? null) : null;
}

export async function servicemapRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/services', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const rootfs = latestRootfs(id);
    if (!rootfs) {
      return reply.status(400).send({ error: 'Run extraction first — the service map needs an extracted rootfs' });
    }
    const jobId = startJob(id, 'services', {}, async () => {
      const result = runServiceMap(rootfs);
      syncFindings(id, 'services', result.findings);
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/services', async (req) => {
    const { id } = req.params as { id: string };
    const done = listJobs(id).find((j) => j.kind === 'services' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });
}
