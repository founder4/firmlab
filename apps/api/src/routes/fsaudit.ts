/**
 * fsaudit routes — the extracted-rootfs static security audit (firmwalker / FACT-style). It reads the classic
 * misconfiguration surface an analyst checks by hand (empty/weak credentials, extra UID-0 accounts, init-spawned
 * shells/telnetd, permissive ssh/telnet/ftp service configs, notable key material) from an ALREADY-EXTRACTED
 * rootfs. Needs a rootfs, so it 400s until extraction has run; its findings are synced into the findings ledger.
 */
import type { FastifyInstance } from 'fastify';
import { syncFindings } from '../findings.js';
import type { ExtractResult } from '../providers/extract.js';
import { runFsAudit } from '../providers/fsaudit.js';
import { startJob } from '../providers/jobs.js';
import { getImage, listJobs } from '../store.js';

function latestRootfs(imageId: string): string | null {
  const job = listJobs(imageId).find((j) => j.kind === 'extract' && j.status === 'done' && j.resultJson);
  return job?.resultJson ? ((JSON.parse(job.resultJson) as ExtractResult).rootfsPath ?? null) : null;
}

export async function fsauditRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/fsaudit', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const rootfs = latestRootfs(id);
    if (!rootfs) {
      return reply.status(400).send({ error: 'Run extraction first — the filesystem audit needs an extracted rootfs' });
    }
    const jobId = startJob(id, 'fsaudit', {}, async () => {
      const result = runFsAudit(rootfs);
      syncFindings(id, 'fsaudit', result.findings);
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/fsaudit', async (req) => {
    const { id } = req.params as { id: string };
    const done = listJobs(id).find((j) => j.kind === 'fsaudit' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });
}
