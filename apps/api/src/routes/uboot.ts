/**
 * U-Boot routes — the bootloader-analysis track. Offline structural analysis of the U-Boot environment stored in a
 * firmware image: POST starts a job that decodes the env and audits the boot posture, syncing its findings (root
 * shell boot args, an interruptible autoboot, a network boot path, an exposed serial console) into the ledger; GET
 * returns the latest completed result. Honest: no env block found degrades to found:false, never a fabricated env.
 */
import type { FastifyInstance } from 'fastify';
import { syncFindings } from '../findings.js';
import { startJob } from '../providers/jobs.js';
import { runUbootAnalysis } from '../providers/uboot.js';
import { getImage, listJobs } from '../store.js';

export async function ubootRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/uboot', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = getImage(id);
    if (!row) return reply.status(404).send({ error: 'Image not found' });
    const jobId = startJob(id, 'uboot', {}, async () => {
      const result = runUbootAnalysis(row.path);
      syncFindings(id, 'uboot', result.findings);
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/uboot', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const done = listJobs(id).find((j) => j.kind === 'uboot' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });
}
