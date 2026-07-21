/**
 * RTOS / bare-metal routes — the raw ARM Cortex-M analysis track. Pure, tool-free static analysis of a raw `.bin`
 * blob: recover the Cortex-M vector table + flash/RAM memory map from the bytes and detect the RTOS kernel. A
 * successful parse is `static_confirmed` — a fact about the image bytes, never a device claim — and its findings
 * (vector table, RTOS kernel, bare-metal lead) are synced into the findings ledger. A non-Cortex-M blob degrades
 * honestly (isCortexM:false) rather than fabricating a memory map.
 */
import type { FastifyInstance } from 'fastify';
import { syncFindings } from '../findings.js';
import { startJob } from '../providers/jobs.js';
import { runRtosAnalysis } from '../providers/rtos.js';
import { getImage, listJobs } from '../store.js';

export async function rtosRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/rtos', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = getImage(id);
    if (!row) return reply.status(404).send({ error: 'Image not found' });
    const jobId = startJob(id, 'rtos', {}, async () => {
      const result = runRtosAnalysis(row.path);
      syncFindings(id, 'rtos', result.findings);
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/rtos', async (req) => {
    const { id } = req.params as { id: string };
    const done = listJobs(id).find((j) => j.kind === 'rtos' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });
}
