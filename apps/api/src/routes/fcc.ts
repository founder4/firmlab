/**
 * FCC-ID recon routes — the deterministic, no-network provider that extracts candidate FCC IDs from the firmware
 * bytes and builds authoritative lookup links (fccid.io + the FCC OET equipment-authorization search). A device's
 * public FCC filing (external/internal photos, manuals, RF/EMC test reports) is a recon goldmine. The findings are
 * `info` / `static_confirmed` — the ID is literally present in the image — and are synced into the findings ledger.
 */
import type { FastifyInstance } from 'fastify';
import { syncFindings } from '../findings.js';
import { runFccLookup } from '../providers/fcc.js';
import { startJob } from '../providers/jobs.js';
import { getImage, listJobs } from '../store.js';

export async function fccRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/fcc', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = getImage(id);
    if (!row) return reply.status(404).send({ error: 'Image not found' });
    const jobId = startJob(id, 'fcc', {}, async () => {
      const result = runFccLookup(row.path, row.analysisJson);
      syncFindings(id, 'fcc', result.findings);
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/fcc', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const done = listJobs(id).find((j) => j.kind === 'fcc' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });
}
