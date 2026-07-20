/**
 * External-intelligence routes (Phase 5) — the OSINT / published-vulnerability / disclosure track, gated by its
 * OWN flag (FIRMLAB_RESEARCH). With it unset every route reports disabled and nothing reaches the network — the
 * local-only default is preserved. GET /research/status exposes the host allowlist so the UI can show exactly
 * where data may go; the run is a job (network + LLM are slow).
 */
import type { FastifyInstance } from 'fastify';
import { startJob } from '../providers/jobs.js';
import { loadResearchConfig } from '../research/config.js';
import { runResearch } from '../research/run.js';
import { getImage, listJobs } from '../store.js';

export async function researchRoutes(app: FastifyInstance): Promise<void> {
  // Whether external intelligence is enabled, and the exact hosts it may contact.
  app.get('/research/status', async () => {
    const cfg = loadResearchConfig();
    if (!cfg) return { enabled: false };
    return { enabled: true, allowlist: cfg.allowlist };
  });

  app.post('/images/:id/research', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    if (!loadResearchConfig()) {
      const error = 'External research disabled — set FIRMLAB_RESEARCH=1 (the only feature that leaves the machine)';
      return reply.status(400).send({ error });
    }
    const jobId = startJob(id, 'research', {}, (h) => runResearch(id, h));
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/research', async (req) => {
    const { id } = req.params as { id: string };
    const done = listJobs(id).find((j) => j.kind === 'research' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });
}
