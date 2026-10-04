/**
 * External-intelligence routes (Phase 5) — the OSINT / published-vulnerability / disclosure track, gated by its
 * OWN flag (FIRMLAB_RESEARCH). The lane is on by default (operator decision, see `research/config.ts`); with it
 * switched off — a stated `0` in the environment or in Settings — every route reports disabled and nothing reaches
 * the network. Being on authorises a run; it never starts one: a run is still a POST per image. GET
 * /research/status exposes the host allowlist so the UI can show exactly where data may go, and
 * /settings/flags reports whether the default, the environment or a stored override decided it. The run is a job
 * (network + LLM are slow).
 */
import type { FastifyInstance } from 'fastify';
import { startJob } from '../providers/jobs.js';
import { RESEARCH_DISABLED, loadResearchConfig } from '../research/config.js';
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
      const error = RESEARCH_DISABLED;
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
