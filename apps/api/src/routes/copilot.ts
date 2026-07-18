/**
 * Copilot routes — the flag-gated LLM interpretation layer. GET /agent/status lets the UI show or hide the
 * copilot; POST runs it as a job (LLM calls are slow), GET returns the latest analysis. With the agent off
 * (no FIRMLAB_AGENT / no key) every route reports disabled and nothing reaches the network.
 */
import type { FastifyInstance } from 'fastify';
import { runCopilot } from '../copilot.js';
import { loadLlmConfig } from '../llm.js';
import { startJob } from '../providers/jobs.js';
import { getImage, listJobs } from '../store.js';

export async function copilotRoutes(app: FastifyInstance): Promise<void> {
  // Whether the copilot is enabled and which provider/model backs it (no secrets exposed).
  app.get('/agent/status', async () => {
    const cfg = loadLlmConfig();
    if (!cfg) return { enabled: false };
    return { enabled: true, provider: cfg.provider, model: cfg.model };
  });

  app.post('/images/:id/copilot', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const cfg = loadLlmConfig();
    if (!cfg) {
      return reply.status(400).send({ error: 'Copilot disabled — set FIRMLAB_AGENT=1 and an LLM API key' });
    }
    const jobId = startJob(id, 'copilot', { provider: cfg.provider, model: cfg.model }, async (handle) => {
      handle.log(`Running copilot via ${cfg.provider} (${cfg.model})…`);
      const result = await runCopilot(id, cfg);
      if (!result) throw new Error('No analysis context for this image');
      handle.log('Copilot analysis complete.');
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/copilot', async (req) => {
    const { id } = req.params as { id: string };
    const done = listJobs(id).find((j) => j.kind === 'copilot' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });
}
