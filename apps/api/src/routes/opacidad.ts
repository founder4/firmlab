/**
 * Opacidad (W9) routes — the autonomous-scan orchestrator. POST plans + runs the class-routed worker chain as a
 * job (it invokes multiple providers, so it is slow); GET returns the latest run. The LLM narrative is optional:
 * with the agent off, opacidad still runs and composes a deterministic narrative, so this route is never gated
 * behind an API key — only the *phrasing* of the report changes when a model is configured.
 */
import type { FastifyInstance } from 'fastify';
import { loadLlmConfig } from '../llm.js';
import { runOpacidad } from '../opacidad.js';
import { startJob } from '../providers/jobs.js';
import { getImage, listJobs } from '../store.js';

export async function opacidadRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/opacidad', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = getImage(id);
    if (!row) return reply.status(404).send({ error: 'Image not found' });
    if (!row.identityJson) {
      return reply
        .status(400)
        .send({ error: 'No analysis yet — the image must be analyzed before an autonomous scan' });
    }
    const cfg = loadLlmConfig();
    const jobId = startJob(id, 'opacidad', { narrative: cfg ? cfg.provider : 'deterministic' }, async (handle) => {
      handle.log('Autonomous scan (opacidad) starting…');
      const result = await runOpacidad(id, row.path, handle, cfg);
      handle.log(`Autonomous scan complete: ${result.steps.length} workers, ${result.findings.total} findings.`);
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/opacidad', async (req) => {
    const { id } = req.params as { id: string };
    const done = listJobs(id).find((j) => j.kind === 'opacidad' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });
}
