/**
 * Read-only analysis views over the cached static analysis: identity, entropy profile, structure map,
 * signatures, and secrets. These back the workbench tabs (Entropy, Structure/binwalk map, Secrets). All data
 * is served from the persisted analysis JSON, so these routes are cheap and never re-read the image.
 */
import type { StaticAnalysis } from '@firmlab/core';
import type { FastifyInstance } from 'fastify';
import { getImage } from '../store.js';

function loadAnalysis(id: string): StaticAnalysis | null {
  const row = getImage(id);
  if (!row?.analysisJson) return null;
  return JSON.parse(row.analysisJson) as StaticAnalysis;
}

export async function analysisRoutes(app: FastifyInstance): Promise<void> {
  app.get('/images/:id/analysis', async (req, reply) => {
    const { id } = req.params as { id: string };
    const analysis = loadAnalysis(id);
    if (!analysis) return reply.status(404).send({ error: 'No analysis for this image' });
    return { analysis };
  });

  app.get('/images/:id/entropy', async (req, reply) => {
    const { id } = req.params as { id: string };
    const analysis = loadAnalysis(id);
    if (!analysis) return reply.status(404).send({ error: 'No analysis for this image' });
    return { size: analysis.size, entropy: analysis.entropy };
  });

  app.get('/images/:id/structure', async (req, reply) => {
    const { id } = req.params as { id: string };
    const analysis = loadAnalysis(id);
    if (!analysis) return reply.status(404).send({ error: 'No analysis for this image' });
    return { size: analysis.size, structure: analysis.structure, signatures: analysis.signatures };
  });

  app.get('/images/:id/secrets', async (req, reply) => {
    const { id } = req.params as { id: string };
    const analysis = loadAnalysis(id);
    if (!analysis) return reply.status(404).send({ error: 'No analysis for this image' });
    return { secrets: analysis.secrets };
  });
}
