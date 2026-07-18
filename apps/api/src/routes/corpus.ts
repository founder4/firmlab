/**
 * Corpus routes — cross-image priors and the corpus overview. Everything here is a *reference* into other
 * images (occurrences), never a new asserted finding: the corpus enriches, it does not conclude.
 */
import type { FastifyInstance } from 'fastify';
import { corpusRefs, deleteRule, listRules, promoteRule } from '../corpus.js';
import { getImage } from '../store.js';

export async function corpusRoutes(app: FastifyInstance): Promise<void> {
  // For one image: which of its credentials / components / binaries also appear in other images.
  app.get('/images/:id/corpus-refs', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    return { refs: corpusRefs(id) };
  });

  // Level 1: the human-curated rule watchlist (e.g. known-bad credentials).
  app.get('/corpus/rules', async (req) => {
    const { type } = (req.query ?? {}) as { type?: string };
    return { rules: listRules(type) };
  });

  app.post('/corpus/rules', async (req, reply) => {
    const body = (req.body ?? {}) as { type?: string; key?: string; label?: string; note?: string };
    const type = typeof body.type === 'string' ? body.type : '';
    const key = typeof body.key === 'string' ? body.key.trim() : '';
    const label = typeof body.label === 'string' ? body.label.trim() : '';
    if (!type || !key || !label) {
      return reply.status(400).send({ error: 'type, key and label are required' });
    }
    return { rule: promoteRule(type, key, label, typeof body.note === 'string' ? body.note : null) };
  });

  app.delete('/corpus/rules/:id', async (req) => {
    const { id } = req.params as { id: string };
    deleteRule(id);
    return { deleted: id };
  });
}
