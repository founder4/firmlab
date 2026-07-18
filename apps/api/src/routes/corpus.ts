/**
 * Corpus routes — cross-image priors and the corpus overview. Everything here is a *reference* into other
 * images (occurrences), never a new asserted finding: the corpus enriches, it does not conclude.
 */
import type { FastifyInstance } from 'fastify';
import { corpusRefs } from '../corpus.js';
import { getImage } from '../store.js';

export async function corpusRoutes(app: FastifyInstance): Promise<void> {
  // For one image: which of its credentials / components / binaries also appear in other images.
  app.get('/images/:id/corpus-refs', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    return { refs: corpusRefs(id) };
  });
}
