/**
 * Firmware diff intake + retrieval. POST kicks off a diff of image `:id` against another image as a job; GET
 * returns the latest completed diff of `:id` against a specific `against` image. Both images must exist.
 */
import type { FastifyInstance } from 'fastify';
import { runDiff } from '../providers/diff.js';
import { startJob } from '../providers/jobs.js';
import { getImage, listJobs } from '../store.js';

export async function diffRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/diff', async (req, reply) => {
    const { id } = req.params as { id: string };
    const body = (req.body ?? {}) as { against?: string };
    const against = body.against;
    if (!against) return reply.status(400).send({ error: 'Body must include { against: <imageId> }' });
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    if (!getImage(against)) return reply.status(404).send({ error: 'Comparison image not found' });
    if (id === against) return reply.status(400).send({ error: 'Cannot diff an image against itself' });

    const jobId = startJob(id, 'diff', { against }, (handle) => runDiff(id, against, handle));
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/diff', async (req, reply) => {
    const { id } = req.params as { id: string };
    const { against } = req.query as { against?: string };
    if (!against) return reply.status(400).send({ error: 'Query must include ?against=<imageId>' });

    const done = listJobs(id).find((j) => {
      if (j.kind !== 'diff' || j.status !== 'done' || !j.resultJson) return false;
      const params = j.params ? (JSON.parse(j.params) as { against?: string }) : null;
      return params?.against === against;
    });
    return reply.status(200).send({ result: done?.resultJson ? JSON.parse(done.resultJson) : null });
  });
}
