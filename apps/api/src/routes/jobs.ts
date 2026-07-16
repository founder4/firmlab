/**
 * Job intake + polling: start extraction, list an image's jobs, and fetch a single job's status/log/result.
 * Extraction is the one job kind wired here; emulation lives in its own route because it also serves a menu.
 */
import type { FastifyInstance } from 'fastify';
import { runExtraction } from '../providers/extract.js';
import { startJob } from '../providers/jobs.js';
import { getImage, getJob, listJobs } from '../store.js';

function jobView(row: ReturnType<typeof getJob>): unknown {
  if (!row) return null;
  return {
    id: row.id,
    imageId: row.imageId,
    kind: row.kind,
    status: row.status,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    params: row.params ? JSON.parse(row.params) : null,
    log: row.log,
    result: row.resultJson ? JSON.parse(row.resultJson) : null,
    error: row.error,
  };
}

export async function jobRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/extract', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = getImage(id);
    if (!row) return reply.status(404).send({ error: 'Image not found' });
    const jobId = startJob(id, 'extract', {}, (handle) => runExtraction(id, row.path, handle));
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/jobs', async (req) => {
    const { id } = req.params as { id: string };
    return { jobs: listJobs(id).map(jobView) };
  });

  app.get('/jobs/:jobId', async (req, reply) => {
    const { jobId } = req.params as { jobId: string };
    const row = getJob(jobId);
    if (!row) return reply.status(404).send({ error: 'Job not found' });
    return { job: jobView(row) };
  });
}
