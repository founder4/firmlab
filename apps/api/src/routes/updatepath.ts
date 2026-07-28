/**
 * Update-mechanism integrity routes (ISTG-FW). POST starts a job that reads the image's own integrity metadata and,
 * when an extraction already produced a rootfs, locates the updater and reads what it verifies; GET returns the
 * latest completed result.
 *
 * The rootfs is OPTIONAL on purpose. Half of this question — what the shipped image itself carries — is answerable
 * from the raw bytes alone, and refusing to run without an extraction would turn "we never looked" into "nothing
 * found" for exactly the images (encrypted bodies, partial carves) where the answer matters most. Without a rootfs
 * the provider records the updater half as `blocked_by_platform` and says so; it never reports it as clean.
 *
 * Findings sync under the stable `updatepath` source, the same string W9 uses, so a manual run and an autonomous
 * scan re-sync the same rows instead of duplicating them.
 */
import type { FastifyInstance } from 'fastify';
import { syncFindings } from '../findings.js';
import type { ExtractResult } from '../providers/extract.js';
import { startJob } from '../providers/jobs.js';
import { runUpdatePath } from '../providers/updatepath.js';
import { getImage, listJobs } from '../store.js';

/** The most recent successful extraction's rootfs, if any. */
function latestRootfs(imageId: string): string | null {
  const done = listJobs(imageId).find((j) => j.kind === 'extract' && j.status === 'done' && j.resultJson);
  return done?.resultJson ? ((JSON.parse(done.resultJson) as ExtractResult).rootfsPath ?? null) : null;
}

export async function updatepathRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/updatepath', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = getImage(id);
    if (!row) return reply.status(404).send({ error: 'Image not found' });
    const rootfsPath = latestRootfs(id);
    const jobId = startJob(id, 'updatepath', { rootfsPath }, async (handle) => {
      if (!rootfsPath) {
        handle.log('No extracted rootfs — reading the image container only; the updater half stays unanswered.');
      }
      const result = runUpdatePath(row.path, rootfsPath);
      handle.log(result.reason);
      syncFindings(id, 'updatepath', result.findings);
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/updatepath', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const done = listJobs(id).find((j) => j.kind === 'updatepath' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });
}
