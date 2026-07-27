/**
 * Firmware diff intake + retrieval. POST kicks off a diff of image `:id` against another image as a job; GET
 * returns the latest completed diff of `:id` against a specific `against` image. Both images must exist.
 */
import type { FastifyInstance } from 'fastify';
import { syncFindings } from '../findings.js';
import { runDiff } from '../providers/diff.js';
import type { ExtractResult } from '../providers/extract.js';
import { runFuncDiff } from '../providers/funcdiff-run.js';
import { startJob } from '../providers/jobs.js';
import { getImage, listJobs } from '../store.js';

/** The most recent successful extraction's rootfs for an image, if any. */
function latestRootfs(imageId: string): string | null {
  const done = listJobs(imageId).find((j) => j.kind === 'extract' && j.status === 'done' && j.resultJson);
  if (!done?.resultJson) return null;
  return (JSON.parse(done.resultJson) as ExtractResult).rootfsPath;
}

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

  /**
   * Function-level diff: `:id` is the NEWER build, `against` the older. Localizes the code change that the
   * package/CVE diff can only tell you happened. Both sides need an extracted rootfs.
   */
  app.post('/images/:id/funcdiff', async (req, reply) => {
    const { id } = req.params as { id: string };
    const body = (req.body ?? {}) as { against?: string; maxPairs?: number; withText?: boolean };
    const against = body.against;
    if (!against) return reply.status(400).send({ error: 'Body must include { against: <older imageId> }' });
    const newer = getImage(id);
    const older = getImage(against);
    if (!newer) return reply.status(404).send({ error: 'Image not found' });
    if (!older) return reply.status(404).send({ error: 'Comparison image not found' });
    if (id === against) return reply.status(400).send({ error: 'Cannot diff an image against itself' });

    const newerRootfs = latestRootfs(id);
    const olderRootfs = latestRootfs(against);
    if (!newerRootfs || !olderRootfs) {
      return reply.status(400).send({
        error: `Run extraction on both images first — ${!olderRootfs ? older.filename : newer.filename} has no extracted rootfs`,
      });
    }
    const maxPairs =
      typeof body.maxPairs === 'number' && Number.isFinite(body.maxPairs)
        ? Math.min(200, Math.max(1, Math.round(body.maxPairs)))
        : undefined;

    // Decompiling the changed functions costs two more radare2 runs each, so it is opt-out rather than implicit.
    const withText = body.withText !== false;
    const jobId = startJob(id, 'funcdiff', { against, maxPairs, withText }, async (handle) => {
      const result = await runFuncDiff(
        olderRootfs,
        newerRootfs,
        { older: older.filename, newer: newer.filename },
        handle,
        maxPairs,
        withText,
      );
      // Keyed by the comparison, so diffing against a different build adds rows instead of replacing them.
      syncFindings(id, `funcdiff:${against}`, result.findings);
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/funcdiff', async (req, reply) => {
    const { id } = req.params as { id: string };
    const { against } = req.query as { against?: string };
    if (!against) return reply.status(400).send({ error: 'Query must include ?against=<imageId>' });
    const done = listJobs(id).find((j) => {
      if (j.kind !== 'funcdiff' || j.status !== 'done' || !j.resultJson) return false;
      const params = j.params ? (JSON.parse(j.params) as { against?: string }) : null;
      return params?.against === against;
    });
    return reply.status(200).send({ result: done?.resultJson ? JSON.parse(done.resultJson) : null });
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
