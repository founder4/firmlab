/**
 * Renode routes (Phase 4, debt #4) — boot an RTOS / Cortex-M firmware. Renode is an opt-in heavy layer; with it
 * absent the job degrades honestly (available:false / blocked_by_platform). The platform is auto-selected from the
 * firmware's hints (or specified); "booted" is decided from real UART output, never assumed.
 */
import type { FastifyInstance } from 'fastify';
import { syncFindings } from '../findings.js';
import { startJob } from '../providers/jobs.js';
import { buildRenodeFindings, detectRenode, renodeHintsFrom, runRenode } from '../providers/renode.js';
import { getImage, listJobs } from '../store.js';

/** MCU/vendor hints for platform selection: identity fields + a bounded slice of the analysis strings. */
function hintsFor(imageId: string): string[] {
  const row = getImage(imageId);
  return renodeHintsFrom(row?.identityJson ?? null, row?.analysisJson ?? null);
}

export async function renodeRoutes(app: FastifyInstance): Promise<void> {
  app.get('/renode/status', async () => ({ available: await detectRenode() }));

  app.post('/images/:id/renode', async (req, reply) => {
    const { id } = req.params as { id: string };
    const row = getImage(id);
    if (!row) return reply.status(404).send({ error: 'Image not found' });
    const body = (req.body ?? {}) as { platform?: string; seconds?: number };
    const opts: { platform?: string; seconds?: number } = {};
    if (body.platform) opts.platform = body.platform;
    if (body.seconds) opts.seconds = Math.min(120, Math.max(3, Number(body.seconds)));
    // The source is image-wide, not per platform: Renode selects the platform from the firmware's own bytes, so
    // "does this image boot under Renode" is one question per image and a re-run replaces its answer. The platform
    // that was chosen travels in the row's evidence, where an operator override is visible without splitting the
    // key and stranding a previous platform's verdict in the ledger forever.
    const jobId = startJob(id, 'renode', { platform: opts.platform ?? null }, () =>
      runRenode(row.path, hintsFor(id), opts).then((r) => {
        syncFindings(id, 'renode', buildRenodeFindings(r));
        return r;
      }),
    );
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/renode', async (req) => {
    const { id } = req.params as { id: string };
    const done = listJobs(id).find((j) => j.kind === 'renode' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });
}
