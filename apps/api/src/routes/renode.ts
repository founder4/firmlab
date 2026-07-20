/**
 * Renode routes (Phase 4, debt #4) — boot an RTOS / Cortex-M firmware. Renode is an opt-in heavy layer; with it
 * absent the job degrades honestly (available:false / blocked_by_platform). The platform is auto-selected from the
 * firmware's hints (or specified); "booted" is decided from real UART output, never assumed.
 */
import type { StaticAnalysis } from '@firmlab/core';
import type { FastifyInstance } from 'fastify';
import { startJob } from '../providers/jobs.js';
import { detectRenode, runRenode } from '../providers/renode.js';
import { getImage, listJobs } from '../store.js';

/** MCU/vendor hints for platform selection: identity fields + a bounded slice of the analysis strings. */
function hintsFor(imageId: string): string[] {
  const row = getImage(imageId);
  const hints: string[] = [];
  if (row?.identityJson) {
    const id = JSON.parse(row.identityJson) as { firmwareClass?: string; arch?: string; bootloader?: string | null };
    hints.push(id.firmwareClass ?? '', id.arch ?? '', id.bootloader ?? '');
  }
  if (row?.analysisJson) {
    const a = JSON.parse(row.analysisJson) as StaticAnalysis;
    hints.push(...a.secrets.slice(0, 40).map((s) => s.value), ...a.signatures.map((s) => s.description));
  }
  return hints.filter(Boolean);
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
    const jobId = startJob(id, 'renode', { platform: opts.platform ?? null }, () =>
      runRenode(row.path, hintsFor(id), opts),
    );
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/renode', async (req) => {
    const { id } = req.params as { id: string };
    const done = listJobs(id).find((j) => j.kind === 'renode' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });
}
