/**
 * The run ledger — every execution against an image, not just the last one of each kind.
 *
 * Twenty routes answer their GET with `listJobs(id).find(j => j.kind === … && j.status === 'done')`. That is the
 * most recent successful run and nothing else, which is why probing three binaries showed an operator one result:
 * the other two were in the database, unread and unreachable. This route reads them back.
 *
 * It is deliberately generic. The per-kind endpoints stay exactly as they are — they serve the "show me the full
 * result of the current thing" case and their shapes are load-bearing for existing panels — while this one answers
 * the question none of them could: what has been run against this image, aimed at what, and what came back.
 *
 * All reading of a result into a line lives in the pure `run-summary.ts`, so the epistemics (a blocked probe is
 * not an empty one) are unit-tested rather than assembled inline in a handler.
 */
import type { FastifyInstance } from 'fastify';
import { type RunSummary, groupRunsByTarget, summarizeRun } from '../providers/run-summary.js';
import { getImage, listJobs } from '../store.js';

/** Kinds the test bench runs against a specific binary or service — the ones with a target worth grouping by. */
const TARGETED_KINDS = new Set(['dynprobe', 'symreach', 'decompile', 'fuzz', 'webprobe', 'emulate', 'renode']);

export async function runsRoutes(app: FastifyInstance): Promise<void> {
  /**
   * Every run for an image, newest first. `kind` filters to one job kind (repeatable, comma-separated);
   * `scope=targeted` narrows to the kinds the test bench drives against a named binary.
   */
  app.get('/images/:id/runs', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const q = (req.query ?? {}) as { kind?: string; scope?: string };

    const wanted = q.kind
      ? new Set(
          q.kind
            .split(',')
            .map((k) => k.trim())
            .filter(Boolean),
        )
      : null;

    const jobs = listJobs(id).filter((j) => {
      if (wanted) return wanted.has(j.kind);
      if (q.scope === 'targeted') return TARGETED_KINDS.has(j.kind);
      return true;
    });

    const runs: RunSummary[] = jobs.map((j) =>
      summarizeRun({
        id: j.id,
        kind: j.kind,
        status: j.status,
        createdAt: j.createdAt,
        updatedAt: j.updatedAt,
        params: j.params,
        resultJson: j.resultJson,
        error: j.error,
      }),
    );

    // Both shapes, because the two questions are different and neither is derivable cheaply on the client:
    // `runs` is the chronological ledger, `byTarget` is "what do I know about this binary".
    return { runs, byTarget: groupRunsByTarget(runs) };
  });

  /**
   * One run in full — the stored result and log for a specific job. The list gives a line per run; this is how a
   * reader gets from that line to the evidence behind it, for a run that is no longer the most recent one.
   */
  app.get('/images/:id/runs/:jobId', async (req, reply) => {
    const { id, jobId } = req.params as { id: string; jobId: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const job = listJobs(id).find((j) => j.id === jobId);
    if (!job) return reply.status(404).send({ error: 'No such run for this image' });
    return {
      summary: summarizeRun({
        id: job.id,
        kind: job.kind,
        status: job.status,
        createdAt: job.createdAt,
        updatedAt: job.updatedAt,
        params: job.params,
        resultJson: job.resultJson,
        error: job.error,
      }),
      params: job.params ? JSON.parse(job.params) : null,
      result: job.resultJson ? JSON.parse(job.resultJson) : null,
      log: job.log,
      error: job.error,
    };
  });
}
