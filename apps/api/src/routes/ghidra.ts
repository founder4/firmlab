/**
 * Ghidra decompilation intake. POST runs `analyzeHeadless` over a chosen binary from the latest extracted
 * rootfs as a job; GET returns the most recent completed decompilation. Needs a prior successful extraction.
 * Ghidra is optional — the job degrades to `available:false` when the tool isn't installed.
 */
import type { FastifyInstance } from 'fastify';
import { syncFindings } from '../findings.js';
import type { ExtractResult } from '../providers/extract.js';
import { type GhidraResult, buildGhidraFindings, runGhidra } from '../providers/ghidra.js';
import { startJob } from '../providers/jobs.js';
import { getImage, listJobs } from '../store.js';

/** Find the most recent successful extraction rootfs for an image, if any. */
function latestRootfs(imageId: string): string | null {
  const done = listJobs(imageId).find((j) => j.kind === 'extract' && j.status === 'done' && j.resultJson);
  if (!done?.resultJson) return null;
  return (JSON.parse(done.resultJson) as ExtractResult).rootfsPath;
}

function latestGhidra(imageId: string): GhidraResult | null {
  const done = listJobs(imageId).find((j) => j.kind === 'ghidra' && j.status === 'done' && j.resultJson);
  if (!done?.resultJson) return null;
  return JSON.parse(done.resultJson) as GhidraResult;
}

export async function ghidraRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/ghidra', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const rootfsPath = latestRootfs(id);
    if (!rootfsPath) {
      return reply.status(400).send({ error: 'Run extraction first — decompilation needs an extracted rootfs' });
    }
    const body = (req.body ?? {}) as { binary?: string };
    const binary = typeof body.binary === 'string' ? body.binary : '';
    if (!binary) return reply.status(400).send({ error: 'No target binary specified' });

    // Per binary, like the radare2 triage next door: decompiling a second target is a different question and must
    // not delete the first one's row. A successful run syncs an EMPTY list, which is what makes re-running
    // idempotent AND clears a stale blocked row once the decompiler is installed.
    const jobId = startJob(id, 'ghidra', { binary }, (handle) =>
      runGhidra(rootfsPath, binary, handle).then((r) => {
        syncFindings(id, `ghidra:${binary}`, buildGhidraFindings(r));
        return r;
      }),
    );
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/ghidra', async (req) => {
    const { id } = req.params as { id: string };
    return { result: latestGhidra(id) };
  });
}
