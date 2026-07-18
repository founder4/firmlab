/**
 * Binary triage intake. POST runs radare2 over a chosen binary from the latest extracted rootfs as a job; GET
 * returns the most recent completed triage. Needs a prior successful extraction to supply the rootfs.
 */
import type { FastifyInstance } from 'fastify';
import { normalizeBinaryHardening, syncFindings } from '../findings.js';
import { type DecompileResult, runDecompile } from '../providers/decompile.js';
import type { ExtractResult } from '../providers/extract.js';
import { startJob } from '../providers/jobs.js';
import { getImage, listJobs } from '../store.js';

/** Find the most recent successful extraction rootfs for an image, if any. */
function latestRootfs(imageId: string): string | null {
  const done = listJobs(imageId).find((j) => j.kind === 'extract' && j.status === 'done' && j.resultJson);
  if (!done?.resultJson) return null;
  return (JSON.parse(done.resultJson) as ExtractResult).rootfsPath;
}

function latestDecompile(imageId: string): DecompileResult | null {
  const done = listJobs(imageId).find((j) => j.kind === 'decompile' && j.status === 'done' && j.resultJson);
  if (!done?.resultJson) return null;
  return JSON.parse(done.resultJson) as DecompileResult;
}

export async function decompileRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/decompile', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const rootfsPath = latestRootfs(id);
    if (!rootfsPath) {
      return reply.status(400).send({ error: 'Run extraction first — binary triage needs an extracted rootfs' });
    }
    const body = (req.body ?? {}) as { binary?: string };
    const binary = typeof body.binary === 'string' ? body.binary : '';
    if (!binary) return reply.status(400).send({ error: 'No target binary specified' });

    const jobId = startJob(id, 'decompile', { binary }, (handle) =>
      runDecompile(rootfsPath, binary, handle).then((r) => {
        syncFindings(id, `binary:${binary}`, normalizeBinaryHardening(r));
        return r;
      }),
    );
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/decompile', async (req) => {
    const { id } = req.params as { id: string };
    return { result: latestDecompile(id) };
  });
}
