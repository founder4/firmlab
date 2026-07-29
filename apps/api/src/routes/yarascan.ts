/**
 * Rule-based rootfs scan intake (YARA). POST runs the operator's rule corpus over the latest extracted rootfs as a
 * job; GET returns the most recent completed result.
 *
 * Like SBOM, gitleaks and emulation, this depends on a prior successful extraction — but the reason it refuses is
 * spelled out rather than returned as an empty scan: no rootfs is a MISSING PREREQUISITE, not a rootfs that came
 * back clean, and the two must never arrive at the caller looking the same.
 *
 * `syncFindings` runs under the stable source `yarascan`, so re-running the sweep replaces exactly its own rows and
 * leaves every other provider's findings alone. The provider itself stays pure w.r.t. the ledger: it returns
 * drafts, and this route is the only thing here that writes them.
 */
import type { FastifyInstance } from 'fastify';
import { syncFindings } from '../findings.js';
import type { ExtractResult } from '../providers/extract.js';
import { startJob } from '../providers/jobs.js';
import { type YaraScanResult, runYaraScan } from '../providers/yarascan.js';
import { getImage, listJobs } from '../store.js';

/** The source string both this route and any future autonomous stage must use — one ledger namespace, not two. */
export const YARASCAN_SOURCE = 'yarascan';

/** Find the most recent successful extraction's rootfs path for an image, if any. */
function latestRootfs(imageId: string): string | null {
  const done = listJobs(imageId).find((j) => j.kind === 'extract' && j.status === 'done' && j.resultJson);
  if (!done?.resultJson) return null;
  return (JSON.parse(done.resultJson) as ExtractResult).rootfsPath;
}

function latestYaraScan(imageId: string): YaraScanResult | null {
  const done = listJobs(imageId).find((j) => j.kind === 'yarascan' && j.status === 'done' && j.resultJson);
  if (!done?.resultJson) return null;
  return JSON.parse(done.resultJson) as YaraScanResult;
}

export async function yarascanRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/yarascan', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const rootfsPath = latestRootfs(id);
    if (!rootfsPath) {
      return reply.status(400).send({
        error:
          'Run extraction first — the rule-based scan needs an extracted rootfs. Nothing was scanned, which is not the same as nothing being found.',
      });
    }
    const jobId = startJob(id, 'yarascan', {}, (handle) =>
      runYaraScan(rootfsPath, handle).then((r) => {
        // Synced whatever the outcome: a blocked scan contributes its own `blocked_by_platform` finding, so the
        // ledger records that the question was asked and could not be answered instead of staying silent.
        syncFindings(id, YARASCAN_SOURCE, r.findings);
        return r;
      }),
    );
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/yarascan', async (req) => {
    const { id } = req.params as { id: string };
    return { result: latestYaraScan(id) };
  });
}
