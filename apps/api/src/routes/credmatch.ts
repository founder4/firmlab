/**
 * Credential cross-reference intake. POST joins the password hashes stored in the latest extracted rootfs against
 * the printable strings that same rootfs ships, as a job; GET returns the most recent completed result.
 *
 * It needs a rootfs, and the refusal says so rather than returning an empty run: no extraction is a MISSING
 * PREREQUISITE, not a credential store that came back unbreakable, and the two must never reach the caller looking
 * the same. Everything else the provider can fail at — openssl absent, a scheme it cannot compute, a candidate set
 * that dropped nothing versus one truncated by the cap — comes back as a completed job carrying its own
 * `blocked_by_platform` findings, because those are answers about coverage and belong in the ledger.
 *
 * `syncFindings` runs under the stable source `credmatch`, so re-running replaces exactly this provider's rows and
 * leaves `fsaudit`'s weak-hash findings (the same accounts, a different claim) untouched. The provider stays pure
 * w.r.t. the ledger: it returns drafts, and this route is the only thing here that writes them.
 */
import type { FastifyInstance } from 'fastify';
import { syncFindings } from '../findings.js';
import { type CredMatchResult, runCredMatch } from '../providers/credmatch.js';
import type { ExtractResult } from '../providers/extract.js';
import { startJob } from '../providers/jobs.js';
import { getImage, listJobs } from '../store.js';

/** The source string both this route and any future autonomous stage must use — one ledger namespace, not two. */
export const CREDMATCH_SOURCE = 'credmatch';

/** Find the most recent successful extraction's rootfs path for an image, if any. */
function latestRootfs(imageId: string): string | null {
  const done = listJobs(imageId).find((j) => j.kind === 'extract' && j.status === 'done' && j.resultJson);
  if (!done?.resultJson) return null;
  return (JSON.parse(done.resultJson) as ExtractResult).rootfsPath;
}

function latestCredMatch(imageId: string): CredMatchResult | null {
  const done = listJobs(imageId).find((j) => j.kind === 'credmatch' && j.status === 'done' && j.resultJson);
  if (!done?.resultJson) return null;
  return JSON.parse(done.resultJson) as CredMatchResult;
}

export async function credmatchRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/credmatch', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const rootfsPath = latestRootfs(id);
    if (!rootfsPath) {
      return reply.status(400).send({
        error:
          'Run extraction first — the credential cross-reference needs an extracted rootfs to read both the stored hashes and the candidate strings. Nothing was tested, which is not the same as nothing being found.',
      });
    }
    const jobId = startJob(id, 'credmatch', {}, (handle) =>
      runCredMatch(rootfsPath, handle).then((result) => {
        // Synced whatever the outcome: a run that could not compute a scheme, or never reached a hash at all,
        // contributes its own `blocked_by_platform` rows so the ledger records the question rather than staying
        // silent — and a bounded negative is recorded as the fact it is.
        syncFindings(id, CREDMATCH_SOURCE, result.findings);
        return result;
      }),
    );
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/credmatch', async (req) => {
    const { id } = req.params as { id: string };
    return { result: latestCredMatch(id) };
  });
}
