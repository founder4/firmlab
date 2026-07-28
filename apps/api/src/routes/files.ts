/**
 * files routes — the extracted filesystem, served.
 *
 * Thin HTTP over `providers/fsbrowse.ts`: the route's only jobs are to find the extraction root for an image and
 * to turn a refusal into the right status code. Two things it deliberately does NOT do:
 *
 *  • It does not 400 an image that was never extracted the way `fsaudit` does. A missing rootfs is a precondition
 *    failure for an audit, but for a browser it is the answer — "no extraction has run" and "the extraction
 *    produced 54 volumes and no rootfs" and "the carve is truncated" are different states with different next
 *    moves, and an error string collapses them. So the browse endpoints always return 200 with the extraction
 *    verdict (`describeExtraction`), and `listing: null` when there is nothing on disk. The caller cannot reach a
 *    file list without passing the sentence that bounds it.
 *  • It does not start a job. Reading a directory is milliseconds and synchronous; wrapping it in the job machinery
 *    would only add a poll loop between the operator and the bytes they are trying to check.
 *
 * Status codes carry the guard's distinction: a path the rules refuse is 400 with the rule name, a path that simply
 * is not there is 404. An operator who mistyped and an operator who was refused need different sentences, and the
 * rule is in the body either way.
 */
import type { FastifyInstance } from 'fastify';
import type { ExtractResult } from '../providers/extract.js';
import {
  EVIDENCE_CLAIM,
  type ExtractionBrowseView,
  type PathRefused,
  type ReadView,
  describeExtraction,
  listDirectory,
  readFileSlice,
} from '../providers/fsbrowse.js';
import { searchExtraction } from '../providers/fssearch.js';
import { getImage, listJobs } from '../store.js';

/** Status codes per refusal rule — "not there" and "not allowed" are different answers. */
const NOT_FOUND_RULES = new Set<PathRefused['rule']>(['not-found']);

/**
 * The extraction root for an image, plus the verdict any listing must be read next to.
 *
 * Reads the most recent extract job whatever its status: a failed or still-running extraction is a state the
 * browser must be able to report, and only looking at `status = 'done'` would render all three as "never run".
 */
function extractionOf(imageId: string): { root: string | null; view: ExtractionBrowseView } {
  const job = listJobs(imageId).find((j) => j.kind === 'extract');
  if (!job) return { root: null, view: describeExtraction({ jobStatus: null }) };

  let result: ExtractResult | null = null;
  if (job.resultJson) {
    try {
      result = JSON.parse(job.resultJson) as ExtractResult;
    } catch {
      result = null;
    }
  }
  const status = job.status as 'queued' | 'running' | 'done' | 'error';
  const view = describeExtraction({
    jobStatus: status,
    jobError: job.error,
    outputDir: result?.outputDir ?? null,
    rootfsPath: result?.rootfsPath ?? null,
    extractor: result?.extractor,
    noRootfsVerdict: result?.noRootfsDiagnosis?.verdict,
  });
  return { root: view.browsable ? (result?.outputDir ?? null) : null, view };
}

export async function filesRoutes(app: FastifyInstance): Promise<void> {
  /** List one directory of the extraction. `path` is root-relative; omitted means the extraction root. */
  app.get('/images/:id/files', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });

    const { root, view } = extractionOf(id);
    const { path: requested } = req.query as { path?: string };
    if (!root) return { extraction: view, listing: null, claim: EVIDENCE_CLAIM };

    const listing = listDirectory(root, requested ?? '');
    if ('rule' in listing) {
      const status = NOT_FOUND_RULES.has(listing.rule) ? 404 : 400;
      return reply.status(status).send({ error: listing.reason, rule: listing.rule, extraction: view });
    }
    return { extraction: view, listing, claim: EVIDENCE_CLAIM };
  });

  /**
   * Which file says this — the other direction from the browser, and the one an analyst reaches for when a
   * provider's evidence names a string and the question is where else it appears.
   *
   * The answer leads with its coverage, not its hits: every skipped file is a hole, and a short list that does
   * not say what it skipped reads as a complete one.
   */
  app.get('/images/:id/files/search', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });

    const { root, view } = extractionOf(id);
    const { q, regex, deep } = req.query as { q?: string; regex?: string; deep?: string };
    if (!root) return { extraction: view, result: null, claim: EVIDENCE_CLAIM };
    if (!q) return reply.status(400).send({ error: 'Provide a search term as ?q=', extraction: view });

    const result = searchExtraction(root, q, {
      regex: regex === '1' || regex === 'true',
      deep: deep === '1' || deep === 'true',
    });
    if ('error' in result) return reply.status(400).send({ error: result.error, extraction: view });
    return { extraction: view, result, claim: EVIDENCE_CLAIM };
  });

  /**
   * Read a bounded slice of one file. `view=text|hex` is a preference — bytes the classifier calls binary are
   * hexdumped regardless, and the response says which rule chose.
   */
  app.get('/images/:id/files/read', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });

    const { root, view } = extractionOf(id);
    const q = req.query as { path?: string; offset?: string; limit?: string; view?: string };
    if (!root) return { extraction: view, read: null, claim: EVIDENCE_CLAIM };
    if (!q.path) {
      return reply.status(400).send({ error: 'A `path` query parameter is required — name the file to read.' });
    }

    const preferred: ReadView | undefined = q.view === 'hex' ? 'hex' : q.view === 'text' ? 'text' : undefined;
    const read = readFileSlice(root, q.path, q.offset, q.limit, preferred);
    if ('rule' in read) {
      const status = NOT_FOUND_RULES.has(read.rule) ? 404 : 400;
      return reply.status(status).send({
        error: read.reason,
        rule: read.rule,
        ...(read.symlinkTarget ? { symlinkTarget: read.symlinkTarget } : {}),
        extraction: view,
      });
    }
    return { extraction: view, read, claim: EVIDENCE_CLAIM };
  });
}
