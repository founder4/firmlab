/**
 * Standalone auxiliary-partition secret scan.
 *
 * The provider already runs inside opacidad, but credential-corpus maintenance must be able to refresh this one
 * source without re-running every expensive autonomous worker. It reads only the latest completed extraction and
 * records redaction-safe key fingerprints; key material never leaves the provider.
 */
import type { FastifyInstance } from 'fastify';
import { recordCredentialHashes } from '../corpus.js';
import { credentialHashesFromFindings, syncFindings } from '../findings.js';
import { runAuxSecrets } from '../providers/auxsecrets.js';
import type { ExtractResult } from '../providers/extract.js';
import { startJob } from '../providers/jobs.js';
import { getImage, listJobs } from '../store.js';

export function latestExtractionInputs(
  jobs: readonly { kind: string; status: string; resultJson?: string | null }[],
): { outputDir: string; rootfsPath: string | null } | null {
  for (const job of jobs) {
    if (job.kind !== 'extract' || job.status !== 'done' || !job.resultJson) continue;
    try {
      const result = JSON.parse(job.resultJson) as Partial<ExtractResult>;
      if (typeof result.outputDir === 'string' && result.outputDir.length > 0) {
        return {
          outputDir: result.outputDir,
          rootfsPath: typeof result.rootfsPath === 'string' ? result.rootfsPath : null,
        };
      }
    } catch {
      // A malformed historical row is not usable input. Keep looking for an older completed extraction.
    }
  }
  return null;
}

export async function auxsecretsRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/auxsecrets', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const extraction = latestExtractionInputs(listJobs(id));
    if (!extraction) {
      return reply.status(400).send({
        error:
          'Run extraction first — the auxiliary-partition scan needs a completed extraction output. Historical findings were preserved.',
      });
    }
    const jobId = startJob(id, 'auxsecrets', {}, async (handle) => {
      const result = runAuxSecrets(extraction.outputDir, extraction.rootfsPath);
      handle.log(result.reason);
      if (result.available) {
        syncFindings(id, 'auxsecrets', result.findings);
        recordCredentialHashes(id, credentialHashesFromFindings(result.findings));
      } else {
        handle.log('Input is no longer readable; historical auxsecrets findings were preserved.');
      }
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/auxsecrets', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const done = listJobs(id).find((job) => job.kind === 'auxsecrets' && job.status === 'done' && job.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });
}
