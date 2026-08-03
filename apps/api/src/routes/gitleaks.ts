/**
 * Deep secret-scan intake. POST runs gitleaks over the latest extracted rootfs as a job; GET returns the most
 * recent completed result. Like SBOM and emulation, this depends on a prior successful extraction for a rootfs.
 *
 * The precondition is checked by `providers/rootfs-gate.ts` — see that module for why a null rootfs is four
 * different answers and why only one of them is "run extraction first".
 */
import type { FastifyInstance } from 'fastify';
import { recordCredentials } from '../corpus.js';
import { classifyGitleaksHit } from '../findings-normalize.js';
import { normalizeGitleaks, syncFindings } from '../findings.js';
import { type GitleaksResult, runGitleaks } from '../providers/gitleaks.js';
import { startJob } from '../providers/jobs.js';
import { type RootfsStage, gateOnRootfs, rootfsGateBody } from '../providers/rootfs-gate.js';
import { getImage, listJobs } from '../store.js';

const STAGE: RootfsStage = { stage: 'gitleaks', needs: 'the deep secret scan' };

function latestGitleaks(imageId: string): GitleaksResult | null {
  const done = listJobs(imageId).find((j) => j.kind === 'gitleaks' && j.status === 'done' && j.resultJson);
  if (!done?.resultJson) return null;
  return JSON.parse(done.resultJson) as GitleaksResult;
}

export async function gitleaksRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/gitleaks', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const gate = gateOnRootfs(STAGE, listJobs(id));
    if (!gate.ok) return reply.status(gate.status).send(rootfsGateBody(gate));
    const rootfsPath = gate.rootfsPath;
    const jobId = startJob(id, 'gitleaks', {}, (handle) =>
      runGitleaks(rootfsPath, handle).then((r) => {
        syncFindings(id, 'gitleaks', normalizeGitleaks(r));
        if (r.available) {
          // The SAME classification the ledger row gets, rather than a second opinion hardcoded here. This wrote
          // `severity: 'high'` for every match, so the BE3600's seven upstream dnscrypt PUBLIC keys entered the
          // corpus-wide credential table as high-severity credentials — and that table is what the cross-image
          // layer reads to claim credential REUSE between two devices. An over-claim in a per-image row is
          // visible beside its own evidence; the same over-claim here travels to conclusions about other images.
          recordCredentials(
            id,
            r.findings.map((f) => ({ value: f.match, kind: f.rule, severity: classifyGitleaksHit(f).severity })),
          );
        }
        return r;
      }),
    );
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/gitleaks', async (req) => {
    const { id } = req.params as { id: string };
    return { result: latestGitleaks(id) };
  });
}
