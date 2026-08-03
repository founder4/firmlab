/**
 * fsaudit routes — the extracted-rootfs static security audit (firmwalker / FACT-style). It reads the classic
 * misconfiguration surface an analyst checks by hand (empty/weak credentials, extra UID-0 accounts, init-spawned
 * shells/telnetd, permissive ssh/telnet/ftp service configs, notable key material) from an ALREADY-EXTRACTED
 * rootfs. Needs a rootfs, so it refuses until there is one — through `providers/rootfs-gate.ts`, which separates
 * "no extraction has run" from "extraction ran and this image has no rootfs" rather than telling the operator to
 * repeat a stage that already completed. Its findings are synced into the findings ledger.
 */
import type { FastifyInstance } from 'fastify';
import { syncFindings } from '../findings.js';
import { runFsAudit } from '../providers/fsaudit.js';
import { startJob } from '../providers/jobs.js';
import { type RootfsStage, gateOnRootfs, rootfsGateBody } from '../providers/rootfs-gate.js';
import { getImage, listJobs } from '../store.js';

const STAGE: RootfsStage = { stage: 'fsaudit', needs: 'the filesystem audit' };

export async function fsauditRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/fsaudit', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const gate = gateOnRootfs(STAGE, listJobs(id));
    if (!gate.ok) return reply.status(gate.status).send(rootfsGateBody(gate));
    const rootfs = gate.rootfsPath;
    const jobId = startJob(id, 'fsaudit', {}, async () => {
      const result = runFsAudit(rootfs);
      syncFindings(id, 'fsaudit', result.findings);
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/fsaudit', async (req) => {
    const { id } = req.params as { id: string };
    const done = listJobs(id).find((j) => j.kind === 'fsaudit' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });
}
