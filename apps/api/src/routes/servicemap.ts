/**
 * servicemap routes — the static network-service-enumeration over an extracted rootfs. It maps the daemons the
 * firmware is configured to START (inittab, inetd, rc scripts, systemd units) — the boot-time attack surface —
 * WITHOUT booting anything. Needs a rootfs, so it refuses until there is one — through
 * `providers/rootfs-gate.ts`, which says WHICH of the four rootfs-less states this image is in instead of telling
 * an operator to re-run an extraction that already ran. Its findings (a service inventory plus one lead per
 * exposed autostart network daemon) are synced into the findings ledger.
 */
import type { FastifyInstance } from 'fastify';
import { syncFindings } from '../findings.js';
import { startJob } from '../providers/jobs.js';
import { type RootfsStage, gateOnRootfs, rootfsGateBody } from '../providers/rootfs-gate.js';
import { runServiceMap } from '../providers/servicemap.js';
import { getImage, listJobs } from '../store.js';

const STAGE: RootfsStage = { stage: 'services', needs: 'the service map' };

export async function servicemapRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/services', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const gate = gateOnRootfs(STAGE, listJobs(id));
    if (!gate.ok) return reply.status(gate.status).send(rootfsGateBody(gate));
    const rootfs = gate.rootfsPath;
    const jobId = startJob(id, 'services', {}, async () => {
      const result = runServiceMap(rootfs);
      syncFindings(id, 'services', result.findings);
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/services', async (req) => {
    const { id } = req.params as { id: string };
    const done = listJobs(id).find((j) => j.kind === 'services' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });
}
