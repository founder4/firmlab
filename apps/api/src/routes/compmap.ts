/**
 * Component dependency-map routes. Assembles a link-dependency graph (binaries → DT_NEEDED shared libraries)
 * over the latest extracted rootfs, as a background job. radare2's rabin2 is an opt-in layer — with it absent
 * the job returns available:false honestly. The primary output is the graph; the one optional finding is an
 * INFO/static_confirmed inventory.
 *
 * The rootfs precondition goes through `providers/rootfs-gate.ts`: "no extraction has run" and "extraction ran and
 * this image has no rootfs" are different answers with different next moves, and the second must not be reported as
 * an instruction to repeat the first.
 */
import type { FastifyInstance } from 'fastify';
import { syncFindings } from '../findings.js';
import { runComponentMap } from '../providers/compmap.js';
import { startJob } from '../providers/jobs.js';
import { type RootfsStage, gateOnRootfs, rootfsGateBody } from '../providers/rootfs-gate.js';
import { getImage, listJobs } from '../store.js';

const STAGE: RootfsStage = { stage: 'compmap', needs: 'the component map' };

export async function compmapRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/compmap', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const gate = gateOnRootfs(STAGE, listJobs(id));
    if (!gate.ok) return reply.status(gate.status).send(rootfsGateBody(gate));
    const rootfs = gate.rootfsPath;
    const jobId = startJob(id, 'compmap', {}, async () => {
      const result = await runComponentMap(rootfs);
      syncFindings(id, 'compmap', result.findings);
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/compmap', async (req) => {
    const { id } = req.params as { id: string };
    const done = listJobs(id).find((j) => j.kind === 'compmap' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });
}
