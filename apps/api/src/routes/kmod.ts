/**
 * The kernel-module sweep, given a route.
 *
 * Same shape as `routes/binvuln.ts` and for the same reason: the provider must be reachable without running a
 * whole autonomous scan, and its RESULT — how many modules were read, which provenance key the image supports,
 * which modules the disassembly budget reached and which it named as dropped — has to reach a reader. A findings
 * list without those numbers is a bound presented as an answer.
 *
 * The same `source` string both ways (`kmod`), so a run from here and a run from W9 are idempotent with respect
 * to each other rather than duplicating rows.
 *
 * It goes through `startJob` because the third layer shells out to radare2 once per ranked module and would
 * otherwise hold the connection open for the duration.
 */
import type { FastifyInstance } from 'fastify';
import { syncFindings } from '../findings.js';
import { startJob } from '../providers/jobs.js';
import { runKmod } from '../providers/kmod.js';
import { type RootfsStage, gateOnRootfs, rootfsGateBody } from '../providers/rootfs-gate.js';
import { getImage, listJobs } from '../store.js';

const STAGE: RootfsStage = {
  stage: 'kmod',
  needs: 'the kernel-module sweep',
  note: 'No kernel module was read, which is not the same as the kernel carrying none.',
};

export async function kmodRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/kmod', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const gate = gateOnRootfs(STAGE, listJobs(id));
    if (!gate.ok) return reply.status(gate.status).send(rootfsGateBody(gate));
    const rootfsPath = gate.rootfsPath;
    const jobId = startJob(id, 'kmod', {}, async (handle) => {
      const result = await runKmod(rootfsPath);
      handle.log(result.reason);
      syncFindings(id, 'kmod', result.findings);
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/kmod', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const done = listJobs(id).find((j) => j.kind === 'kmod' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });
}
