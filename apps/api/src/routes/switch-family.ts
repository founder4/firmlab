/** On-demand static switch-family leads. A missing rootfs skips only that lane; no findings are synced. */
import type { FastifyInstance } from 'fastify';
import { startJob } from '../providers/jobs.js';
import { gateOnRootfs } from '../providers/rootfs-gate.js';
import { runSwitchFamilyAnalysis } from '../providers/switch-family.js';
import { getImage, listJobs } from '../store.js';

export async function switchFamilyRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/switch-family', async (req, reply) => {
    const { id } = req.params as { id: string };
    const image = getImage(id);
    if (!image) return reply.status(404).send({ error: 'Image not found' });
    const gate = gateOnRootfs({ stage: 'switch-family', needs: 'the extracted switch-family lane' }, listJobs(id));
    const jobId = startJob(id, 'switch-family', {}, async (handle) => {
      const result = await runSwitchFamilyAnalysis(
        image.path,
        gate.ok ? gate.rootfsPath : null,
        undefined,
        handle.signal,
      );
      if (!gate.ok) result.rootfs.reason += ` (${gate.state}). ${gate.error}`;
      handle.log(result.overall.summary);
      handle.log(result.raw.reason);
      handle.log(result.rootfs.reason);
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/switch-family', async (req) => {
    const { id } = req.params as { id: string };
    const done = listJobs(id).find((job) => job.kind === 'switch-family' && job.status === 'done' && job.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });
}
