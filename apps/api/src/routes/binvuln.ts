/**
 * The binary-hardening sweep, given a route — because until now it did not have one.
 *
 * `providers/binvuln.ts` is the corpus's **second-largest source of findings** (337 rows against `sbom`'s 474) and
 * it was reachable from exactly one place: `binvulnRun` inside the autonomous scan. There was no POST, no GET, no
 * client method and no panel, so an operator who wanted the sweep had to run `opacidad` over the whole image, and
 * the sweep's own result — how many binaries it walked, how many candidates it found, and what its cap dropped —
 * reached no reader at all. The rows landed in the findings ledger with no way back to the run that produced them.
 *
 * **The result is mostly its own denominator, which is why the GET matters.** `binariesScanned` against
 * `candidates` against `findings.length` are three different numbers, and the gaps between them are the answer to
 * "is this list everything?": `FINDING_CAP` truncates on merit, `relocatableSkipped` counts `.ko`/`.o` objects the
 * question does not apply to, `neuteredSkipped` counts entries the extractor cut to `/dev/null`, and
 * `exposedDropped` NAMES the exposed binaries that still did not fit. A findings list without those is a bound
 * presented as an answer.
 *
 * The same source string both ways (`binvuln`), so a run from here and a run from W9 are idempotent with respect
 * to each other rather than duplicating rows — `syncFindings` deletes and re-inserts only that source.
 *
 * `runBinVuln` is synchronous and walks up to 12000 paths, so it still goes through `startJob`: the walk is slow
 * enough on a real rootfs that doing it in the request would hold the connection open for the duration.
 */
import type { FastifyInstance } from 'fastify';
import { syncFindings } from '../findings.js';
import { runBinVuln } from '../providers/binvuln.js';
import { startJob } from '../providers/jobs.js';
import { type RootfsStage, gateOnRootfs, rootfsGateBody } from '../providers/rootfs-gate.js';
import { getImage, listJobs } from '../store.js';

const STAGE: RootfsStage = {
  stage: 'binvuln',
  needs: 'the binary-hardening sweep',
  note: 'No binary was examined, which is not the same as no binary being weak.',
};

export async function binvulnRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/binvuln', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const gate = gateOnRootfs(STAGE, listJobs(id));
    if (!gate.ok) return reply.status(gate.status).send(rootfsGateBody(gate));
    const rootfsPath = gate.rootfsPath;
    const jobId = startJob(id, 'binvuln', {}, async () => {
      const result = runBinVuln(rootfsPath);
      syncFindings(id, 'binvuln', result.findings);
      return result;
    });
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/binvuln', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const done = listJobs(id).find((j) => j.kind === 'binvuln' && j.status === 'done' && j.resultJson);
    return { result: done?.resultJson ? JSON.parse(done.resultJson) : null };
  });
}
