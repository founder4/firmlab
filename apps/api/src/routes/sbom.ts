/**
 * SBOM + CVE intake. POST runs syft (+grype) over the latest extracted rootfs as a job; GET returns the most
 * recent completed SBOM result. Like emulation, this depends on a prior successful extraction for a rootfs.
 *
 * The precondition is checked by `providers/rootfs-gate.ts`, not by a local `rootfsPath === null` test: a null
 * rootfs covered "extraction never ran", "it is running", "it failed" and "it ran and this image has none", and
 * both Xiaomi eCos images were being told to run an extraction that had already run and already explained itself.
 */
import type { FastifyInstance } from 'fastify';
import { recordComponents } from '../corpus.js';
import { normalizeSbom, syncFindings } from '../findings.js';
import { startJob } from '../providers/jobs.js';
import { type RootfsStage, gateOnRootfs, rootfsGateBody } from '../providers/rootfs-gate.js';
import { type SbomResult, runSbom } from '../providers/sbom.js';
import { getImage, listJobs } from '../store.js';

const STAGE: RootfsStage = { stage: 'sbom', needs: 'SBOM scanning' };

function latestSbom(imageId: string): SbomResult | null {
  const done = listJobs(imageId).find((j) => j.kind === 'sbom' && j.status === 'done' && j.resultJson);
  if (!done?.resultJson) return null;
  return JSON.parse(done.resultJson) as SbomResult;
}

export async function sbomRoutes(app: FastifyInstance): Promise<void> {
  app.post('/images/:id/sbom', async (req, reply) => {
    const { id } = req.params as { id: string };
    if (!getImage(id)) return reply.status(404).send({ error: 'Image not found' });
    const gate = gateOnRootfs(STAGE, listJobs(id));
    if (!gate.ok) return reply.status(gate.status).send(rootfsGateBody(gate));
    const rootfsPath = gate.rootfsPath;
    const jobId = startJob(id, 'sbom', {}, (handle) =>
      runSbom(id, rootfsPath, handle).then((r) => {
        syncFindings(id, 'sbom', normalizeSbom(r));
        if (r.available) {
          // Cross-image component occurrences, each carrying how many CVEs grype matched to it.
          const cveCount = (name: string, version: string): number =>
            r.vulnerabilities.filter((v) => v.packageName === name && v.packageVersion === version).length;
          recordComponents(
            id,
            r.packages.map((p) => ({ name: p.name, version: p.version, cveCount: cveCount(p.name, p.version) })),
          );
        }
        return r;
      }),
    );
    return reply.status(202).send({ jobId });
  });

  app.get('/images/:id/sbom', async (req) => {
    const { id } = req.params as { id: string };
    return { result: latestSbom(id) };
  });
}
